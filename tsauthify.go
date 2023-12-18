// The tsauthify command is an HTTP reverse proxy that maps Tailscale
// authentication cookies to backend-specific HTTP username & password
// cookie-based authentication.
//
// As of 2023-12-16 it is a work in progress.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"tailscale.com/tsnet"
)

var (
	flagType    = flag.String("type", "", "backend type. One of: unifi, tripplite-webcardlxe, supermicro-bmc")
	flagBackend = flag.String("backend", "", "backend URL root")
)

func main() {
	flag.Parse()

	switch *flagType {
	case "":
		log.Fatal("--type is required")
	default:
		log.Fatalf("unknown --type %q", *flagType)
	case "unifi", "tripplite-webcardlxe", "supermicro-bmc":
		// good.
	}
	if *flagBackend == "" {
		log.Fatal("--backend is required")
	}
	base, err := url.Parse(*flagBackend)
	if err != nil {
		log.Fatalf("invalid --backend value %q: %v", *flagBackend, err)
	}
	if base.Path != "" && base.Path != "/" {
		base.Path = ""
	}

	log.Printf("Starting tsauthify...")
	os.Setenv("TAILSCALE_USE_WIP_CODE", "1")
	ctx := context.Background()

	ts := &tsnet.Server{
		Hostname: "authify",
	}
	_, err = ts.Up(ctx)
	if err != nil {
		log.Fatal(err)
	}
	_, err = ts.LocalClient()
	if err != nil {
		log.Fatalf("getting local client: %v", err)
	}
	ln, err := ts.ListenTLS("tcp", ":443")
	if err != nil {
		log.Fatal(err)
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	dialContext := dialer.DialContext
	rp := httputil.NewSingleHostReverseProxy(base)
	rp.Transport = &http.Transport{
		TLSClientConfig:       tlsConfig,
		DialContext:           dialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	p := &Proxy{
		backend:     base,
		backendType: backendType(*flagType),
		rp:          rp,
	}

	log.Fatal(http.Serve(ln, p))
}

type backendType string

const (
	backendTypeUnifi         backendType = "unifi"
	backendTypeTrippLite     backendType = "tripplite-webcardlxe"
	backendTypeSupermicroBMC backendType = "supermicro-bmc"
)

type Proxy struct {
	backendType backendType
	backend     *url.URL
	rp          *httputil.ReverseProxy

	mu         sync.Mutex
	cookies    []*http.Cookie
	validUntil time.Time
}

func (p *Proxy) noCookies() bool {
	switch p.backendType {
	default:
		return false
	case backendTypeTrippLite:
		return true
	}
}

func (p *Proxy) getCookies() (_ []*http.Cookie, refreshed bool, _ error) {
	if p.noCookies() {
		return nil, false, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	if now.Before(p.validUntil) {
		return p.cookies, false, nil
	}

	cookies, err := p.renewCookiesLocked()
	if err != nil {
		return nil, false, err
	}
	p.cookies = cookies
	p.validUntil = now.Add(10 * time.Minute)
	return cookies, true, nil
}

func (p *Proxy) renewCookiesLocked() ([]*http.Cookie, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch p.backendType {
	default:
		return nil, fmt.Errorf("unknown backend type: %v", p.backendType)
	case backendTypeUnifi:
		jbody, err := json.Marshal(map[string]any{
			"username": "readonly",
			"password": "readonly123", // TODO: get from file or setec
			"remember": false,
			"strict":   true,
		})
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, "POST", p.backend.String()+"/api/login", bytes.NewReader(jbody))
		if err != nil {
			return nil, err
		}
		res, err := p.rp.Transport.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			res.Write(os.Stderr)
			return nil, fmt.Errorf("non-200 getting cookies: %v", res.Status)
		}
		cookies := res.Cookies()
		if len(cookies) == 0 {
			return nil, fmt.Errorf("no cookies found")
		}
		return cookies, nil
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cookies, cookiesRefreshed, err := p.getCookies()
	if err != nil {
		log.Printf("Error getting cookies: %v", err)
		http.Error(w, "Error getting cookies", http.StatusInternalServerError)
		return
	}

	if cookiesRefreshed {
		for _, c := range cookies {
			http.SetCookie(w, c)
		}
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}

	var rec *httptest.ResponseRecorder
	origW := w

	if p.backendType == backendTypeTrippLite {
		if r.Method == "POST" && r.URL.Path == "/api/oauth/token" && r.URL.Query().Get("grant_type") == "password" {
			pass, err := os.ReadFile(filepath.Join(os.Getenv("HOME"), "keys", "tsauthify", "tripplite-webcardlxe"))
			if err != nil {
				log.Printf("Error reading tripplite-webcardlxe key: %v", err)
				http.Error(w, "Error reading key", http.StatusInternalServerError)
				return
			}
			j, _ := json.Marshal(map[string]string{
				"username": "localadmin",
				"password": strings.TrimSpace(string(pass)),
			})
			r.ContentLength = int64(len(j))
			r.Body = io.NopCloser(bytes.NewReader(j))
		}

		if r.Method == "GET" && r.URL.Path == "/" {
			rec = httptest.NewRecorder()
			w = rec
		}
	}

	p.rp.ServeHTTP(w, r)

	if p.backendType == backendTypeTrippLite && r.Method == "GET" && r.URL.Path == "/" {
		username := "localadmin" // TODO: be configurable
		b := rec.Body.Bytes()
		b = bytes.ReplaceAll(b, []byte(`</html>`), []byte(`<script defer>
	window.onload = function() {
			console.log("tsauthify loaded; auto-filling form...");
		document.getElementsByTagName("input")[0].value = "`+username+`";
		document.getElementsByTagName("input")[0].dispatchEvent(new KeyboardEvent('compositionend'), {});
		document.getElementsByTagName("input")[1].value = "dummy-password";
		document.getElementsByTagName("input")[1].dispatchEvent(new KeyboardEvent('compositionend'), {});
		window.setTimeout(function() {
			console.log("tsauthify: clicking button");
			document.getElementsByTagName("button")[1].click()
			console.log("tsauthify: clicked");
		}, 200);
	};
</script></html>`))
		w = origW
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write(b)
	}
}
