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
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"time"

	"tailscale.com/tsnet"
)

func main() {
	log.Printf("Starting tsauthify...")
	os.Setenv("TAILSCALE_USE_WIP_CODE", "1")
	ctx := context.Background()

	ts := &tsnet.Server{
		Hostname: "authify",
	}
	_, err := ts.Up(ctx)
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

	base, err := url.Parse("https://10.0.0.10:8443")
	if err != nil {
		panic(err)
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
		backendType: backendTypeUnifi,
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

func (p *Proxy) getCookies() (_ []*http.Cookie, refreshed bool, _ error) {
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
	p.rp.ServeHTTP(w, r)
}
