// The tsauthify command is an HTTP reverse proxy that maps Tailscale
// authentication to backend-specific HTTP username & password
// cookie-based authentication. Its goal is to enable Tailscale-based
// auth without usernames and passwords to everything running in
// Brad's homelab. And other people's.
//
// As of 2023-12-16 it is a work in progress.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/tsnet"
)

func main() {
	var typs []string
	for typ := range backendTypes {
		typs = append(typs, string(typ))
	}
	sort.Strings(typs)
	var (
		flagType      = flag.String("type", "", "backend type. One of: "+strings.Join(typs, ", "))
		flagBackend   = flag.String("backend", "", "backend URL root")
		flagName      = flag.String("name", "", "tsnet hostname and state-directory suffix. Defaults to --type. State is stored in $XDG_CONFIG_HOME/tsauthify-<name>.")
		flagPasswords = flag.String("passwords-dir", "", "directory containing per-user backend password files (one file per username, file contents = password). If unset, defaults to $HOME/keys/tsauthify/<type>/.")
	)
	flag.Parse()

	if _, ok := backendTypes[backendType(*flagType)]; !ok {
		if *flagType == "" {
			log.Fatal("--type is required")
		}
		log.Fatalf("unknown --type %q", *flagType)
	}
	if *flagBackend == "" {
		log.Fatal("--backend is required")
	}
	base, err := url.Parse(*flagBackend)
	if err != nil {
		log.Fatalf("invalid --backend value %q: %v", *flagBackend, err)
	}
	if base.Path == "/" {
		base.Path = ""
	}

	name := *flagName
	if name == "" {
		name = *flagType
	}

	log.Printf("Starting tsauthify...")
	os.Setenv("TAILSCALE_USE_WIP_CODE", "1")
	ctx := context.Background()

	confDir, err := os.UserConfigDir()
	if err != nil {
		log.Fatalf("UserConfigDir: %v", err)
	}
	ts := &tsnet.Server{
		Hostname: name,
		Dir:      filepath.Join(confDir, "tsauthify-"+name),
	}
	_, err = ts.Up(ctx)
	if err != nil {
		log.Fatal(err)
	}
	lc, err := ts.LocalClient()
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
	impl := backendTypes[backendType(*flagType)]
	var p *Proxy // closed over by ModifyResponse but p is set later
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = base.Scheme
			pr.Out.URL.Host = base.Host

			// SuperMicro's BMC treats "Websocket" and "WebSocket"
			// case sensitively, in violation of the HTTP specs.
			// Adjust to pacify it.
			outh := pr.Out.Header
			for h, vv := range outh {
				h2 := strings.ReplaceAll(h, "Websocket", "WebSocket")
				if h2 != h {
					outh[h2] = vv
					delete(outh, h)
				}
			}
		},
		ModifyResponse: func(res *http.Response) error {
			if impl.modifyResponse == nil {
				return nil
			}
			return impl.modifyResponse(p, res)
		},
		Transport: &http.Transport{
			TLSClientConfig:       tlsConfig,
			DialContext:           dialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	p = &Proxy{
		backend:      base,
		impl:         impl,
		rp:           rp,
		localClient:  lc,
		passwordsDir: *flagPasswords,
	}

	log.Fatal(http.Serve(ln, p))
}

type backendType string

var backendTypes = map[backendType]*backendImpl{}

type backendImpl struct {
	Type backendType // optional; populated by addBackend

	// getCookiesLocked optionally specifies a func to get auth cookies
	// to send to the backend. It receives the inbound request so it can
	// resolve the caller's identity via Proxy.backendCreds. The cookies it
	// returns are shared across all callers, so this only fits backends
	// where all Tailscale users share a single backend account.
	getCookiesLocked func(*Proxy, context.Context, *http.Request) ([]*http.Cookie, error)

	modifyResponse func(*Proxy, *http.Response) error // optional
	modifyRequest  func(*Proxy, *http.Request) error  // optional
}

func addBackend(typ backendType, impl *backendImpl) {
	if _, dup := backendTypes[typ]; dup {
		panic("duplicate backend type: " + typ)
	}
	if typ == "" {
		panic("empty type")
	}
	if impl.Type != "" && impl.Type != typ {
		panic("inconsistent backend type")
	}
	impl.Type = typ
	backendTypes[typ] = impl
}

type Proxy struct {
	impl         *backendImpl
	backend      *url.URL
	rp           *httputil.ReverseProxy
	localClient  *local.Client
	passwordsDir string // if non-empty, where to read passwords; see --passwords-dir

	mu         sync.Mutex
	cookies    []*http.Cookie
	validUntil time.Time
}

// passwordFor returns the password stored on disk for the given backend user.
// Passwords live at <passwordsDir>/<username>, where passwordsDir defaults
// to $HOME/keys/tsauthify/<type>/ when --passwords-dir is unset.
func (p *Proxy) passwordFor(username string) (string, error) {
	if username == "" {
		return "", errors.New("empty backend username")
	}
	dir := p.passwordsDir
	if dir == "" {
		dir = filepath.Join(os.Getenv("HOME"), "keys", "tsauthify", string(p.impl.Type))
	}
	v, err := os.ReadFile(filepath.Join(dir, username))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(v)), nil
}

// backendCreds returns the (username, password) that the proxy should present
// to the upstream backend on behalf of the caller of r.
func (p *Proxy) backendCreds(r *http.Request) (username, password string, err error) {
	username, err = p.resolveBackendUsername(r)
	if err != nil {
		return "", "", err
	}
	password, err = p.passwordFor(username)
	if err != nil {
		return "", "", err
	}
	return username, password, nil
}

func (p *Proxy) getCookies(r *http.Request) (_ []*http.Cookie, refreshed bool, _ error) {
	f := p.impl.getCookiesLocked
	if f == nil {
		return nil, false, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	if now.Before(p.validUntil) {
		return p.cookies, false, nil
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	cookies, err := f(p, ctx, r)
	if err != nil {
		return nil, false, err
	}
	p.cookies = cookies
	p.validUntil = now.Add(10 * time.Minute)
	return cookies, true, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%v %v ... ", r.Method, r.URL.Path)
	cookies, cookiesRefreshed, err := p.getCookies(r)
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

	if f := p.impl.modifyRequest; f != nil {
		if err := f(p, r); err != nil {
			log.Printf("Error altering request: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	p.rp.ServeHTTP(w, r)
}
