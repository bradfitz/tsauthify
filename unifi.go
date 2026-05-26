package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

func init() {
	addBackend("unifi", &backendImpl{
		getCookiesLocked: func(p *Proxy, ctx context.Context, r *http.Request) ([]*http.Cookie, error) {
			username, password, err := p.backendCreds(r)
			if err != nil {
				return nil, err
			}
			jbody, err := json.Marshal(map[string]any{
				"username": username,
				"password": password,
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
		},
		// modifyResponse watches for the backend deleting the unifises
		// session cookie (i.e. the user clicked Sign Out) and invalidates
		// our cached cookies so the next request triggers a fresh /api/login.
		// Without this, after a logout we'd keep handing out stale cookies
		// until the 10-minute cache TTL expires.
		modifyResponse: func(p *Proxy, res *http.Response) error {
			for _, c := range res.Cookies() {
				if c.Name != "unifises" {
					continue
				}
				if c.MaxAge < 0 || (!c.Expires.IsZero() && c.Expires.Before(time.Now())) {
					p.mu.Lock()
					p.cookies = nil
					p.validUntil = time.Time{}
					p.mu.Unlock()
					break
				}
			}
			return nil
		},
	})
}
