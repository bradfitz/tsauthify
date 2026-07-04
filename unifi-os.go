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

// unifi-os backend handles UniFi OS Server (nginx/ucore front, e.g. the
// self-hosted "UniFi OS Server 5.x") rather than the classic UniFi
// Network controller. The two differ in three ways that matter here:
//
//   - login endpoint is POST /api/auth/login (not /api/login)
//   - session cookie is named TOKEN (not unifises)
//   - the classic remember/strict body fields are not accepted
//
// UniFi OS Server may also enforce CSRF via X-CSRF-Token for mutating
// requests. That's not handled here; the current use case is a
// read-mostly UI (Network dashboards). If a POST from the UI breaks
// with a CSRF error, extend modifyRequest to capture/echo the token.
func init() {
	addBackend("unifi-os", &backendImpl{
		getCookiesLocked: func(p *Proxy, ctx context.Context, r *http.Request) ([]*http.Cookie, error) {
			username, password, err := p.backendCreds(r)
			if err != nil {
				return nil, err
			}
			jbody, err := json.Marshal(map[string]any{
				"username": username,
				"password": password,
			})
			if err != nil {
				return nil, err
			}
			req, err := http.NewRequestWithContext(ctx, "POST", p.backend.String()+"/api/auth/login", bytes.NewReader(jbody))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "application/json")
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
		// modifyResponse watches for the backend deleting the TOKEN
		// session cookie (i.e. the user clicked Sign Out) and invalidates
		// our cached cookies so the next request triggers a fresh
		// /api/auth/login. Same pattern as the classic unifi backend.
		modifyResponse: func(p *Proxy, res *http.Response) error {
			for _, c := range res.Cookies() {
				if c.Name != "TOKEN" {
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
