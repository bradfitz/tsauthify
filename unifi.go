package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

func init() {
	addBackend("unifi", &backendImpl{
		getCookiesLocked: func(p *Proxy, ctx context.Context) ([]*http.Cookie, error) {
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
		},
	})
}
