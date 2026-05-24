package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func init() {
	addBackend("tripplite-webcardlxe", &backendImpl{
		modifyRequest: func(p *Proxy, r *http.Request) error {
			if r.Method == "GET" && r.URL.Path == "/" {
				// Force a fresh body so our injected script can't be skipped
				// by a 304 against an older cached version.
				r.Header.Del("If-None-Match")
				r.Header.Del("If-Modified-Since")
				return nil
			}
			if r.Method != "POST" || r.URL.Path != "/api/oauth/token" || r.URL.Query().Get("grant_type") != "password" {
				return nil
			}
			username, password, err := p.backendCreds(r)
			if err != nil {
				return err
			}
			j, _ := json.Marshal(map[string]string{
				"username": username,
				"password": password,
			})
			r.ContentLength = int64(len(j))
			r.Body = io.NopCloser(bytes.NewReader(j))
			return nil
		},

		modifyResponse: func(p *Proxy, res *http.Response) error {
			req := res.Request
			if req.Method != "GET" || req.URL.Path != "/" || res.StatusCode != 200 {
				return nil
			}
			// The SPA reads the username back out of the form to fetch
			// per-user preferences, so we must inject the real username
			// here rather than a placeholder.
			username, err := p.resolveBackendUsername(req)
			if err != nil {
				return err
			}
			userJSON, err := json.Marshal(username)
			if err != nil {
				return err
			}
			b, err := io.ReadAll(res.Body)
			if err != nil {
				return err
			}

			// The injected script auto-submits the login form with the real
			// username and a placeholder password; modifyRequest above swaps
			// in the real password when the form's POST flies by.
			b = bytes.ReplaceAll(b, []byte(`</html>`), []byte(`<script defer>
		window.onload = function() {
				console.log("tsauthify loaded; auto-filling form...");
			document.getElementsByTagName("input")[0].value = `+string(userJSON)+`;
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

			res.Header.Set("Content-Length", fmt.Sprint(len(b)))
			res.Header.Set("Cache-Control", "no-store")
			res.Header.Del("ETag")
			res.Header.Del("Last-Modified")
			res.Body = io.NopCloser(bytes.NewReader(b))
			return nil
		},
	})
}
