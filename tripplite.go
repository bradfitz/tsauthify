package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func init() {
	addBackend("tripplite-webcardlxe", &backendImpl{
		modifyRequest: func(p *Proxy, r *http.Request) error {
			if r.Method != "POST" || r.URL.Path != "/api/oauth/token" || r.URL.Query().Get("grant_type") != "password" {
				return nil
			}
			pass, err := p.getPassword()
			if err != nil {
				return err
			}
			j, _ := json.Marshal(map[string]string{
				"username": "localadmin",
				"password": strings.TrimSpace(string(pass)),
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
			b, err := io.ReadAll(res.Body)
			if err != nil {
				return err
			}

			username := "localadmin" // TODO: be configurable
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

			res.Header.Set("Content-Length", fmt.Sprint(len(b)))
			res.Body = io.NopCloser(bytes.NewReader(b))
			return nil
		},
	})
}
