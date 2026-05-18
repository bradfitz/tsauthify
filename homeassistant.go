package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var haLoginFlowRE = regexp.MustCompile(`^/auth/login_flow/[a-f0-9]+$`)

// haInjectPath reports whether the given path is one we inject our auto-login
// script into. We hit both the app shell (which redirects to /auth/authorize
// when not logged in) and the authorize page itself.
func haInjectPath(p string) bool {
	return p == "/" || p == "/auth/authorize"
}

func init() {
	addBackend("homeassistant", &backendImpl{
		modifyRequest: func(p *Proxy, r *http.Request) error {
			if r.Method == "GET" && haInjectPath(r.URL.Path) {
				// Force uncompressed so we can inject our auto-login script.
				r.Header.Set("Accept-Encoding", "identity")
				return nil
			}
			if r.Method == "POST" && haLoginFlowRE.MatchString(r.URL.Path) {
				pass, err := p.getPassword()
				if err != nil {
					return err
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					return err
				}
				r.Body.Close()
				var m map[string]any
				if err := json.Unmarshal(body, &m); err != nil {
					return err
				}
				m["username"] = "bradfitz" // TODO: be configurable
				m["password"] = pass
				body, err = json.Marshal(m)
				if err != nil {
					return err
				}
				r.ContentLength = int64(len(body))
				r.Body = io.NopCloser(bytes.NewReader(body))
				return nil
			}
			return nil
		},
		modifyResponse: func(p *Proxy, res *http.Response) error {
			req := res.Request
			if req.Method != "GET" || !haInjectPath(req.URL.Path) || res.StatusCode != 200 {
				return nil
			}
			if !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
				return nil
			}
			body, err := readMaybeCompressed(res)
			if err != nil {
				return err
			}
			body = bytes.Replace(body, []byte("<head>"), []byte("<head>"+haAutoLoginScript), 1)
			res.Header.Del("Content-Encoding")
			res.Header.Set("Content-Length", fmt.Sprint(len(body)))
			res.ContentLength = int64(len(body))
			res.Body = io.NopCloser(bytes.NewReader(body))
			return nil
		},
	})
}

func readMaybeCompressed(res *http.Response) ([]byte, error) {
	var r io.Reader = res.Body
	switch res.Header.Get("Content-Encoding") {
	case "", "identity":
		// nothing
	case "gzip":
		gr, err := gzip.NewReader(res.Body)
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		r = gr
	case "deflate":
		// HTTP "deflate" is ambiguous; try zlib (header+adler32) first, fall back to raw flate.
		buf, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}
		if zr, err := zlib.NewReader(bytes.NewReader(buf)); err == nil {
			defer zr.Close()
			return io.ReadAll(zr)
		}
		fr := flate.NewReader(bytes.NewReader(buf))
		defer fr.Close()
		return io.ReadAll(fr)
	default:
		return nil, fmt.Errorf("unsupported Content-Encoding %q", res.Header.Get("Content-Encoding"))
	}
	return io.ReadAll(r)
}

// haAutoLoginScript runs early in the Home Assistant index page. If we don't
// already have tokens in localStorage, it performs the OAuth login flow against
// the proxy (which substitutes the real username/password server-side), stores
// the resulting tokens where the HA frontend expects them, and reloads.
const haAutoLoginScript = `<script>
(async function() {
  try {
    if (localStorage.hassTokens) return;
    const clientId = location.origin + "/";
    let r = await fetch("/auth/login_flow", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        client_id: clientId,
        handler: ["homeassistant", null],
        redirect_uri: location.origin + "/?auth_callback=1",
      }),
    });
    const flow = await r.json();
    r = await fetch("/auth/login_flow/" + flow.flow_id, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({username: "x", password: "x", client_id: clientId}),
    });
    const step = await r.json();
    if (step.type !== "create_entry") {
      console.error("tsauthify: login failed", step);
      return;
    }
    const form = new FormData();
    form.append("client_id", clientId);
    form.append("code", step.result);
    form.append("grant_type", "authorization_code");
    r = await fetch("/auth/token", {method: "POST", body: form});
    const tok = await r.json();
    localStorage.setItem("hassTokens", JSON.stringify({
      ...tok,
      hassUrl: location.origin,
      clientId: clientId,
      expires: Date.now() + tok.expires_in * 1000,
    }));
    location.replace("/");
  } catch (e) {
    console.error("tsauthify auto-login error:", e);
  }
})();
</script>`
