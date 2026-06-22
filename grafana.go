package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// The grafana backend type injects Grafana's auth.proxy headers
// (X-Webauth-User / -Name / -Role) on every request, mapping the
// Tailscale caller's identity to a Grafana org role.
//
// The user-map value is the Grafana role: "Admin", "Editor", or
// "Viewer". An empty value (e.g. catch-all `"*": ""`) causes the
// proxy to strip all X-Webauth-* headers; if Grafana has
// [auth.anonymous] enabled the caller falls through to that
// (typically Viewer), otherwise they get a login page.
//
// Modeled on tailscale.com/cmd/proxy-to-grafana, but role resolution
// goes through the standard tsauthify user-map / ACL grant
// mechanism instead of a proxy-to-grafana-specific capability.
//
// Required Grafana config (grafana.ini):
//
//	[auth.proxy]
//	enabled = true
//	header_name = X-Webauth-User
//	header_property = username
//	auto_sign_up = true
//	headers = Name:X-Webauth-Name Role:X-Webauth-Role
//	enable_login_token = true
func init() {
	addBackend("grafana", &backendImpl{
		modifyRequest: func(p *Proxy, r *http.Request) error {
			// Strip any X-Webauth-* the client may have sent; only
			// the proxy gets to set them.
			for h := range r.Header {
				if strings.EqualFold(h, "X-Webauth-User") ||
					strings.EqualFold(h, "X-Webauth-Name") ||
					strings.EqualFold(h, "X-Webauth-Role") {
					r.Header.Del(h)
				}
			}

			role, err := p.resolveBackendUsername(r)
			if err != nil {
				return err
			}
			if role == "" {
				// No role for this caller: leave the headers
				// stripped and let Grafana's [auth.anonymous]
				// handle them.
				return nil
			}
			switch role {
			case "Admin", "Editor", "Viewer":
			default:
				return fmt.Errorf("grafana: invalid role %q (want Admin, Editor, or Viewer)", role)
			}

			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			who, err := p.localClient.WhoIs(ctx, r.RemoteAddr)
			if err != nil {
				return fmt.Errorf("grafana: WhoIs(%q): %v", r.RemoteAddr, err)
			}
			login := who.UserProfile.LoginName
			if login == "" {
				return fmt.Errorf("grafana: caller %q has no LoginName", r.RemoteAddr)
			}
			name := who.UserProfile.DisplayName
			if name == "" {
				name = login
			}

			r.Header.Set("X-Webauth-User", login)
			r.Header.Set("X-Webauth-Name", name)
			r.Header.Set("X-Webauth-Role", role)
			return nil
		},
	})
}
