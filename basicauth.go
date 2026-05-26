package main

import "net/http"

// The basic-auth backend type injects HTTP Basic credentials into every
// outbound request. The user-map value is the backend username; the
// password is read from <passwords-dir>/<username> as with other types.
//
// If the resolved username is empty (e.g. user-map entry `"*": ""`), no
// Authorization header is set; the backend sees the request as
// anonymous. Useful for backends that have their own per-user access
// control (e.g. zot's accessControl with anonymousPolicy=["read"]).
func init() {
	addBackend("basic-auth", &backendImpl{
		modifyRequest: func(p *Proxy, r *http.Request) error {
			username, err := p.resolveBackendUsername(r)
			if err != nil {
				return err
			}
			if username == "" {
				r.Header.Del("Authorization")
				return nil
			}
			password, err := p.passwordFor(username)
			if err != nil {
				return err
			}
			r.SetBasicAuth(username, password)
			return nil
		},
	})
}
