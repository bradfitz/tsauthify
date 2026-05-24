package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"tailscale.com/tailcfg"
)

// tsauthifyCap is the Tailscale ACL "app" grant capability key the proxy reads
// from a caller's WhoIsResponse.CapMap to learn what backend username to use
// for them.
const tsauthifyCap tailcfg.PeerCapability = "github.com/bradfitz/tsauthify"

var userMapFile = flag.String("user-map", "", `optional path to a JSON file mapping Tailscale LoginName to backend username (with "*" as a catch-all key). If unset, identity is resolved from Tailscale ACL app grants instead.`)

// capGrant is the JSON shape of a single tsauthify grant entry in
// WhoIsResponse.CapMap[tsauthifyCap]. Operators put this in their
// Tailscale policy under "app" grants.
type capGrant struct {
	Username string `json:"username"`
}

// resolveBackendUsername returns the upstream backend username that the proxy
// should authenticate as on behalf of the Tailscale caller of r.
//
// If --user-map is set, it consults that file; otherwise it reads Tailscale
// ACL app grants from the caller's WhoIs response. Returns an error if the
// caller cannot be mapped — ServeHTTP turns that into a 403.
func (p *Proxy) resolveBackendUsername(r *http.Request) (string, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	who, err := p.localClient.WhoIs(ctx, r.RemoteAddr)
	if err != nil {
		return "", fmt.Errorf("WhoIs(%q): %v", r.RemoteAddr, err)
	}
	login := who.UserProfile.LoginName

	if *userMapFile != "" {
		m, err := loadUserMap(*userMapFile)
		if err != nil {
			return "", err
		}
		if login != "" {
			if u, ok := m[login]; ok {
				return u, nil
			}
		}
		if u, ok := m["*"]; ok {
			return u, nil
		}
		return "", fmt.Errorf("no user-map entry for %q and no \"*\" catch-all", login)
	}

	raw := who.CapMap[tsauthifyCap]
	switch len(raw) {
	case 0:
		return "", fmt.Errorf("no %q grant for %q", tsauthifyCap, login)
	case 1:
	default:
		return "", fmt.Errorf("multiple %q grants for %q; expected one", tsauthifyCap, login)
	}
	var g capGrant
	if err := json.Unmarshal([]byte(raw[0]), &g); err != nil {
		return "", fmt.Errorf("invalid %q grant: %v", tsauthifyCap, err)
	}
	if g.Username == "" {
		return "", errors.New("grant has empty username")
	}
	return g.Username, nil
}

func loadUserMap(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing user-map %q: %v", path, err)
	}
	return m, nil
}
