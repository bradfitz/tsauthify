package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
)

func init() {
	addBackend("supermicro-bmc", &backendImpl{
		modifyRequest: func(p *Proxy, r *http.Request) error {
			if r.Method != "POST" || r.URL.Path != "/cgi/login.cgi" {
				return nil
			}
			username, password, err := p.backendCreds(r)
			if err != nil {
				return err
			}
			uv := (url.Values{
				"name": []string{username},
				"pwd":  []string{password},
			}).Encode()
			r.ContentLength = int64(len(uv))
			r.Body = io.NopCloser(strings.NewReader(uv))
			return nil
		},
	})
}
