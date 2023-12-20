package main

import (
	"errors"
	"io"
	"log"
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
			pass, err := p.getPassword()
			if err != nil {
				log.Printf("Error reading username: %v", err)
				return errors.New("error reading key")
			}
			uv := (url.Values{
				"name": []string{"ADMIN"},
				"pwd":  []string{strings.TrimSpace(string(pass))},
			}).Encode()
			r.ContentLength = int64(len(uv))
			r.Body = io.NopCloser(strings.NewReader(uv))
			return nil
		},
	})
}
