package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aydocs/fang/pkg/models"
)

type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
	Cookies []*models.Cookie
	Params  map[string]string
	Ctx     context.Context
}

func NewRequest(method, rawURL string) *Request {
	return &Request{
		Method:  method,
		URL:     rawURL,
		Headers: make(map[string]string),
		Params:  make(map[string]string),
		Ctx:     context.Background(),
	}
}

func (r *Request) WithHeader(key, value string) *Request {
	r.Headers[key] = value
	return r
}

func (r *Request) WithHeaders(h map[string]string) *Request {
	for k, v := range h {
		r.Headers[k] = v
	}
	return r
}

func (r *Request) WithBody(body string) *Request {
	r.Body = body
	return r
}

func (r *Request) WithCookie(c *models.Cookie) *Request {
	r.Cookies = append(r.Cookies, c)
	return r
}

func (r *Request) WithParam(key, value string) *Request {
	r.Params[key] = value
	return r
}

func (r *Request) WithContext(ctx context.Context) *Request {
	r.Ctx = ctx
	return r
}

func (r *Request) Build() (*http.Request, error) {
	u := r.URL
	if len(r.Params) > 0 {
		var parts []string
		for k, v := range r.Params {
			parts = append(parts, k+"="+v)
		}
		query := strings.Join(parts, "&")
		if strings.Contains(u, "?") {
			u += "&" + query
		} else {
			u += "?" + query
		}
	}

	var bodyReader io.Reader
	if r.Body != "" {
		bodyReader = strings.NewReader(r.Body)
	}

	req, err := http.NewRequestWithContext(r.Ctx, r.Method, u, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}

	for _, c := range r.Cookies {
		req.AddCookie(&http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Path:     c.Path,
			Domain:   c.Domain,
			Secure:   c.Secure,
			HttpOnly: c.HttpOnly,
		})
	}

	return req, nil
}
