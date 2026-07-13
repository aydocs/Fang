package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/aydocs/fang/internal/auth"
	"github.com/aydocs/fang/pkg/models"
)

type Client struct {
	client      *http.Client
	config      *Config
	jar         *CookieJar
	metrics     *Metrics
	rateLimiter *RateLimiter
	pool        *Pool
	middleware  HandlerFunc
	chain       *MiddlewareChain
	session     *auth.Session
	mu          sync.Mutex
	closed      bool
}

func NewClient(opts ...Option) *Client {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	transport := NewTransport(cfg)

	httpClient := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
	}

	if !cfg.FollowRedirects {
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= cfg.MaxRedirects {
				return fmt.Errorf("too many redirects")
			}
			req.Header.Del("Referer")
			return nil
		}
	}

	jar := NewCookieJar()
	if cfg.Cookies != nil {
		jar.Set(cfg.Cookies)
	}

	metrics := NewMetrics()
	rl := NewRateLimiter(cfg.RateLimit)

	chain := NewMiddlewareChain()
	chain.Use(RetryMiddleware(cfg.MaxRetries, cfg.RetryDelay, metrics))
	chain.Use(RateLimitMiddleware(rl))
	chain.Use(MetricsMiddleware(metrics))

	pool := NewPool(cfg.MaxConcurrency)

	c := &Client{
		client:      httpClient,
		config:      cfg,
		jar:         jar,
		metrics:     metrics,
		rateLimiter: rl,
		pool:        pool,
		chain:       chain,
	}

	baseHandler := c.executeRequest
	c.middleware = chain.Then(baseHandler)

	return c
}

func (c *Client) Do(req *Request) (*Response, error) {
	if c.closed {
		return nil, fmt.Errorf("client is closed")
	}
	return c.middleware(req)
}

func (c *Client) Get(url string) (*Response, error) {
	return c.Do(NewRequest(http.MethodGet, url))
}

func (c *Client) Post(url, body string) (*Response, error) {
	req := NewRequest(http.MethodPost, url)
	req.Body = body
	if _, ok := req.Headers["Content-Type"]; !ok {
		req.Headers["Content-Type"] = "application/x-www-form-urlencoded"
	}
	return c.Do(req)
}

func (c *Client) Put(url, body string) (*Response, error) {
	req := NewRequest(http.MethodPut, url)
	req.Body = body
	return c.Do(req)
}

func (c *Client) Delete(url string) (*Response, error) {
	return c.Do(NewRequest(http.MethodDelete, url))
}

func (c *Client) Head(url string) (*Response, error) {
	return c.Do(NewRequest(http.MethodHead, url))
}

func (c *Client) Options(url string) (*Response, error) {
	return c.Do(NewRequest(http.MethodOptions, url))
}

func (c *Client) DoRaw(method, targetURL string, headers map[string]string, body string) (*Response, error) {
	req := NewRequest(method, targetURL)
	for k, v := range headers {
		req.Headers[k] = v
	}
	req.Body = body
	return c.Do(req)
}

func (c *Client) executeRequest(req *Request) (*Response, error) {
	httpReq, err := req.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	httpReq.Header.Set("User-Agent", c.config.UserAgent)
	for k, v := range c.config.Headers {
		httpReq.Header.Set(k, v)
	}

	if c.jar != nil {
		for _, cookie := range c.jar.Cookies(httpReq) {
			httpReq.AddCookie(cookie)
		}
	}

	if c.session != nil {
		c.session.ApplyToRequest(httpReq)
	}

	start := time.Now()
	httpResp, err := c.client.Do(httpReq)
	duration := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer httpResp.Body.Close()

	bodyBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	bodyStr := string(bodyBytes)

	if c.jar != nil {
		c.jar.SetCookies(httpReq, httpResp.Cookies())
	}

	if c.session != nil {
		c.session.FromResponse(httpResp)
	}

	redirect := ""
	if httpResp.StatusCode >= 300 && httpResp.StatusCode < 400 {
		redirect = httpResp.Header.Get("Location")
	}

	respURL := ""
	if httpResp.Request != nil && httpResp.Request.URL != nil {
		respURL = httpResp.Request.URL.String()
	}

	response := &Response{
		StatusCode: httpResp.StatusCode,
		Status:     httpResp.Status,
		Headers:    httpResp.Header,
		Body:       bodyStr,
		BodyBytes:  bodyBytes,
		BodyLength: len(bodyBytes),
		URL:        respURL,
		Redirect:   redirect,
		Duration:   duration,
		Request: &RequestInfo{
			Method:  req.Method,
			URL:     req.URL,
			Headers: httpReq.Header,
			Body:    req.Body,
		},
	}

	response.Cookies = parseCookies(httpResp.Cookies())

	if httpResp.TLS != nil {
		response.TLS = extractTLSInfo(httpResp.TLS)
	}

	return response, nil
}

func (c *Client) Batch(ctx context.Context, requests []*Request) []*Response {
	c.mu.Lock()
	pool := c.pool
	c.mu.Unlock()

	if pool == nil {
		pool = NewPool(c.config.MaxConcurrency)
	}

	handler := func(req *Request) (*Response, error) {
		return c.Do(req)
	}

	pool.Start(handler)

	type pending struct {
		index int
		ch    chan *jobResult
	}

	pendingJobs := make([]*pending, len(requests))
	for i, req := range requests {
		ch := make(chan *jobResult, 1)
		pendingJobs[i] = &pending{index: i, ch: ch}
		select {
		case pool.jobs <- &job{request: req, resultCh: ch}:
		case <-ctx.Done():
			responses := make([]*Response, len(requests))
			return responses
		}
	}

	responses := make([]*Response, len(requests))
	for _, pj := range pendingJobs {
		select {
		case result := <-pj.ch:
			if result.err == nil {
				responses[pj.index] = result.response
			}
		case <-ctx.Done():
			return responses
		}
	}
	return responses
}

func (c *Client) Metrics() *Metrics {
	return c.metrics
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	c.rateLimiter.Stop()
	c.client.CloseIdleConnections()
}

func (c *Client) Config() *Config {
	return c.config
}

func (c *Client) CookieJar() *CookieJar {
	return c.jar
}

func (c *Client) SetSession(s *auth.Session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.session = s
}

func (c *Client) Session() *auth.Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session
}

func parseCookies(cookies []*http.Cookie) []*models.Cookie {
	result := make([]*models.Cookie, 0, len(cookies))
	for _, c := range cookies {
		jc := &models.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HttpOnly: c.HttpOnly,
		}
		switch c.SameSite {
		case http.SameSiteLaxMode:
			jc.SameSite = "Lax"
		case http.SameSiteStrictMode:
			jc.SameSite = "Strict"
		case http.SameSiteNoneMode:
			jc.SameSite = "None"
		default:
			jc.SameSite = "Default"
		}
		result = append(result, jc)
	}
	return result
}

func extractTLSInfo(tlsState *tls.ConnectionState) *TLSInfo {
	if tlsState == nil {
		return nil
	}

	info := &TLSInfo{
		Version: tlsVersionString(tlsState.Version),
		Cipher:  tls.CipherSuiteName(tlsState.CipherSuite),
	}

	if len(tlsState.PeerCertificates) > 0 {
		cert := tlsState.PeerCertificates[0]
		info.Certificate = &CertificateInfo{
			Subject:   cert.Subject.CommonName,
			Issuer:    cert.Issuer.CommonName,
			NotBefore: cert.NotBefore,
			NotAfter:  cert.NotAfter,
			DNSNames:  cert.DNSNames,
		}
		if len(cert.DNSNames) == 0 {
			info.Certificate.SelfSigned = cert.Subject.CommonName == cert.Issuer.CommonName
		} else {
			info.Certificate.SelfSigned = cert.Subject.CommonName == cert.Issuer.CommonName
		}
	}

	return info
}
