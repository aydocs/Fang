package http

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
)

type Middleware func(req *Request, next HandlerFunc) (*Response, error)

type HandlerFunc func(req *Request) (*Response, error)

type MiddlewareChain struct {
	middlewares []Middleware
}

func NewMiddlewareChain() *MiddlewareChain {
	return &MiddlewareChain{
		middlewares: make([]Middleware, 0),
	}
}

func (mc *MiddlewareChain) Use(m Middleware) {
	mc.middlewares = append(mc.middlewares, m)
}

func (mc *MiddlewareChain) Then(handler HandlerFunc) HandlerFunc {
	for i := len(mc.middlewares) - 1; i >= 0; i-- {
		mw := mc.middlewares[i]
		next := handler
		handler = func(mw Middleware, next HandlerFunc) HandlerFunc {
			return func(req *Request) (*Response, error) {
				return mw(req, next)
			}
		}(mw, next)
	}
	return handler
}

func RetryMiddleware(maxRetries int, delay time.Duration, metrics *Metrics) Middleware {
	return func(req *Request, next HandlerFunc) (*Response, error) {
		var resp *Response
		var err error
		for attempt := 0; attempt <= maxRetries; attempt++ {
			if attempt > 0 {
				if metrics != nil {
					metrics.AddRetry()
				}
				time.Sleep(delay * time.Duration(attempt))
			}
			resp, err = next(req)
			if err == nil {
				return resp, nil
			}
			if !isRetryableError(err) || attempt == maxRetries {
				return nil, err
			}
		}
		return resp, err
	}
}

func RateLimitMiddleware(rl *RateLimiter) Middleware {
	return func(req *Request, next HandlerFunc) (*Response, error) {
		if err := rl.Wait(context.Background()); err != nil {
			return nil, err
		}
		return next(req)
	}
}

func RedirectMiddleware(maxRedirects int) Middleware {
	return func(req *Request, next HandlerFunc) (*Response, error) {
		resp, err := next(req)
		if err != nil {
			return nil, err
		}
		redirects := 0
		for resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.Redirect != "" && redirects < maxRedirects {
			redirects++
			redirectURL := resp.Redirect
			if strings.HasPrefix(redirectURL, "/") {
				baseURL := req.URL
				if idx := strings.Index(baseURL, "://"); idx != -1 {
					if slashIdx := strings.Index(baseURL[idx+3:], "/"); slashIdx != -1 {
						baseURL = baseURL[:idx+3+slashIdx]
					}
				}
				redirectURL = baseURL + redirectURL
			}
			redirectReq := NewRequest(req.Method, redirectURL)
			redirectReq.Headers = req.Headers
			resp, err = next(redirectReq)
			if err != nil {
				return nil, err
			}
		}
		return resp, nil
	}
}

func LoggingMiddleware() Middleware {
	return func(req *Request, next HandlerFunc) (*Response, error) {
		start := time.Now()
		resp, err := next(req)
		duration := time.Since(start)
		if err != nil {
			log.Printf("[HTTP] %s %s - ERROR: %v (%v)", req.Method, req.URL, err, duration)
			return nil, err
		}
		log.Printf("[HTTP] %s %s - %d (%v)", req.Method, req.URL, resp.StatusCode, duration)
		return resp, nil
	}
}

func MetricsMiddleware(metrics *Metrics) Middleware {
	return func(req *Request, next HandlerFunc) (*Response, error) {
		metrics.AddRequest()
		start := time.Now()
		resp, err := next(req)
		duration := time.Since(start)
		if err != nil {
			metrics.AddFailure()
			return nil, err
		}
		metrics.AddSuccess()
		metrics.AddLatency(duration)
		metrics.AddBytesReceived(int64(len(resp.Body)))
		metrics.AddBytesSent(int64(len(req.Body)))
		return resp, nil
	}
}

func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	retryable := []string{
		"connection refused",
		"connection reset",
		"dial tcp",
		"no such host",
		"i/o timeout",
		"EOF",
		"use of closed network connection",
		"TLS handshake timeout",
		"connection timed out",
		"read: connection reset",
		"write: connection reset",
	}
	for _, e := range retryable {
		if strings.Contains(errStr, e) {
			return true
		}
	}
	return false
}

func IsConnectionError(err error) bool {
	return isRetryableError(err)
}

type contextKey string

func (c contextKey) String() string {
	return fmt.Sprintf("http/%s", string(c))
}

const (
	ContextKeyRequestID = contextKey("request_id")
)
