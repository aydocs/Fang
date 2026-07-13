package http

import (
	"time"

	"github.com/aydocs/fang/pkg/models"
)

type Config struct {
	Timeout         time.Duration
	MaxRetries      int
	RetryDelay      time.Duration
	MaxConcurrency  int
	RateLimit       int
	Proxy           string
	ProxyAuth       string
	SOCKS5          string
	FollowRedirects bool
	MaxRedirects    int
	MaxIdleConns    int
	IdleConnTimeout time.Duration
	TLSInsecure     bool
	TLSCipherSuites []uint16
	UserAgent       string
	Headers         map[string]string
	Cookies         []*models.Cookie
}

type Option func(*Config)

func defaultConfig() *Config {
	return &Config{
		Timeout:         10 * time.Second,
		MaxRetries:      2,
		RetryDelay:      500 * time.Millisecond,
		MaxConcurrency:  20,
		RateLimit:       50,
		FollowRedirects: false,
		MaxRedirects:    5,
		MaxIdleConns:    100,
		IdleConnTimeout: 30 * time.Second,
		TLSInsecure:     false,
		UserAgent:       "Fang/1.0 (Security Scanner)",
		Headers:         make(map[string]string),
	}
}

func WithTimeout(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.Timeout = d
		}
	}
}

func WithRetries(n int) Option {
	return func(c *Config) {
		if n > 0 {
			c.MaxRetries = n
		}
	}
}

func WithRateLimit(n int) Option {
	return func(c *Config) {
		if n > 0 {
			c.RateLimit = n
		}
	}
}

func WithProxy(p string) Option {
	return func(c *Config) {
		c.Proxy = p
	}
}

func WithSOCKS5(p string) Option {
	return func(c *Config) {
		c.SOCKS5 = p
	}
}

func WithFollowRedirects(b bool) Option {
	return func(c *Config) {
		c.FollowRedirects = b
	}
}

func WithCipherSuites(cs ...uint16) Option {
	return func(c *Config) {
		if len(cs) > 0 {
			c.TLSCipherSuites = cs
		}
	}
}

func WithUserAgent(ua string) Option {
	return func(c *Config) {
		if ua != "" {
			c.UserAgent = ua
		}
	}
}

func WithMaxConcurrency(n int) Option {
	return func(c *Config) {
		if n > 0 {
			c.MaxConcurrency = n
		}
	}
}

func WithMaxIdleConns(n int) Option {
	return func(c *Config) {
		if n > 0 {
			c.MaxIdleConns = n
		}
	}
}

func WithTimeoutIdle(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.IdleConnTimeout = d
		}
	}
}

func WithHeaders(h map[string]string) Option {
	return func(c *Config) {
		for k, v := range h {
			c.Headers[k] = v
		}
	}
}

func WithCookies(cookies []*models.Cookie) Option {
	return func(c *Config) {
		c.Cookies = cookies
	}
}
