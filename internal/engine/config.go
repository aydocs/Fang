package engine

import (
	"time"

	"github.com/aydocs/fang/pkg/models"
)

type Config struct {
	Threads        int
	Timeout        time.Duration
	RateLimit      int
	Proxy          string
	Cookies        []*models.Cookie
	Headers        map[string]string
	TemplatesDir   string
	WordlistsDir   string
	OutputDir      string
	OutputFormats  []string
	Tags           []string
	ExcludeTags    []string
	Modules        []string
	ExcludeModules []string
	Quiet          bool
	Verbose        bool
	Quick          bool
	DryRun         bool
}

type Option func(*Config)

func NewConfig(opts ...Option) *Config {
	cfg := &Config{
		Threads:   20,
		Timeout:   10 * time.Second,
		RateLimit: 50,
		Headers:   make(map[string]string),
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

func WithThreads(n int) Option {
	return func(c *Config) {
		if n > 0 {
			c.Threads = n
		}
	}
}

func WithTimeout(d time.Duration) Option {
	return func(c *Config) {
		if d > 0 {
			c.Timeout = d
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

func WithCookies(cookies []*models.Cookie) Option {
	return func(c *Config) {
		c.Cookies = cookies
	}
}

func WithHeaders(h map[string]string) Option {
	return func(c *Config) {
		c.Headers = h
	}
}

func WithModules(modules ...string) Option {
	return func(c *Config) {
		c.Modules = modules
	}
}

func WithExcludeModules(modules ...string) Option {
	return func(c *Config) {
		c.ExcludeModules = modules
	}
}

func WithQuick(quick bool) Option {
	return func(c *Config) {
		c.Quick = quick
	}
}
