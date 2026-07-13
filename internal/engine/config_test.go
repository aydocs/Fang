package engine

import (
	"testing"
	"time"
)

func TestConfigDefaults(t *testing.T) {
	cfg := NewConfig()
	if cfg.Threads != 20 {
		t.Errorf("default threads = %d, want 20", cfg.Threads)
	}
	if cfg.Timeout != 10*time.Second {
		t.Errorf("default timeout = %v, want 10s", cfg.Timeout)
	}
	if cfg.RateLimit != 50 {
		t.Errorf("default rate limit = %d, want 50", cfg.RateLimit)
	}
}

func TestConfigWithOptions(t *testing.T) {
	cfg := NewConfig(
		WithThreads(10),
		WithTimeout(30),
		WithRateLimit(100),
	)
	if cfg.Threads != 10 {
		t.Errorf("threads = %d, want 10", cfg.Threads)
	}
}

func TestConfigWithProxy(t *testing.T) {
	cfg := NewConfig(WithProxy("http://127.0.0.1:8080"))
	if cfg.Proxy != "http://127.0.0.1:8080" {
		t.Errorf("proxy = %q, want http://127.0.0.1:8080", cfg.Proxy)
	}
}

func TestConfigWithHeaders(t *testing.T) {
	headers := map[string]string{"X-Custom": "test"}
	cfg := NewConfig(WithHeaders(headers))
	if cfg.Headers["X-Custom"] != "test" {
		t.Errorf("header = %q, want test", cfg.Headers["X-Custom"])
	}
}
