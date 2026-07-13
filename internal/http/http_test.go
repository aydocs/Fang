package http

import (
	"testing"
	"time"

	"github.com/aydocs/fang/pkg/models"
)

func TestNewClient(t *testing.T) {
	c := NewClient()
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestClientWithConfig(t *testing.T) {
	c := NewClient(
		WithTimeout(5*time.Second),
		WithRateLimit(10),
		WithProxy("http://proxy:8080"),
		WithRetries(3),
	)
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestClientDefaultTimeout(t *testing.T) {
	c := NewClient()
	if c.config.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", c.config.Timeout)
	}
}

func TestClientDefaultRetries(t *testing.T) {
	c := NewClient()
	if c.config.MaxRetries != 2 {
		t.Errorf("MaxRetries = %d, want 2", c.config.MaxRetries)
	}
}

func TestClientWithCookies(t *testing.T) {
	cookies := []*models.Cookie{
		{Name: "session", Value: "abc123"},
	}
	c := NewClient(WithCookies(cookies))
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestClientWithHeaders(t *testing.T) {
	headers := map[string]string{"X-Test": "value"}
	c := NewClient(WithHeaders(headers))
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestRequestBuilder(t *testing.T) {
	req := NewRequest("GET", "http://test.com").
		WithHeader("X-Custom", "val").
		WithBody("test").
		WithCookie(&models.Cookie{Name: "session", Value: "abc"}).
		WithParam("q", "search")

	if req == nil {
		t.Fatal("expected non-nil request")
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(100)
	if rl == nil {
		t.Fatal("expected non-nil rate limiter")
	}
}

func TestRateLimiterAllow(t *testing.T) {
	rl := NewRateLimiter(10)
	if !rl.Allow() {
		t.Error("Allow() = false on fresh limiter")
	}
}

func TestRateLimiterStop(t *testing.T) {
	rl := NewRateLimiter(10)
	rl.Stop()
}

func TestPoolNew(t *testing.T) {
	p := NewPool(5)
	if p == nil {
		t.Fatal("expected non-nil pool")
	}
}

func TestMetrics(t *testing.T) {
	m := NewMetrics()
	if m == nil {
		t.Fatal("expected non-nil metrics")
	}
	m.AddRequest()
	m.AddSuccess()
	m.AddLatency(100 * time.Millisecond)
	m.AddBytesSent(1024)

	snap := m.Snapshot()
	if snap.TotalRequests != 1 {
		t.Errorf("TotalRequests = %d, want 1", snap.TotalRequests)
	}
	if snap.Successful != 1 {
		t.Errorf("Successful = %d, want 1", snap.Successful)
	}
}

func TestMiddlewareRetry(t *testing.T) {
	mw := RetryMiddleware(3, 10*time.Millisecond, nil)
	if mw == nil {
		t.Fatal("expected non-nil middleware")
	}
}

func TestTransportConfig(t *testing.T) {
	cfg := &Config{
		MaxIdleConns:   100,
		MaxConcurrency: 50,
	}
	if cfg.MaxIdleConns != 100 {
		t.Errorf("MaxIdleConns = %d, want 100", cfg.MaxIdleConns)
	}
}

func TestResponse(t *testing.T) {
	resp := &Response{
		StatusCode: 200,
		Body:       "OK",
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if resp.Body != "OK" {
		t.Errorf("Body = %q, want OK", resp.Body)
	}
}

func TestTransportWithProxy(t *testing.T) {
	tr := NewTransport(&Config{Proxy: "http://proxy:8080"})
	if tr == nil {
		t.Fatal("expected non-nil transport")
	}
}

func TestTransportWithSOCKS5(t *testing.T) {
	tr := NewTransport(&Config{SOCKS5: "socks5://localhost:1080"})
	if tr == nil {
		t.Fatal("expected non-nil transport")
	}
}
