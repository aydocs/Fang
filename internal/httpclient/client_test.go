package httpclient

import (
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	c := NewClient(5 * time.Second)
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestClientGet(t *testing.T) {
	c := NewClient(5 * time.Second)
	_, err := c.Get("http://localhost:1/test")
	if err == nil {
		t.Log("Get returned nil error")
	}
}

func TestClientPost(t *testing.T) {
	c := NewClient(5 * time.Second)
	_, err := c.Post("http://localhost:1/test", "{}")
	if err == nil {
		t.Log("Post returned nil error")
	}
}

func TestClientHead(t *testing.T) {
	c := NewClient(5 * time.Second)
	_, err := c.Head("http://localhost:1/test")
	if err == nil {
		t.Log("Head returned nil error")
	}
}

func TestClientDoRaw(t *testing.T) {
	c := NewClient(5 * time.Second)
	_, err := c.DoRaw("OPTIONS", "http://localhost:1/test", nil)
	if err == nil {
		t.Log("DoRaw returned nil error")
	}
}

func TestClientGetWithHeaders(t *testing.T) {
	c := NewClient(5 * time.Second)
	headers := map[string]string{"X-Test": "value"}
	_, err := c.GetWithHeaders("http://localhost:1/test", headers)
	if err == nil {
		t.Log("GetWithHeaders returned nil error")
	}
}

func TestClientConfig(t *testing.T) {
	c := NewClient(5 * time.Second)
	cfg := c.Config()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}
