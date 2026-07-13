package auth

import (
	"net/http"
	"testing"
)

func TestNewSession(t *testing.T) {
	s := NewSession()
	if s == nil {
		t.Fatal("expected non-nil session")
	}
}

func TestSessionWithCookies(t *testing.T) {
	s := NewSession()
	s.Cookies = append(s.Cookies, &http.Cookie{Name: "session", Value: "abc123"})
	req, _ := http.NewRequest("GET", "http://test.com", nil)
	s.ApplyToRequest(req)
	cookies := req.Header.Get("Cookie")
	if cookies == "" {
		t.Error("no cookies applied")
	}
}

func TestSessionWithHeader(t *testing.T) {
	s := NewSession()
	s.Headers["Authorization"] = "Bearer token"
	req, _ := http.NewRequest("GET", "http://test.com", nil)
	s.ApplyToRequest(req)
	if req.Header.Get("Authorization") != "Bearer token" {
		t.Errorf("Authorization = %q", req.Header.Get("Authorization"))
	}
}

func TestSessionFromResponse(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{"session=abc; Path=/"},
		},
	}
	s := NewSession()
	s.FromResponse(resp)
	if len(s.Cookies) == 0 {
		t.Fatal("expected cookies from response")
	}
}

func TestSessionClone(t *testing.T) {
	s := NewSession()
	s.Cookies = append(s.Cookies, &http.Cookie{Name: "a", Value: "1"})
	s.Headers["X-Test"] = "val"

	clone := s.Clone()
	if clone == nil {
		t.Fatal("expected non-nil clone")
	}
	if len(clone.Cookies) != 1 {
		t.Errorf("clone cookies = %d, want 1", len(clone.Cookies))
	}
	if clone.Headers["X-Test"] != "val" {
		t.Errorf("clone header = %q, want val", clone.Headers["X-Test"])
	}
}

func TestSessionBasicAuth(t *testing.T) {
	s := NewSession()
	s.BasicUser = "admin"
	s.BasicPass = "password"
	req, _ := http.NewRequest("GET", "http://test.com", nil)
	s.ApplyToRequest(req)
	auth := req.Header.Get("Authorization")
	if auth == "" {
		t.Error("basic auth not applied")
	}
}

func TestSessionBearerToken(t *testing.T) {
	s := NewSession()
	s.Bearer = "my-token"
	req, _ := http.NewRequest("GET", "http://test.com", nil)
	s.ApplyToRequest(req)
	if req.Header.Get("Authorization") != "Bearer my-token" {
		t.Errorf("Authorization = %q", req.Header.Get("Authorization"))
	}
}

func TestSessionMultipleCookies(t *testing.T) {
	s := NewSession()
	s.Cookies = append(s.Cookies, &http.Cookie{Name: "a", Value: "1"})
	s.Cookies = append(s.Cookies, &http.Cookie{Name: "b", Value: "2"})
	req, _ := http.NewRequest("GET", "http://test.com", nil)
	s.ApplyToRequest(req)
	cookie := req.Header.Get("Cookie")
	if cookie == "" {
		t.Error("no cookies")
	}
}

func TestSessionCSRF(t *testing.T) {
	s := NewSession()
	s.CSRF = "csrf-token"
	req, _ := http.NewRequest("POST", "http://test.com", nil)
	s.ApplyToRequest(req)
	if req.Header.Get("X-CSRF-Token") != "csrf-token" {
		t.Errorf("CSRF token = %q", req.Header.Get("X-CSRF-Token"))
	}
}

func TestSessionCloneNil(t *testing.T) {
	var s *Session
	clone := s.Clone()
	if clone != nil {
		t.Error("nil session clone should return nil")
	}
}
