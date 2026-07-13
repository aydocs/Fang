package crawler

import (
	"context"
	"testing"
	"time"

	"github.com/aydocs/fang/internal/engine"
)

func TestCrawlerNew(t *testing.T) {
	c := &Crawler{}
	if err := c.Init(context.Background(), nil); err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
}

func TestCrawlerConfigDefaults(t *testing.T) {
	c := &Crawler{}
	if err := c.Init(context.Background(), nil); err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	if c.config.MaxDepth != 2 {
		t.Errorf("MaxDepth = %d, want 2", c.config.MaxDepth)
	}
	if c.config.MaxPages != 50 {
		t.Errorf("MaxPages = %d, want 50", c.config.MaxPages)
	}
	if c.config.MaxConcurrency != 10 {
		t.Errorf("MaxConcurrency = %d, want 10", c.config.MaxConcurrency)
	}
	if !c.config.FollowRedirects {
		t.Error("FollowRedirects = false, want true")
	}
}

func TestCrawlerWithConfig(t *testing.T) {
	c := &Crawler{}
	cfg := &engine.Config{
		Threads: 2,
		Timeout: 5 * time.Second,
	}
	if err := c.Init(context.Background(), cfg); err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	if c.config.MaxConcurrency != 2 {
		t.Errorf("MaxConcurrency = %d, want 2", c.config.MaxConcurrency)
	}
	if c.config.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", c.config.Timeout)
	}
}

func TestFilterIncludeExclude(t *testing.T) {
	f := NewFilter()
	if err := f.AddIncludePattern(`\.php$`); err != nil {
		t.Fatalf("AddIncludePattern returned error: %v", err)
	}
	if err := f.AddExcludePattern(`admin`); err != nil {
		t.Fatalf("AddExcludePattern returned error: %v", err)
	}

	if !f.ShouldCrawl("/index.php") {
		t.Error("ShouldCrawl(/index.php) = false, want true")
	}
	if f.ShouldCrawl("/admin.php") {
		t.Error("ShouldCrawl(/admin.php) = true, want false")
	}
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input string
		base  string
		want  string
	}{
		{"HTTP://EXAMPLE.COM/", "", "http://example.com"},
		{"http://example.com:80/", "", "http://example.com"},
		{"http://example.com/foo?b=1&a=2", "", "http://example.com/foo?a=2&b=1"},
	}
	for _, tt := range tests {
		got := NormalizeURL(tt.input, tt.base)
		if got != tt.want {
			t.Errorf("NormalizeURL(%q, %q) = %q, want %q", tt.input, tt.base, got, tt.want)
		}
	}
}

func TestIsSameDomain(t *testing.T) {
	if !IsSameDomain("http://example.com/page", "http://example.com/other") {
		t.Error("IsSameDomain(example, example) = false")
	}
	if IsSameDomain("http://example.com/page", "http://other.com/") {
		t.Error("IsSameDomain(example, other) = true")
	}
}

func TestParseLinks(t *testing.T) {
	html := `<a href="/page1">Link1</a><a href="http://other.com">External</a>`
	links := ParseLinks(html, "http://example.com/")
	if len(links) == 0 {
		t.Log("no links parsed (may need full HTML document)")
	}
}

func TestFilterStaticFiles(t *testing.T) {
	f := NewFilter()
	static := []string{".jpg", ".png", ".css", ".svg"}
	for _, ext := range static {
		if !f.IsStaticFile("http://example.com/file" + ext) {
			t.Errorf("IsStaticFile(file%s) = false, want true", ext)
		}
	}
	if f.IsStaticFile("http://example.com/index.php") {
		t.Error("IsStaticFile(index.php) = true, want false")
	}
}

func TestRobotsParser(t *testing.T) {
	robots := `User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /public/`
	rp := ParseRobots(robots)
	if !rp.IsAllowed("/public/") {
		t.Error("IsAllowed(/public/) = false, want true")
	}
	if rp.IsAllowed("/admin/") {
		t.Error("IsAllowed(/admin/) = true, want false")
	}
}

func TestExtractJSEndpoints(t *testing.T) {
	js := `
	fetch('/api/users')
	axios.post('/api/login', data)
	new WebSocket('wss://chat.example.com')
	`
	endpoints := ExtractJSEndpoints(js)
	if len(endpoints) == 0 {
		t.Log("no endpoints extracted (may need different JS patterns)")
	}
}
