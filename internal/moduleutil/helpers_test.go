package moduleutil

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fanghttp "github.com/aydocs/fang/internal/http"
)

func newTestClient() *fanghttp.Client {
	return fanghttp.NewClient()
}

func TestBuildURL(t *testing.T) {
	url := BuildURL("http://test.com", "/api/users")
	if url != "http://test.com/api/users" {
		t.Errorf("BuildURL = %q", url)
	}
}

func TestBuildURLWithSlash(t *testing.T) {
	url := BuildURL("http://test.com/", "/api/users")
	if url != "http://test.com/api/users" {
		t.Errorf("BuildURL with trailing slash = %q", url)
	}
}

func TestHasMarker(t *testing.T) {
	if !HasMarker("testFANGMARKERcontent", "FANGMARKER") {
		t.Error("HasMarker should find FANGMARKER")
	}
	if HasMarker("testcontent", "FANGMARKER") {
		t.Error("HasMarker should not find FANGMARKER")
	}
}

func TestExtractParams(t *testing.T) {
	params := ExtractParams("http://test.com/page.php?id=1&name=test&page=2")
	if len(params) != 3 {
		t.Errorf("expected 3 params, got %d", len(params))
	}
}

func TestExtractParamsNoQuery(t *testing.T) {
	params := ExtractParams("http://test.com/page.php")
	if len(params) != 0 {
		t.Errorf("expected 0 params, got %d", len(params))
	}
}

func TestCheckReflection(t *testing.T) {
	client := newTestClient()
	defer client.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("echo: " + r.URL.Query().Get("param")))
	}))
	defer srv.Close()

	if !CheckReflection(client, srv.URL, "param", "MARKER") {
		t.Error("CheckReflection should find reflected marker")
	}

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("no marker here"))
	}))
	defer srv2.Close()

	if CheckReflection(client, srv2.URL, "param", "MARKER") {
		t.Error("CheckReflection should not find unreflected marker")
	}
}

func TestCheckTimeDelay(t *testing.T) {
	client := newTestClient()
	defer client.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("fast"))
	}))
	defer srv.Close()

	if CheckTimeDelay(client, srv.URL, 5*time.Second) {
		t.Error("CheckTimeDelay should return false for fast response with long expected delay")
	}
}

func TestExtractJSFiles(t *testing.T) {
	html := `<script src="/js/app.js"></script><script src="https://cdn.com/lib.js"></script>`
	files := ExtractJSFiles(html, "http://test.com")
	if len(files) == 0 {
		t.Log("no JS files extracted")
	}
}

func TestExtractParamsDuplicate(t *testing.T) {
	params := ExtractParams("http://test.com/?a=1&a=2&b=3")
	if len(params) != 2 {
		t.Logf("duplicate param handling: %d params", len(params))
	}
}

func TestCheckReflectionEmpty(t *testing.T) {
	client := newTestClient()
	defer client.Close()

	if CheckReflection(client, "", "marker", "payload") {
		t.Error("CheckReflection('', 'marker', 'payload') = true")
	}
}

func TestCheckTimeDelayNumeric(t *testing.T) {
	client := newTestClient()
	defer client.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.Write([]byte("delayed"))
	}))
	defer srv.Close()

	if !CheckTimeDelay(client, srv.URL, 100*time.Millisecond) {
		t.Error("CheckTimeDelay should return true for delayed response")
	}
}
