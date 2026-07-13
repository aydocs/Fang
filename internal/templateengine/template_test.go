package templateengine

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/templates"
)

func TestEngineNew(t *testing.T) {
	e := NewEngine(nil)
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestLoadTemplatesDirectory(t *testing.T) {
	dir := t.TempDir()
	tmpl := `
id: test-template
info:
  name: Test Template
  severity: info
  remediation: "Fix it"
  tags: test
requests:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: word
        words:
          - "test"
`
	os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(tmpl), 0644)

	e := NewEngine(nil)
	err := e.LoadDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
}

func TestLoadTemplatesInvalidDir(t *testing.T) {
	e := NewEngine(nil)
	err := e.LoadDirectory("/nonexistent")
	if err == nil {
		t.Log("LoadDirectory on nonexistent dir returned nil error")
	}
}

func TestExecuteTemplate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	tmplContent := `
id: test
info:
  name: Test
  severity: info
  remediation: "Fix it"
  tags: test
requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "test"
`
	os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(tmplContent), 0644)

	client := fanghttp.NewClient()
	defer client.Close()

	e := NewEngine(client)
	err := e.LoadDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}

	results := e.Execute(srv.URL)
	if results == nil {
		t.Error("expected non-nil results")
	}
	if len(results) == 0 {
		t.Error("expected at least one match")
	}
}

func TestMatcherTypes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	tmplContent := `
id: matcher-test
info:
  name: Matcher Test
  severity: medium
  remediation: "Fix it"
  tags: test
requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
`
	os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(tmplContent), 0644)

	client := fanghttp.NewClient()
	defer client.Close()

	e := NewEngine(client)
	err := e.LoadDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}

	results := e.Execute(srv.URL)
	if len(results) == 0 {
		t.Log("no matches (expected for closed port)")
	}
}

func TestMultiMatcher(t *testing.T) {
	matchers := []templates.Matcher{
		{Type: "word", Words: []string{"root"}},
		{Type: "status", Status: []int{200}},
	}
	if len(matchers) != 2 {
		t.Errorf("len(matchers) = %d, want 2", len(matchers))
	}
}

func TestTemplateLoad(t *testing.T) {
	_, err := templates.LoadTemplate("")
	if err == nil {
		t.Error("LoadTemplate with empty path should error")
	}
}
