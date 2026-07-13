package report

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aydocs/fang/pkg/models"
)

func TestEngineNew(t *testing.T) {
	e := New(&Config{OutputDir: t.TempDir()})
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestEngineDefaultConfig(t *testing.T) {
	e := New(nil)
	if e.config == nil {
		t.Fatal("expected non-nil config")
	}
	if e.config.OutputDir == "" {
		t.Error("expected non-empty default OutputDir")
	}
}

func TestGenerateJSON(t *testing.T) {
	dir := t.TempDir()
	e := New(&Config{OutputDir: dir})

	result := &models.ScanResult{
		Target: "http://test.com",
		Findings: []*models.Finding{
			{Title: "Test Finding", Severity: models.High, Confidence: models.HighConfidence},
		},
	}

	path, err := e.GenerateJSON(context.Background(), result)
	if err != nil {
		t.Fatal(err)
	}

	if path == "" {
		t.Error("expected non-empty path")
	}

	files, _ := os.ReadDir(dir)
	if len(files) == 0 {
		t.Error("no files generated")
	}
}

func TestGenerateHTML(t *testing.T) {
	dir := t.TempDir()
	e := New(&Config{OutputDir: dir})

	result := &models.ScanResult{
		Target: "http://test.com",
		Findings: []*models.Finding{
			{Title: "XSS", Severity: models.Critical, Confidence: models.HighConfidence},
			{Title: "Info Leak", Severity: models.Low, Confidence: models.LowConfidence},
		},
	}

	path, err := e.GenerateHTML(context.Background(), result)
	if err != nil {
		t.Fatal(err)
	}

	if path == "" {
		t.Error("expected non-empty path")
	}

	files, _ := os.ReadDir(dir)
	if len(files) == 0 {
		t.Error("no files generated")
	}
}

func TestGenerateMarkdown(t *testing.T) {
	dir := t.TempDir()
	e := New(&Config{OutputDir: dir})

	result := &models.ScanResult{
		Target: "http://test.com",
		Findings: []*models.Finding{
			{Title: "SQL Injection", Severity: models.Critical, Confidence: models.HighConfidence},
		},
	}

	path, err := e.GenerateMarkdown(context.Background(), result)
	if err != nil {
		t.Fatal(err)
	}

	if path == "" {
		t.Error("expected non-empty path")
	}

	files, _ := os.ReadDir(dir)
	if len(files) == 0 {
		t.Error("no files generated")
	}
}

func TestGenerateSARIF(t *testing.T) {
	dir := t.TempDir()
	e := New(&Config{OutputDir: dir})

	result := &models.ScanResult{
		Target: "http://test.com",
		Findings: []*models.Finding{
			{Title: "RCE", Severity: models.Critical, Confidence: models.CriticalConfidence},
		},
	}

	path, err := e.GenerateSARIF(context.Background(), result)
	if err != nil {
		t.Fatal(err)
	}

	if path == "" {
		t.Error("expected non-empty path")
	}

	files, _ := os.ReadDir(dir)
	if len(files) == 0 {
		t.Error("no files generated")
	}
}

func TestGenerateAllFormats(t *testing.T) {
	dir := t.TempDir()
	e := New(&Config{OutputDir: dir})

	result := &models.ScanResult{
		Target: "http://test.com",
		Findings: []*models.Finding{
			{Title: "Test", Severity: models.Medium, Confidence: models.MediumConfidence},
		},
	}

	formats := []string{"json", "html", "markdown", "sarif"}
	for _, format := range formats {
		var err error
		switch format {
		case "json":
			_, err = e.GenerateJSON(context.Background(), result)
		case "html":
			_, err = e.GenerateHTML(context.Background(), result)
		case "markdown":
			_, err = e.GenerateMarkdown(context.Background(), result)
		case "sarif":
			_, err = e.GenerateSARIF(context.Background(), result)
		}
		if err != nil {
			t.Errorf("%s generation failed: %v", format, err)
		}
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) < 4 {
		t.Errorf("expected at least 4 files, got %d", len(entries))
	}
}

func TestWithOutputDirFile(t *testing.T) {
	dir := t.TempDir()
	e := New(&Config{OutputDir: filepath.Join(dir, "reports")})
	if e.config.OutputDir != filepath.Join(dir, "reports") {
		t.Errorf("OutputDir = %q, want %q", e.config.OutputDir, filepath.Join(dir, "reports"))
	}
}
