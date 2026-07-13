package report

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aydocs/fang/pkg/models"
)

type Config struct {
	OutputDir       string
	Formats         []string
	IncludeEvidence bool
	IncludeRaw      bool
}

type Engine struct {
	config *Config
}

func New(cfg *Config) *Engine {
	if cfg == nil {
		home, _ := os.UserHomeDir()
		cfg = &Config{
			OutputDir:       filepath.Join(home, ".fang", "reports"),
			Formats:         []string{"json"},
			IncludeEvidence: true,
		}
	}
	return &Engine{config: cfg}
}

func (e *Engine) Generate(ctx context.Context, result *models.ScanResult) ([]string, error) {
	var paths []string
	for _, format := range e.config.Formats {
		var path string
		var err error
		switch strings.ToLower(format) {
		case "html":
			path, err = e.GenerateHTML(ctx, result)
		case "json":
			path, err = e.GenerateJSON(ctx, result)
		case "md", "markdown":
			path, err = e.GenerateMarkdown(ctx, result)
		case "pdf":
			path, err = e.GeneratePDF(ctx, result, nil)
		case "sarif":
			path, err = e.GenerateSARIF(ctx, result)
		default:
			return paths, fmt.Errorf("unsupported format: %s", format)
		}
		if err != nil {
			return paths, fmt.Errorf("%s generation failed: %w", format, err)
		}
		paths = append(paths, path)
	}
	return paths, nil
}

func (e *Engine) GenerateHTML(ctx context.Context, result *models.ScanResult) (string, error) {
	body := e.buildHTML(result)
	sanitized := sanitizeTarget(result.Target)
	ts := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("%s_%s.html", sanitized, ts)
	path := filepath.Join(e.config.OutputDir, filename)

	if err := os.MkdirAll(e.config.OutputDir, 0755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		return "", err
	}
	return path, nil
}

func (e *Engine) GenerateJSON(ctx context.Context, result *models.ScanResult) (string, error) {
	body, err := generateJSON(result)
	if err != nil {
		return "", err
	}
	sanitized := sanitizeTarget(result.Target)
	ts := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("%s_%s.json", sanitized, ts)
	path := filepath.Join(e.config.OutputDir, filename)

	if err := os.MkdirAll(e.config.OutputDir, 0755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		return "", err
	}
	return path, nil
}

func (e *Engine) GenerateMarkdown(ctx context.Context, result *models.ScanResult) (string, error) {
	body := generateMarkdown(result)
	sanitized := sanitizeTarget(result.Target)
	ts := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("%s_%s.md", sanitized, ts)
	path := filepath.Join(e.config.OutputDir, filename)

	if err := os.MkdirAll(e.config.OutputDir, 0755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		return "", err
	}
	return path, nil
}

func (e *Engine) GenerateSARIF(ctx context.Context, result *models.ScanResult) (string, error) {
	body, err := generateSARIF(result)
	if err != nil {
		return "", err
	}
	sanitized := sanitizeTarget(result.Target)
	ts := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("%s_%s.sarif", sanitized, ts)
	path := filepath.Join(e.config.OutputDir, filename)

	if err := os.MkdirAll(e.config.OutputDir, 0755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		return "", err
	}
	return path, nil
}

func sanitizeTarget(target string) string {
	s := strings.ReplaceAll(target, "https://", "")
	s = strings.ReplaceAll(s, "http://", "")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, ":", "_")
	return s
}
