package engine

import (
	"context"
	"testing"

	"github.com/aydocs/fang/pkg/models"
)

type mockModule struct {
	id       string
	name     string
	desc     string
	severity models.Severity
	findings []*models.Finding
	err      error
}

func (m *mockModule) ID() string                                  { return m.id }
func (m *mockModule) Name() string                                { return m.name }
func (m *mockModule) Description() string                         { return m.desc }
func (m *mockModule) Severity() models.Severity                   { return m.severity }
func (m *mockModule) Init(ctx context.Context, cfg *Config) error { return nil }
func (m *mockModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	return m.findings, m.err
}

func TestEngineRunAll(t *testing.T) {
	global = &Registry{modules: make(map[string]Module)}
	global.Register(&mockModule{
		id: "mock1", name: "Mock One", severity: 3,
		findings: []*models.Finding{{Title: "Test", Severity: models.Critical}},
	})

	eng := New(NewConfig(WithThreads(1), WithTimeout(5)))
	result, err := eng.Run(context.Background(), "https://example.com")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(result.Findings))
	}
}

func TestEngineRunModule(t *testing.T) {
	global = &Registry{modules: make(map[string]Module)}
	global.Register(&mockModule{
		id: "mock1", name: "Mock One", severity: 3,
		findings: []*models.Finding{{Title: "Found!", Severity: models.Critical}},
	})

	eng := New(NewConfig(WithThreads(1), WithTimeout(5)))
	result, err := eng.RunModule(context.Background(), "mock1", "https://example.com")
	if err != nil {
		t.Fatalf("RunModule failed: %v", err)
	}
	if result.ModuleID != "mock1" {
		t.Errorf("module id = %q, want mock1", result.ModuleID)
	}
}

func TestEngineRunUnknownModule(t *testing.T) {
	global = &Registry{modules: make(map[string]Module)}
	eng := New(NewConfig())
	_, err := eng.RunModule(context.Background(), "nonexistent", "https://example.com")
	if err == nil {
		t.Fatal("expected error for unknown module")
	}
}

func TestEngineFilterModules(t *testing.T) {
	global = &Registry{modules: make(map[string]Module)}
	global.Register(&mockModule{id: "keep", severity: 3})
	global.Register(&mockModule{id: "skip", severity: 0})
	global.Register(&mockModule{id: "exclude", severity: 4})

	cfg := NewConfig(
		WithModules("keep", "skip"),
		WithExcludeModules("exclude"),
	)
	eng := New(cfg)

	filtered := eng.filterModules(global.List())
	if len(filtered) != 2 {
		t.Errorf("expected 2 filtered modules, got %d", len(filtered))
	}
}

func TestEngineQuickFilter(t *testing.T) {
	global = &Registry{modules: make(map[string]Module)}
	global.Register(&mockModule{id: "critical", severity: 4})
	global.Register(&mockModule{id: "info", severity: 0})

	cfg := NewConfig(WithQuick(true))
	eng := New(cfg)

	filtered := eng.filterModules(global.List())
	if len(filtered) != 1 {
		t.Errorf("expected 1 module in quick mode, got %d", len(filtered))
	}
	if filtered[0].ID() != "critical" {
		t.Errorf("expected critical module, got %s", filtered[0].ID())
	}
}

func TestEngineTargetFromURL(t *testing.T) {
	eng := New(NewConfig())
	target, err := eng.TargetFromURL("https://example.com/path?q=1")
	if err != nil {
		t.Fatalf("TargetFromURL failed: %v", err)
	}
	if target.URL != "https://example.com/path?q=1" {
		t.Errorf("url = %q, want https://example.com/path?q=1", target.URL)
	}
	if target.Domain != "example.com" {
		t.Errorf("domain = %q, want example.com", target.Domain)
	}
}

func TestEngineModulesAreEnriched(t *testing.T) {
	global = &Registry{modules: make(map[string]Module)}
	global.Register(&mockModule{
		id: "sqli", severity: 4,
		findings: []*models.Finding{{
			Title: "SQLi Test",
			CWEID: "CWE-89",
		}},
	})

	eng := New(NewConfig(WithThreads(1), WithTimeout(5)))
	result, err := eng.Run(context.Background(), "https://example.com")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Findings[0].OWASPCategory == "" {
		t.Error("expected OWASPCategory to be enriched")
	}
	if result.Findings[0].CVSS == nil {
		t.Error("expected CVSS to be enriched")
	}
}
