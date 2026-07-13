package git

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestGitModuleID(t *testing.T) {
	m := &GitModule{}
	if m.ID() != "git" {
		t.Errorf("ID = %q, want git", m.ID())
	}
}

func TestGitModuleSeverity(t *testing.T) {
	m := &GitModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestGitModuleInit(t *testing.T) {
	m := &GitModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestGitModuleScanGraceful(t *testing.T) {
	m := &GitModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
