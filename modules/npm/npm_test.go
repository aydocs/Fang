package npm

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestNpmModuleID(t *testing.T) {
	m := &NpmModule{}
	if m.ID() != "npm" {
		t.Errorf("ID = %q, want npm", m.ID())
	}
}

func TestNpmModuleSeverity(t *testing.T) {
	m := &NpmModule{}
	if m.Severity() != models.High {
		t.Errorf("Severity = %d, want High", m.Severity())
	}
}

func TestNpmModuleInit(t *testing.T) {
	m := &NpmModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestNpmModuleScanGraceful(t *testing.T) {
	m := &NpmModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
