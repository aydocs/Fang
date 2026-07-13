package inject

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestInjectModuleID(t *testing.T) {
	m := &AdvancedInjectModule{}
	if m.ID() != "inject" {
		t.Errorf("ID = %q, want inject", m.ID())
	}
}

func TestInjectModuleSeverity(t *testing.T) {
	m := &AdvancedInjectModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestInjectModuleInit(t *testing.T) {
	m := &AdvancedInjectModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestInjectScanGraceful(t *testing.T) {
	m := &AdvancedInjectModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
