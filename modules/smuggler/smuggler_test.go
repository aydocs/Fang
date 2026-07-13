package smuggler

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestSmugglerModuleID(t *testing.T) {
	m := &SmugglerModule{}
	if m.ID() != "smuggler" {
		t.Errorf("ID = %q, want smuggler", m.ID())
	}
}

func TestSmugglerModuleSeverity(t *testing.T) {
	m := &SmugglerModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestSmugglerModuleInit(t *testing.T) {
	m := &SmugglerModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestSmugglerScanGraceful(t *testing.T) {
	m := &SmugglerModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
