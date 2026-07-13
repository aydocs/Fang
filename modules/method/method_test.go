package method

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestMethodModuleID(t *testing.T) {
	m := &MethodModule{}
	if m.ID() != "method" {
		t.Errorf("ID = %q, want method", m.ID())
	}
}

func TestMethodModuleSeverity(t *testing.T) {
	m := &MethodModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestMethodModuleInit(t *testing.T) {
	m := &MethodModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestMethodScanGraceful(t *testing.T) {
	m := &MethodModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
