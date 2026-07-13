package reverse

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestReverseModuleID(t *testing.T) {
	m := &ReverseModule{}
	if m.ID() != "reverse" {
		t.Errorf("ID = %q, want reverse", m.ID())
	}
}

func TestReverseModuleSeverity(t *testing.T) {
	m := &ReverseModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestReverseModuleInit(t *testing.T) {
	m := &ReverseModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestReverseScanGraceful(t *testing.T) {
	m := &ReverseModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
