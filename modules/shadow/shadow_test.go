package shadow

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestShadowModuleID(t *testing.T) {
	m := &ShadowModule{}
	if m.ID() != "shadow" {
		t.Errorf("ID = %q, want shadow", m.ID())
	}
}

func TestShadowModuleSeverity(t *testing.T) {
	m := &ShadowModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestShadowModuleInit(t *testing.T) {
	m := &ShadowModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestShadowScanGraceful(t *testing.T) {
	m := &ShadowModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
