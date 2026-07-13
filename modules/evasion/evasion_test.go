package evasion

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestEvasionModuleID(t *testing.T) {
	m := &EvasionModule{}
	if m.ID() != "evasion" {
		t.Errorf("ID = %q, want evasion", m.ID())
	}
}

func TestEvasionModuleSeverity(t *testing.T) {
	m := &EvasionModule{}
	if m.Severity() != models.High {
		t.Errorf("Severity = %d, want High", m.Severity())
	}
}

func TestEvasionModuleInit(t *testing.T) {
	m := &EvasionModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestEvasionScanGraceful(t *testing.T) {
	m := &EvasionModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
