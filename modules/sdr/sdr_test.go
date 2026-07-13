package sdr

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestSdrModuleID(t *testing.T) {
	m := &SdrModule{}
	if m.ID() != "sdr" {
		t.Errorf("ID = %q, want sdr", m.ID())
	}
}

func TestSdrModuleSeverity(t *testing.T) {
	m := &SdrModule{}
	if m.Severity() != models.Medium {
		t.Errorf("Severity = %d, want Medium", m.Severity())
	}
}

func TestSdrModuleInit(t *testing.T) {
	m := &SdrModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestSdrModuleScanGraceful(t *testing.T) {
	m := &SdrModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
