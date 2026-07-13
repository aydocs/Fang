package phish

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestPhishModuleID(t *testing.T) {
	m := &PhishModule{}
	if m.ID() != "phish" {
		t.Errorf("ID = %q, want phish", m.ID())
	}
}

func TestPhishModuleSeverity(t *testing.T) {
	m := &PhishModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestPhishModuleInit(t *testing.T) {
	m := &PhishModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestPhishModuleScanGraceful(t *testing.T) {
	m := &PhishModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
