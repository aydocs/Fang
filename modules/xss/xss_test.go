package xss

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestXSSModuleID(t *testing.T) {
	m := &XSSModule{}
	if m.ID() != "xss" {
		t.Errorf("ID = %q, want xss", m.ID())
	}
}

func TestXSSModuleSeverity(t *testing.T) {
	m := &XSSModule{}
	if m.Severity() != models.High {
		t.Errorf("Severity = %d, want High", m.Severity())
	}
}

func TestXSSModuleInit(t *testing.T) {
	m := &XSSModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestXSSScanHandlesError(t *testing.T) {
	m := &XSSModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
