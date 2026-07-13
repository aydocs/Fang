package dataphantom

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestDataPhantomModuleID(t *testing.T) {
	m := &DataPhantomModule{}
	if m.ID() != "dataphantom" {
		t.Errorf("ID = %q, want dataphantom", m.ID())
	}
}

func TestDataPhantomModuleSeverity(t *testing.T) {
	m := &DataPhantomModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestDataPhantomModuleInit(t *testing.T) {
	m := &DataPhantomModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestDataPhantomScanGraceful(t *testing.T) {
	m := &DataPhantomModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
