package sbom

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestSbomModuleID(t *testing.T) {
	m := &SbomModule{}
	if m.ID() != "sbom" {
		t.Errorf("ID = %q, want sbom", m.ID())
	}
}

func TestSbomModuleSeverity(t *testing.T) {
	m := &SbomModule{}
	if m.Severity() != models.High {
		t.Errorf("Severity = %d, want High", m.Severity())
	}
}

func TestSbomModuleInit(t *testing.T) {
	m := &SbomModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestSbomModuleScanGraceful(t *testing.T) {
	m := &SbomModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
