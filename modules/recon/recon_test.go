package recon

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestReconModuleID(t *testing.T) {
	m := &ReconModule{}
	if m.ID() != "recon" {
		t.Errorf("ID = %q, want recon", m.ID())
	}
}

func TestReconModuleSeverity(t *testing.T) {
	m := &ReconModule{}
	if m.Severity() != models.Info {
		t.Errorf("Severity = %d, want Info", m.Severity())
	}
}

func TestReconModuleInit(t *testing.T) {
	m := &ReconModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestReconScanGraceful(t *testing.T) {
	m := &ReconModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
