package spectre

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestSpectreModuleID(t *testing.T) {
	m := &SpectreModule{}
	if m.ID() != "spectre" {
		t.Errorf("ID = %q, want spectre", m.ID())
	}
}

func TestSpectreModuleSeverity(t *testing.T) {
	m := &SpectreModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestSpectreModuleInit(t *testing.T) {
	m := &SpectreModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestSpectreScanGraceful(t *testing.T) {
	m := &SpectreModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
