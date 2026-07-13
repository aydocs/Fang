package adcs

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestADCSModuleID(t *testing.T) {
	m := &ADCSModule{}
	if m.ID() != "adcs" {
		t.Errorf("ID = %q, want adcs", m.ID())
	}
}

func TestADCSModuleSeverity(t *testing.T) {
	m := &ADCSModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestADCSModuleInit(t *testing.T) {
	m := &ADCSModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestADCSModuleScanGraceful(t *testing.T) {
	m := &ADCSModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
