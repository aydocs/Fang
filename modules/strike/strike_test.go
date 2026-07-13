package strike

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestStrikeModuleID(t *testing.T) {
	m := &StrikeModule{}
	if m.ID() != "strike" {
		t.Errorf("ID = %q, want strike", m.ID())
	}
}

func TestStrikeModuleSeverity(t *testing.T) {
	m := &StrikeModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestStrikeModuleInit(t *testing.T) {
	m := &StrikeModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestStrikeScanGraceful(t *testing.T) {
	m := &StrikeModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}

func TestStrikeDescription(t *testing.T) {
	m := &StrikeModule{}
	desc := m.Description()
	if desc == "" {
		t.Error("Description should not be empty")
	}
}
