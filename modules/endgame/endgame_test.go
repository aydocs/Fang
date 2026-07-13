package endgame

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestEndGameModuleID(t *testing.T) {
	m := &EndGameModule{}
	if m.ID() != "endgame" {
		t.Errorf("ID = %q, want endgame", m.ID())
	}
}

func TestEndGameModuleSeverity(t *testing.T) {
	m := &EndGameModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestEndGameModuleInit(t *testing.T) {
	m := &EndGameModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestEndGameScanGraceful(t *testing.T) {
	m := &EndGameModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
