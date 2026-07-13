package idpwn

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestIDPwnModuleID(t *testing.T) {
	m := &IDPwnModule{}
	if m.ID() != "idpwn" {
		t.Errorf("ID = %q, want idpwn", m.ID())
	}
}

func TestIDPwnModuleSeverity(t *testing.T) {
	m := &IDPwnModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestIDPwnModuleInit(t *testing.T) {
	m := &IDPwnModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestIDPwnScanGraceful(t *testing.T) {
	m := &IDPwnModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
