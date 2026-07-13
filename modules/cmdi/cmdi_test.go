package cmdi

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestCMDIModuleID(t *testing.T) {
	m := &CMDIModule{}
	if m.ID() != "cmdi" {
		t.Errorf("ID = %q, want cmdi", m.ID())
	}
}

func TestCMDIModuleSeverity(t *testing.T) {
	m := &CMDIModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestCMDIModuleInit(t *testing.T) {
	m := &CMDIModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestCMDIScanGraceful(t *testing.T) {
	m := &CMDIModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
