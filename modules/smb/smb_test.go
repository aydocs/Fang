package smb

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestSMBModuleID(t *testing.T) {
	m := &SMBModule{}
	if m.ID() != "smb" {
		t.Errorf("ID = %q, want smb", m.ID())
	}
}

func TestSMBModuleSeverity(t *testing.T) {
	m := &SMBModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestSMBModuleInit(t *testing.T) {
	m := &SMBModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestSMBModuleScanGraceful(t *testing.T) {
	m := &SMBModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
