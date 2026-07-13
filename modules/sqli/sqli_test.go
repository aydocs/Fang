package sqli

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestSQLiModuleID(t *testing.T) {
	m := &SQLiModule{}
	if m.ID() != "sqli" {
		t.Errorf("ID = %q, want sqli", m.ID())
	}
}

func TestSQLiModuleName(t *testing.T) {
	m := &SQLiModule{}
	if m.Name() == "" {
		t.Error("Name should not be empty")
	}
}

func TestSQLiModuleSeverity(t *testing.T) {
	m := &SQLiModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestSQLiModuleInit(t *testing.T) {
	m := &SQLiModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestSQLiScanEmptyTarget(t *testing.T) {
	m := &SQLiModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1", Domain: "127.0.0.1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
