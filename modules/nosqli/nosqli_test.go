package nosqli

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestNoSQLModuleID(t *testing.T) {
	m := &NoSQLModule{}
	if m.ID() != "nosqli" {
		t.Errorf("ID = %q, want nosqli", m.ID())
	}
}

func TestNoSQLModuleSeverity(t *testing.T) {
	m := &NoSQLModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestNoSQLModuleInit(t *testing.T) {
	m := &NoSQLModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestNoSQLScanGraceful(t *testing.T) {
	m := &NoSQLModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
