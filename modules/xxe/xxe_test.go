package xxe

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestXXEModuleID(t *testing.T) {
	m := &XXEModule{}
	if m.ID() != "xxe" {
		t.Errorf("ID = %q, want xxe", m.ID())
	}
}

func TestXXEModuleSeverity(t *testing.T) {
	m := &XXEModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestXXEModuleInit(t *testing.T) {
	m := &XXEModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestXXEScanGraceful(t *testing.T) {
	m := &XXEModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
