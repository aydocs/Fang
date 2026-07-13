package soap

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestSOAPModuleID(t *testing.T) {
	m := &SOAPModule{}
	if m.ID() != "soap" {
		t.Errorf("ID = %q, want soap", m.ID())
	}
}

func TestSOAPModuleSeverity(t *testing.T) {
	m := &SOAPModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestSOAPModuleInit(t *testing.T) {
	m := &SOAPModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestSOAPModuleScanGraceful(t *testing.T) {
	m := &SOAPModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
