package xpath

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestXPathModuleID(t *testing.T) {
	m := &XPathModule{}
	if m.ID() != "xpath" {
		t.Errorf("ID = %q, want xpath", m.ID())
	}
}

func TestXPathModuleSeverity(t *testing.T) {
	m := &XPathModule{}
	if m.Severity() != models.High {
		t.Errorf("Severity = %d, want High", m.Severity())
	}
}

func TestXPathModuleInit(t *testing.T) {
	m := &XPathModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestXPathScanGraceful(t *testing.T) {
	m := &XPathModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
