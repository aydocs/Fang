package saml

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestSAMLModuleID(t *testing.T) {
	m := &SAMLModule{}
	if m.ID() != "saml" {
		t.Errorf("ID = %q, want saml", m.ID())
	}
}

func TestSAMLModuleSeverity(t *testing.T) {
	m := &SAMLModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestSAMLModuleInit(t *testing.T) {
	m := &SAMLModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestSAMLModuleScanGraceful(t *testing.T) {
	m := &SAMLModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
