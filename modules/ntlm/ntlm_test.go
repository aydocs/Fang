package ntlm

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestNTLMModuleID(t *testing.T) {
	m := &NTLMModule{}
	if m.ID() != "ntlm" {
		t.Errorf("ID = %q, want ntlm", m.ID())
	}
}

func TestNTLMModuleSeverity(t *testing.T) {
	m := &NTLMModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestNTLMModuleInit(t *testing.T) {
	m := &NTLMModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestNTLMModuleScanGraceful(t *testing.T) {
	m := &NTLMModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
