package kerberos

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestKerberosModuleID(t *testing.T) {
	m := &KerberosModule{}
	if m.ID() != "kerberos" {
		t.Errorf("ID = %q, want kerberos", m.ID())
	}
}

func TestKerberosModuleSeverity(t *testing.T) {
	m := &KerberosModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestKerberosModuleInit(t *testing.T) {
	m := &KerberosModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestKerberosModuleScanGraceful(t *testing.T) {
	m := &KerberosModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
