package ldap

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestLDAPModuleID(t *testing.T) {
	m := &LDAPModule{}
	if m.ID() != "ldap" {
		t.Errorf("ID = %q, want ldap", m.ID())
	}
}

func TestLDAPModuleSeverity(t *testing.T) {
	m := &LDAPModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestLDAPModuleInit(t *testing.T) {
	m := &LDAPModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestLDAPScanGraceful(t *testing.T) {
	m := &LDAPModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
