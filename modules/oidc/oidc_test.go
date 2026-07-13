package oidc

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestOIDCModuleID(t *testing.T) {
	m := &OIDCModule{}
	if m.ID() != "oidc" {
		t.Errorf("ID = %q, want oidc", m.ID())
	}
}

func TestOIDCModuleSeverity(t *testing.T) {
	m := &OIDCModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestOIDCModuleInit(t *testing.T) {
	m := &OIDCModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestOIDCModuleScanGraceful(t *testing.T) {
	m := &OIDCModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
