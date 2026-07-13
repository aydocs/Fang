package redirect

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestRedirectModuleID(t *testing.T) {
	m := &RedirectModule{}
	if m.ID() != "redirect" {
		t.Errorf("ID = %q, want redirect", m.ID())
	}
}

func TestRedirectModuleSeverity(t *testing.T) {
	m := &RedirectModule{}
	if m.Severity() != models.Medium {
		t.Errorf("Severity = %d, want Medium", m.Severity())
	}
}

func TestRedirectModuleInit(t *testing.T) {
	m := &RedirectModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestRedirectScanGraceful(t *testing.T) {
	m := &RedirectModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
