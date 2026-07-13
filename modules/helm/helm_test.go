package helm

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestHelmModuleID(t *testing.T) {
	m := &HelmModule{}
	if m.ID() != "helm" {
		t.Errorf("ID = %q, want helm", m.ID())
	}
}

func TestHelmModuleSeverity(t *testing.T) {
	m := &HelmModule{}
	if m.Severity() != models.High {
		t.Errorf("Severity = %d, want High", m.Severity())
	}
}

func TestHelmModuleInit(t *testing.T) {
	m := &HelmModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestHelmModuleScanGraceful(t *testing.T) {
	m := &HelmModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
