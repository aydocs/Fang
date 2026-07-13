package k8s

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestK8sModuleID(t *testing.T) {
	m := &K8sModule{}
	if m.ID() != "k8s" {
		t.Errorf("ID = %q, want k8s", m.ID())
	}
}

func TestK8sModuleSeverity(t *testing.T) {
	m := &K8sModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestK8sModuleInit(t *testing.T) {
	m := &K8sModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestK8sModuleScanGraceful(t *testing.T) {
	m := &K8sModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
