package terraform

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestTerraformModuleID(t *testing.T) {
	m := &TerraformModule{}
	if m.ID() != "terraform" {
		t.Errorf("ID = %q, want terraform", m.ID())
	}
}

func TestTerraformModuleSeverity(t *testing.T) {
	m := &TerraformModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestTerraformModuleInit(t *testing.T) {
	m := &TerraformModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestTerraformModuleScanGraceful(t *testing.T) {
	m := &TerraformModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
