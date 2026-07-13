package cicd

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestCicdModuleID(t *testing.T) {
	m := &CicdModule{}
	if m.ID() != "cicd" {
		t.Errorf("ID = %q, want cicd", m.ID())
	}
}

func TestCicdModuleSeverity(t *testing.T) {
	m := &CicdModule{}
	if m.Severity() != models.High {
		t.Errorf("Severity = %d, want High", m.Severity())
	}
}

func TestCicdModuleInit(t *testing.T) {
	m := &CicdModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestCicdModuleScanGraceful(t *testing.T) {
	m := &CicdModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
