package serverless

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestServerlessModuleID(t *testing.T) {
	m := &ServerlessModule{}
	if m.ID() != "serverless" {
		t.Errorf("ID = %q, want serverless", m.ID())
	}
}

func TestServerlessModuleSeverity(t *testing.T) {
	m := &ServerlessModule{}
	if m.Severity() != models.High {
		t.Errorf("Severity = %d, want High", m.Severity())
	}
}

func TestServerlessModuleInit(t *testing.T) {
	m := &ServerlessModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestServerlessModuleScanGraceful(t *testing.T) {
	m := &ServerlessModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
