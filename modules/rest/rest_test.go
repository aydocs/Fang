package rest

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestRESTModuleID(t *testing.T) {
	m := &RESTModule{}
	if m.ID() != "rest" {
		t.Errorf("ID = %q, want rest", m.ID())
	}
}

func TestRESTModuleSeverity(t *testing.T) {
	m := &RESTModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestRESTModuleInit(t *testing.T) {
	m := &RESTModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestRESTModuleScanGraceful(t *testing.T) {
	m := &RESTModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
