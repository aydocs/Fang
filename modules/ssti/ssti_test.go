package ssti

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestSSTIModuleID(t *testing.T) {
	m := &SSTIModule{}
	if m.ID() != "ssti" {
		t.Errorf("ID = %q, want ssti", m.ID())
	}
}

func TestSSTIModuleSeverity(t *testing.T) {
	m := &SSTIModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestSSTIModuleInit(t *testing.T) {
	m := &SSTIModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestSSTIScanGraceful(t *testing.T) {
	m := &SSTIModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
