package lfi

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestLFIModuleID(t *testing.T) {
	m := &LFIModule{}
	if m.ID() != "lfi" {
		t.Errorf("ID = %q, want lfi", m.ID())
	}
}

func TestLFIModuleSeverity(t *testing.T) {
	m := &LFIModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestLFIModuleInit(t *testing.T) {
	m := &LFIModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestLFIScanGraceful(t *testing.T) {
	m := &LFIModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
