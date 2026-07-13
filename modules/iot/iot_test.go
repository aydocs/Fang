package iot

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestIotModuleID(t *testing.T) {
	m := &IotModule{}
	if m.ID() != "iot" {
		t.Errorf("ID = %q, want iot", m.ID())
	}
}

func TestIotModuleSeverity(t *testing.T) {
	m := &IotModule{}
	if m.Severity() != models.High {
		t.Errorf("Severity = %d, want High", m.Severity())
	}
}

func TestIotModuleInit(t *testing.T) {
	m := &IotModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestIotModuleScanGraceful(t *testing.T) {
	m := &IotModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
