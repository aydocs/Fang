package zday

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestZeroDayModuleID(t *testing.T) {
	m := &ZeroDayModule{}
	if m.ID() != "0day" {
		t.Errorf("ID = %q, want 0day", m.ID())
	}
}

func TestZeroDayModuleName(t *testing.T) {
	m := &ZeroDayModule{}
	if m.Name() == "" {
		t.Error("Name should not be empty")
	}
}

func TestZeroDayModuleInit(t *testing.T) {
	m := &ZeroDayModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5), engine.WithRateLimit(10)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestZeroDayScanGraceful(t *testing.T) {
	m := &ZeroDayModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}

func TestZeroDayGetCVEChecks(t *testing.T) {
	m := &ZeroDayModule{}
	checks := m.getCVEChecks()
	if len(checks) == 0 {
		t.Error("expected at least 1 CVE check")
	}
	for _, c := range checks {
		if c.ID == "" {
			t.Error("CVE check has empty ID")
		}
	}
}
