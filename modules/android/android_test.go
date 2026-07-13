package android

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestAndroidModuleID(t *testing.T) {
	m := &AndroidModule{}
	if m.ID() != "android" {
		t.Errorf("ID = %q, want android", m.ID())
	}
}

func TestAndroidModuleSeverity(t *testing.T) {
	m := &AndroidModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestAndroidModuleInit(t *testing.T) {
	m := &AndroidModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestAndroidModuleScanGraceful(t *testing.T) {
	m := &AndroidModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
