package ios

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestIOSModuleID(t *testing.T) {
	m := &IOSModule{}
	if m.ID() != "ios" {
		t.Errorf("ID = %q, want ios", m.ID())
	}
}

func TestIOSModuleSeverity(t *testing.T) {
	m := &IOSModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestIOSModuleInit(t *testing.T) {
	m := &IOSModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestIOSModuleScanGraceful(t *testing.T) {
	m := &IOSModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
