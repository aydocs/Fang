package wifi

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestWifiModuleID(t *testing.T) {
	m := &WifiModule{}
	if m.ID() != "wifi" {
		t.Errorf("ID = %q, want wifi", m.ID())
	}
}

func TestWifiModuleSeverity(t *testing.T) {
	m := &WifiModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestWifiModuleInit(t *testing.T) {
	m := &WifiModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestWifiModuleScanGraceful(t *testing.T) {
	m := &WifiModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
