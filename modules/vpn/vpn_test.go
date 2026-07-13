package vpn

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestVPNModuleID(t *testing.T) {
	m := &VPNModule{}
	if m.ID() != "vpn" {
		t.Errorf("ID = %q, want vpn", m.ID())
	}
}

func TestVPNModuleSeverity(t *testing.T) {
	m := &VPNModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestVPNModuleInit(t *testing.T) {
	m := &VPNModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestVPNModuleScanGraceful(t *testing.T) {
	m := &VPNModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
