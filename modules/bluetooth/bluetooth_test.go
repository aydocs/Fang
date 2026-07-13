package bluetooth

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestBluetoothModuleID(t *testing.T) {
	m := &BluetoothModule{}
	if m.ID() != "bluetooth" {
		t.Errorf("ID = %q, want bluetooth", m.ID())
	}
}

func TestBluetoothModuleSeverity(t *testing.T) {
	m := &BluetoothModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestBluetoothModuleInit(t *testing.T) {
	m := &BluetoothModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestBluetoothModuleScanGraceful(t *testing.T) {
	m := &BluetoothModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
