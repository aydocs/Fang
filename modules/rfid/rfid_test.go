package rfid

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestRfidModuleID(t *testing.T) {
	m := &RfidModule{}
	if m.ID() != "rfid" {
		t.Errorf("ID = %q, want rfid", m.ID())
	}
}

func TestRfidModuleSeverity(t *testing.T) {
	m := &RfidModule{}
	if m.Severity() != models.High {
		t.Errorf("Severity = %d, want High", m.Severity())
	}
}

func TestRfidModuleInit(t *testing.T) {
	m := &RfidModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestRfidModuleScanGraceful(t *testing.T) {
	m := &RfidModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
