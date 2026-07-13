package payment

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestPaymentModuleID(t *testing.T) {
	m := &PaymentModule{}
	if m.ID() != "payment" {
		t.Errorf("ID = %q, want payment", m.ID())
	}
}

func TestPaymentModuleSeverity(t *testing.T) {
	m := &PaymentModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestPaymentModuleInit(t *testing.T) {
	m := &PaymentModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestPaymentScanGraceful(t *testing.T) {
	m := &PaymentModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
