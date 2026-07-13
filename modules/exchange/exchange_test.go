package exchange

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestExchangeModuleID(t *testing.T) {
	m := &ExchangeModule{}
	if m.ID() != "exchange" {
		t.Errorf("ID = %q, want exchange", m.ID())
	}
}

func TestExchangeModuleSeverity(t *testing.T) {
	m := &ExchangeModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestExchangeModuleInit(t *testing.T) {
	m := &ExchangeModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestExchangeModuleScanGraceful(t *testing.T) {
	m := &ExchangeModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
