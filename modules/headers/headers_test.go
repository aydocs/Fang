package headers

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestHeadersModuleID(t *testing.T) {
	m := &HeadersModule{}
	if m.ID() != "headers" {
		t.Errorf("ID = %q, want headers", m.ID())
	}
}

func TestHeadersModuleSeverity(t *testing.T) {
	m := &HeadersModule{}
	if m.Severity() != models.Info {
		t.Errorf("Severity = %d, want Info", m.Severity())
	}
}

func TestHeadersModuleInit(t *testing.T) {
	m := &HeadersModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestHeadersScanGraceful(t *testing.T) {
	m := &HeadersModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
