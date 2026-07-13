package ssrf

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestSSRFModuleID(t *testing.T) {
	m := &SSRFModule{}
	if m.ID() != "ssrf" {
		t.Errorf("ID = %q, want ssrf", m.ID())
	}
}

func TestSSRFModuleInit(t *testing.T) {
	m := &SSRFModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestSSRFScanGraceful(t *testing.T) {
	m := &SSRFModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
