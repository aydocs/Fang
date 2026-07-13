package deser

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestDeserModuleID(t *testing.T) {
	m := &DeserModule{}
	if m.ID() != "deser" {
		t.Errorf("ID = %q, want deser", m.ID())
	}
}

func TestDeserModuleInit(t *testing.T) {
	m := &DeserModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestDeserScanGraceful(t *testing.T) {
	m := &DeserModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
