package devnull

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestDevNullModuleID(t *testing.T) {
	m := &DevNullModule{}
	if m.ID() != "devnull" {
		t.Errorf("ID = %q, want devnull", m.ID())
	}
}

func TestDevNullModuleSeverity(t *testing.T) {
	m := &DevNullModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestDevNullModuleInit(t *testing.T) {
	m := &DevNullModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestDevNullScanGraceful(t *testing.T) {
	m := &DevNullModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
