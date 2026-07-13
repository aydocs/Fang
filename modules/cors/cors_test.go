package cors

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestCORSModuleID(t *testing.T) {
	m := &CORSModule{}
	if m.ID() != "cors" {
		t.Errorf("ID = %q, want cors", m.ID())
	}
}

func TestCORSModuleSeverity(t *testing.T) {
	m := &CORSModule{}
	if m.Severity() != models.Medium {
		t.Errorf("Severity = %d, want Medium", m.Severity())
	}
}

func TestCORSModuleInit(t *testing.T) {
	m := &CORSModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}
