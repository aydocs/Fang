package arsenal

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestArsenalModuleID(t *testing.T) {
	m := &ArsenalModule{}
	if m.ID() != "arsenal" {
		t.Errorf("ID = %q, want arsenal", m.ID())
	}
}

func TestArsenalModuleSeverity(t *testing.T) {
	m := &ArsenalModule{}
	if m.Severity() != models.Medium {
		t.Errorf("Severity = %d, want Medium", m.Severity())
	}
}

func TestArsenalModuleInit(t *testing.T) {
	m := &ArsenalModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}
