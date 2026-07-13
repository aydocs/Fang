package central

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestCentralModuleID(t *testing.T) {
	m := &CentralModule{}
	if m.ID() != "central" {
		t.Errorf("ID = %q, want central", m.ID())
	}
}

func TestCentralModuleSeverity(t *testing.T) {
	m := &CentralModule{}
	if m.Severity() != models.Medium {
		t.Errorf("Severity = %d, want Medium", m.Severity())
	}
}

func TestCentralModuleInit(t *testing.T) {
	m := &CentralModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestCentralScanGraceful(t *testing.T) {
	m := &CentralModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}

func TestCentralMakeFinding(t *testing.T) {
	m := &CentralModule{}
	f := m.makeFinding("Test Title", models.Medium, models.HighConfidence, "https://example.com", "param1", "payload", "evidence", "Test description", "Fix it", "CWE-200")
	if f.Title != "Test Title" {
		t.Errorf("Title = %q, want 'Test Title'", f.Title)
	}
	if f.Severity != models.Medium {
		t.Errorf("Severity = %d, want Medium", f.Severity)
	}
	if f.ModuleID != "central" {
		t.Errorf("ModuleID = %q, want central", f.ModuleID)
	}
}
