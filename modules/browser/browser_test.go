package browser

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestBrowserModuleID(t *testing.T) {
	m := &BrowserModule{}
	if m.ID() != "browser" {
		t.Errorf("ID = %q, want browser", m.ID())
	}
}

func TestBrowserModuleSeverity(t *testing.T) {
	m := &BrowserModule{}
	if m.Severity() != models.High {
		t.Errorf("Severity = %d, want High", m.Severity())
	}
}

func TestBrowserModuleInit(t *testing.T) {
	m := &BrowserModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}
