package crlf

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestCRLFModuleID(t *testing.T) {
	m := &CRLFModule{}
	if m.ID() != "crlf" {
		t.Errorf("ID = %q, want crlf", m.ID())
	}
}

func TestCRLFModuleSeverity(t *testing.T) {
	m := &CRLFModule{}
	if m.Severity() != models.High {
		t.Errorf("Severity = %d, want High", m.Severity())
	}
}

func TestCRLFModuleInit(t *testing.T) {
	m := &CRLFModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestCRLFScanGraceful(t *testing.T) {
	m := &CRLFModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
