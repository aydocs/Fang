package websocket

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestWebSocketModuleID(t *testing.T) {
	m := &WebSocketModule{}
	if m.ID() != "websocket" {
		t.Errorf("ID = %q, want websocket", m.ID())
	}
}

func TestWebSocketModuleSeverity(t *testing.T) {
	m := &WebSocketModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestWebSocketModuleInit(t *testing.T) {
	m := &WebSocketModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestWebSocketScanGraceful(t *testing.T) {
	m := &WebSocketModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "ws://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
