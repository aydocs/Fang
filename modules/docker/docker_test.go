package docker

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestDockerModuleID(t *testing.T) {
	m := &DockerModule{}
	if m.ID() != "docker" {
		t.Errorf("ID = %q, want docker", m.ID())
	}
}

func TestDockerModuleSeverity(t *testing.T) {
	m := &DockerModule{}
	if m.Severity() != models.Critical {
		t.Errorf("Severity = %d, want Critical", m.Severity())
	}
}

func TestDockerModuleInit(t *testing.T) {
	m := &DockerModule{}
	if err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5))); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestDockerModuleScanGraceful(t *testing.T) {
	m := &DockerModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if _, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"}); err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
