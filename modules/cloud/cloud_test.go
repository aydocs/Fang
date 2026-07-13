package cloud

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestCloudModuleID(t *testing.T) {
	m := &CloudModule{}
	if m.ID() != "cloud" {
		t.Errorf("ID = %q, want cloud", m.ID())
	}
}

func TestCloudModuleInit(t *testing.T) {
	m := &CloudModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestCloudScanGraceful(t *testing.T) {
	m := &CloudModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
