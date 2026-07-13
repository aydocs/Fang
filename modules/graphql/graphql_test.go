package graphql

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
)

func TestGraphQLModuleID(t *testing.T) {
	m := &GraphQLModule{}
	if m.ID() != "graphql" {
		t.Errorf("ID = %q, want graphql", m.ID())
	}
}

func TestGraphQLModuleInit(t *testing.T) {
	m := &GraphQLModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestGraphQLScanGraceful(t *testing.T) {
	m := &GraphQLModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}
