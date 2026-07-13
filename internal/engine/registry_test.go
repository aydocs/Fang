package engine

import (
	"context"
	"testing"

	"github.com/aydocs/fang/pkg/models"
)

type testModule struct {
	id   string
	name string
	desc string
	sev  models.Severity
}

func (m *testModule) ID() string                                  { return m.id }
func (m *testModule) Name() string                                { return m.name }
func (m *testModule) Description() string                         { return m.desc }
func (m *testModule) Severity() models.Severity                   { return m.sev }
func (m *testModule) Init(ctx context.Context, cfg *Config) error { return nil }
func (m *testModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	return nil, nil
}

func TestRegistryRegisterAndGet(t *testing.T) {
	global = &Registry{
		modules: make(map[string]Module),
	}

	m := &testModule{id: "testmod", name: "Test Module", desc: "A test", sev: 1}
	global.Register(m)

	got, ok := global.Get("testmod")
	if !ok {
		t.Fatal("expected module to be found")
	}
	if got.ID() != "testmod" {
		t.Errorf("got module id %q, want testmod", got.ID())
	}
}

func TestRegistryGetUnknown(t *testing.T) {
	global = &Registry{
		modules: make(map[string]Module),
	}

	_, ok := global.Get("nonexistent")
	if ok {
		t.Error("expected nonexistent module to not be found")
	}
}

func TestRegistryList(t *testing.T) {
	global = &Registry{
		modules: make(map[string]Module),
	}

	global.Register(&testModule{id: "a"})
	global.Register(&testModule{id: "b"})

	list := global.List()
	if len(list) != 2 {
		t.Errorf("expected 2 modules, got %d", len(list))
	}
}

func TestGetRegistry(t *testing.T) {
	r := GetRegistry()
	if r == nil {
		t.Fatal("expected non-nil registry")
	}
	r2 := GetRegistry()
	if r != r2 {
		t.Error("GetRegistry() should return singleton")
	}
}
