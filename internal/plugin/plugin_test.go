package plugin

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aydocs/fang/pkg/models"
)

type testModule struct{}

func (t *testModule) ID() string                                      { return "test-module" }
func (t *testModule) Name() string                                    { return "Test Module" }
func (t *testModule) Description() string                             { return "A test module" }
func (t *testModule) Severity() models.Severity                       { return models.Medium }
func (t *testModule) Init(ctx context.Context, cfg interface{}) error { return nil }
func (t *testModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	return nil, nil
}

func TestNewManager(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
}

func TestManagerLoadAll(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "testplugin")
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		t.Fatal(err)
	}
	manifest := `id: test-plugin
name: Test Plugin
version: 1.0.0
author: test
description: A test plugin
type: module
min_version: 1.0.0`
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.yaml"), []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}

	m := NewManager(dir)
	if err := m.LoadAll(); err != nil {
		t.Fatalf("LoadAll failed: %v", err)
	}

	p := m.Get("test-plugin")
	if p == nil {
		t.Fatal("expected plugin to be loaded")
	}
	if p.Manifest.ID != "test-plugin" {
		t.Errorf("manifest id = %s, want test-plugin", p.Manifest.ID)
	}
}

func TestManagerRegister(t *testing.T) {
	m := NewManager(t.TempDir())
	p := &Plugin{
		Manifest: Manifest{
			ID:   "custom",
			Name: "Custom",
			Type: TypeModule,
		},
	}
	if err := m.Register(p); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if err := m.Register(p); err == nil {
		t.Error("expected error on duplicate registration")
	}
}

func TestManagerList(t *testing.T) {
	m := NewManager(t.TempDir())
	plugins := m.List()
	if plugins == nil {
		t.Error("List() should return empty slice, not nil")
	}
	if len(plugins) != 0 {
		t.Errorf("got %d plugins, want 0", len(plugins))
	}

	m.Register(&Plugin{
		Manifest: Manifest{ID: "a", Name: "A", Type: TypeModule},
	})
	m.Register(&Plugin{
		Manifest: Manifest{ID: "b", Name: "B", Type: TypePayload},
	})
	if len(m.List()) != 2 {
		t.Errorf("got %d plugins, want 2", len(m.List()))
	}
}

func TestManagerUnload(t *testing.T) {
	m := NewManager(t.TempDir())
	m.Register(&Plugin{
		Manifest: Manifest{ID: "test", Name: "Test", Type: TypeModule},
	})
	if m.Get("test") == nil {
		t.Fatal("expected plugin to exist")
	}
	m.Unload("test")
	if m.Get("test") != nil {
		t.Error("expected plugin to be unloaded")
	}
}

func TestManagerGet(t *testing.T) {
	m := NewManager(t.TempDir())
	m.Register(&Plugin{
		Manifest: Manifest{ID: "find-me", Name: "Find Me", Type: TypeReporter},
	})
	if m.Get("find-me") == nil {
		t.Error("Get returned nil for existing plugin")
	}
	if m.Get("nonexistent") != nil {
		t.Error("Get should return nil for nonexistent plugin")
	}
}

func TestPluginRegisterNil(t *testing.T) {
	m := NewManager(t.TempDir())
	if err := m.Register(nil); err == nil {
		t.Error("expected error for nil plugin")
	}
}

func TestPluginRegisterEmptyID(t *testing.T) {
	m := NewManager(t.TempDir())
	if err := m.Register(&Plugin{Manifest: Manifest{}}); err == nil {
		t.Error("expected error for empty ID")
	}
}

func TestPluginWithModule(t *testing.T) {
	var _ Module = (*testModule)(nil)
}
