package plugin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/aydocs/fang/pkg/models"
	"gopkg.in/yaml.v3"
)

type Module interface {
	ID() string
	Name() string
	Description() string
	Severity() models.Severity
	Init(ctx context.Context, cfg interface{}) error
	Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error)
}

type Type string

const (
	TypeModule   Type = "module"
	TypePayload  Type = "payload"
	TypeEncoder  Type = "encoder"
	TypeReporter Type = "reporter"
)

type Manifest struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Author      string `yaml:"author"`
	Description string `yaml:"description"`
	Type        Type   `yaml:"type"`
	MinVersion  string `yaml:"min_version"`
}

type Plugin struct {
	Manifest Manifest
	Module   Module
}

type PluginEndpoint struct {
	Path    string
	Method  string
	Handler func(ctx context.Context, params map[string]string) ([]*models.Finding, error)
}

type Manager struct {
	plugins map[string]*Plugin
	dir     string
	mu      sync.RWMutex
}

func NewManager(dir string) *Manager {
	return &Manager{
		plugins: make(map[string]*Plugin),
		dir:     dir,
	}
}

func (m *Manager) LoadAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	info, err := os.Stat(m.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return os.MkdirAll(m.dir, 0755)
		}
		return fmt.Errorf("plugin dir stat: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("plugin path is not a directory: %s", m.dir)
	}

	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return fmt.Errorf("read plugin dir: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		manifestPath := filepath.Join(m.dir, entry.Name(), "manifest.yaml")
		if _, err := os.Stat(manifestPath); err != nil {
			continue
		}
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			continue
		}
		var mf Manifest
		if err := yaml.Unmarshal(data, &mf); err != nil {
			continue
		}
		if mf.ID == "" {
			mf.ID = entry.Name()
		}
		m.plugins[mf.ID] = &Plugin{Manifest: mf}
	}

	return nil
}

func (m *Manager) List() []*Plugin {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Plugin, 0, len(m.plugins))
	for _, p := range m.plugins {
		out = append(out, p)
	}
	return out
}

func (m *Manager) Get(id string) *Plugin {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.plugins[id]
}

func (m *Manager) Register(p *Plugin) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p == nil {
		return fmt.Errorf("cannot register nil plugin")
	}
	if p.Manifest.ID == "" {
		return fmt.Errorf("plugin manifest ID is required")
	}
	if _, exists := m.plugins[p.Manifest.ID]; exists {
		return fmt.Errorf("plugin already registered: %s", p.Manifest.ID)
	}
	m.plugins[p.Manifest.ID] = p
	return nil
}

func (m *Manager) Unload(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.plugins, id)
}
