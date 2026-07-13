package engine

import (
	"fmt"
	"sync"

	"github.com/aydocs/fang/pkg/models"
)

var global = &Registry{modules: make(map[string]Module)}

type Registry struct {
	mu      sync.RWMutex
	modules map[string]Module
}

func GetRegistry() *Registry {
	return global
}

func (r *Registry) Register(m Module) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := m.ID()
	if _, exists := r.modules[id]; exists {
		return fmt.Errorf("module %s already registered", id)
	}
	r.modules[id] = m
	return nil
}

func (r *Registry) Get(id string) (Module, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.modules[id]
	return m, ok
}

func (r *Registry) List() []Module {
	r.mu.RLock()
	defer r.mu.RUnlock()
	list := make([]Module, 0, len(r.modules))
	for _, m := range r.modules {
		list = append(list, m)
	}
	return list
}

func (r *Registry) ListBySeverity(s models.Severity) []Module {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var list []Module
	for _, m := range r.modules {
		if m.Severity() == s {
			list = append(list, m)
		}
	}
	return list
}
