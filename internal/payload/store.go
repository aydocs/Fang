package payload

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type Store struct {
	categories map[string]*Category
	mu         sync.RWMutex
}

type Category struct {
	Name     string   `yaml:"name"`
	VulnType string   `yaml:"vuln_type"`
	Payloads []*Entry `yaml:"payloads"`
}

type Entry struct {
	ID      string            `yaml:"id"`
	Value   string            `yaml:"value"`
	Tags    []string          `yaml:"tags"`
	Encoder string            `yaml:"encoder,omitempty"`
	Params  map[string]string `yaml:"params,omitempty"`
}

func NewStore() *Store {
	return &Store{
		categories: make(map[string]*Category),
	}
}

func (s *Store) Load(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}

		var cat Category
		if err := yaml.Unmarshal(data, &cat); err != nil {
			continue
		}

		s.mu.Lock()
		s.categories[cat.Name] = &cat
		s.mu.Unlock()
	}

	return nil
}

func (s *Store) LoadFromFS(fsys fs.FS) error {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		data, err := fs.ReadFile(fsys, entry.Name())
		if err != nil {
			continue
		}

		var cat Category
		if err := yaml.Unmarshal(data, &cat); err != nil {
			continue
		}

		s.mu.Lock()
		s.categories[cat.Name] = &cat
		s.mu.Unlock()
	}

	return nil
}

func (s *Store) GetByVulnType(vulnType string) []*Category {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Category
	for _, cat := range s.categories {
		if strings.EqualFold(cat.VulnType, vulnType) {
			result = append(result, cat)
		}
	}
	return result
}

func (s *Store) Get(name string) *Category {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.categories[name]
}

func (s *Store) All() []*Category {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Category, 0, len(s.categories))
	for _, cat := range s.categories {
		result = append(result, cat)
	}
	return result
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.categories)
}
