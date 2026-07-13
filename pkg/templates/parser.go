package templates

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func LoadTemplates(dir string) ([]*Template, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read templates directory %s: %w", dir, err)
	}

	var templates []*Template
	for _, entry := range entries {
		if entry.IsDir() {
			subTemplates, err := LoadTemplates(filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}
			templates = append(templates, subTemplates...)
			continue
		}

		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		t, err := LoadTemplate(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		templates = append(templates, t)
	}

	return templates, nil
}

func LoadTemplate(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read template file %s: %w", path, err)
	}

	var tmpl Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("failed to parse template %s: %w", path, err)
	}

	if tmpl.ID == "" {
		return nil, fmt.Errorf("template %s has no id field", path)
	}

	if tmpl.Info.Name == "" {
		return nil, fmt.Errorf("template %s has no info.name field", path)
	}

	if tmpl.Info.Severity == "" {
		return nil, fmt.Errorf("template %s has no info.severity field", path)
	}

	if tmpl.Info.Remediation == "" {
		return nil, fmt.Errorf("template %s has no info.remediation field", path)
	}

	if tmpl.Info.Tags == "" {
		return nil, fmt.Errorf("template %s has no info.tags field", path)
	}

	if len(tmpl.Requests) == 0 && len(tmpl.Raw) == 0 {
		return nil, fmt.Errorf("template %s has no requests or raw field", path)
	}

	for i, req := range tmpl.Requests {
		if len(req.Matchers) == 0 {
			return nil, fmt.Errorf("template %s request %d has no matchers", path, i)
		}
	}

	return &tmpl, nil
}
