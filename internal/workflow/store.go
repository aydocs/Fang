package workflow

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func SaveWorkflows(workflows []*Workflow, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("workflow dir: %w", err)
	}
	data, err := json.MarshalIndent(workflows, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal workflows: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write workflows: %w", err)
	}
	return nil
}

func LoadWorkflows(path string) ([]*Workflow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []*Workflow{}, nil
		}
		return nil, fmt.Errorf("read workflows: %w", err)
	}
	var workflows []*Workflow
	if err := json.Unmarshal(data, &workflows); err != nil {
		return nil, fmt.Errorf("parse workflows: %w", err)
	}
	if workflows == nil {
		workflows = []*Workflow{}
	}
	return workflows, nil
}
