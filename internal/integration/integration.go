package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type IntegrationType string

const (
	IntegrationJira   IntegrationType = "jira"
	IntegrationGitHub IntegrationType = "github"
	IntegrationSlack  IntegrationType = "slack"
)

type TicketInfo struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type ConfigStore struct {
	Jira   *JiraConfig   `json:"jira,omitempty"`
	GitHub *GitHubConfig `json:"github,omitempty"`
	Slack  *SlackConfig  `json:"slack,omitempty"`
}

type SlackConfig struct {
	WebhookURL string `json:"webhook_url"`
}

var (
	store     *ConfigStore
	storePath string
	storeMu   sync.RWMutex
	storeOnce sync.Once
)

func storePathLocked() string {
	storeOnce.Do(func() {
		home, _ := os.UserHomeDir()
		storePath = filepath.Join(home, ".fang", "config", "integrations.json")
	})
	return storePath
}

func LoadConfig() (*ConfigStore, error) {
	storeMu.Lock()
	defer storeMu.Unlock()

	path := storePathLocked()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			s := &ConfigStore{}
			store = s
			return s, nil
		}
		return nil, fmt.Errorf("read integrations: %w", err)
	}

	s := &ConfigStore{}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("parse integrations: %w", err)
	}
	store = s
	return s, nil
}

func GetConfig() *ConfigStore {
	storeMu.RLock()
	if store != nil {
		defer storeMu.RUnlock()
		return store
	}
	storeMu.RUnlock()

	storeMu.Lock()
	defer storeMu.Unlock()
	if store != nil {
		return store
	}
	s, err := LoadConfig()
	if err != nil {
		return &ConfigStore{}
	}
	return s
}

func SaveConfig(s *ConfigStore) error {
	storeMu.Lock()
	defer storeMu.Unlock()

	path := storePathLocked()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("integrations dir: %w", err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal integrations: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write integrations: %w", err)
	}
	store = s
	return nil
}
