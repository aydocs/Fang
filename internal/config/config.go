package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type AppConfig struct {
	Theme           string `json:"theme"`
	DefaultThreads  int    `json:"default_threads"`
	DefaultTimeout  int    `json:"default_timeout"`
	SaveReports     bool   `json:"save_reports"`
	ReportFormat    string `json:"report_format"`
	Notifications   bool   `json:"notifications_enabled"`
	NotifyOnScan    bool   `json:"notify_on_scan"`
	NotifyOnError   bool   `json:"notify_on_error"`
	AutoRefresh     bool   `json:"auto_refresh"`
	RefreshInterval int    `json:"refresh_interval"`
}

var (
	config     *AppConfig
	configPath string
	mu         sync.RWMutex
)

func Default() *AppConfig {
	return &AppConfig{
		Theme:           "dark",
		DefaultThreads:  20,
		DefaultTimeout:  10,
		SaveReports:     true,
		ReportFormat:    "html",
		Notifications:   true,
		NotifyOnScan:    true,
		NotifyOnError:   true,
		AutoRefresh:     true,
		RefreshInterval: 10,
	}
}

func Path() string {
	if configPath != "" {
		return configPath
	}
	home, _ := os.UserHomeDir()
	configPath = filepath.Join(home, ".fang", "config.json")
	return configPath
}

func Load() (*AppConfig, error) {
	mu.Lock()
	defer mu.Unlock()

	path := Path()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := Default()
			config = cfg
			if saveErr := saveLocked(); saveErr != nil {
				return cfg, nil
			}
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := Default()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	config = cfg
	return cfg, nil
}

func Get() *AppConfig {
	mu.RLock()
	defer mu.RUnlock()
	if config == nil {
		mu.RUnlock()
		cfg, err := Load()
		mu.RLock()
		if err != nil {
			return Default()
		}
		return cfg
	}
	return config
}

func Save(cfg *AppConfig) error {
	mu.Lock()
	defer mu.Unlock()
	config = cfg
	return saveLocked()
}

func saveLocked() error {
	path := Path()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("config dir: %w", err)
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
