package engine

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/internal/plugin"
	"github.com/aydocs/fang/pkg/models"
)

type Engine struct {
	registry      *Registry
	config        *Config
	client        *fanghttp.Client
	logger        *Logger
	pluginManager *plugin.Manager
	mu            sync.Mutex
	stopped       bool
}

func New(cfg *Config) *Engine {
	httpClient := fanghttp.NewClient(
		fanghttp.WithTimeout(cfg.Timeout),
		fanghttp.WithRateLimit(cfg.RateLimit),
		fanghttp.WithProxy(cfg.Proxy),
		fanghttp.WithHeaders(cfg.Headers),
		fanghttp.WithCookies(cfg.Cookies),
	)
	eng := &Engine{
		registry: GetRegistry(),
		config:   cfg,
		client:   httpClient,
		logger:   NewLogger(cfg.Verbose),
	}
	eng.initPlugins()
	return eng
}

func (e *Engine) Run(ctx context.Context, target string) (*models.ScanResult, error) {
	startTime := time.Now()

	t, err := e.createTarget(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	result := &models.ScanResult{
		Target:    target,
		StartTime: startTime,
	}

	activeResults := e.runActiveStage(ctx, t)

	pluginFindings := e.runPlugins(ctx, t)

	var allFindings []*models.Finding
	for _, mr := range activeResults {
		if mr.Error != nil {
			e.logger.Error("module %s failed: %v", mr.ModuleID, mr.Error)
			continue
		}
		allFindings = append(allFindings, mr.Findings...)
	}
	allFindings = append(allFindings, pluginFindings...)

	result.Findings = allFindings
	result.EndTime = time.Now()
	result.Duration = time.Since(startTime).String()

	summary := models.Summary{}
	for _, f := range allFindings {
		summary.Add(f)
	}
	result.Summary = summary

	return result, nil
}

func (e *Engine) createTarget(target string) (*models.Target, error) {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}
	target = strings.TrimRight(target, "/")

	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	return &models.Target{
		URL:     target,
		Domain:  u.Hostname(),
		Method:  "GET",
		Headers: e.config.Headers,
		Cookies: e.config.Cookies,
	}, nil
}

func (e *Engine) initPlugins() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}
	pluginDir := filepath.Join(homeDir, ".fang", "plugins")
	e.pluginManager = plugin.NewManager(pluginDir)
	_ = e.pluginManager.LoadAll()
}

func (e *Engine) runPlugins(ctx context.Context, target *models.Target) []*models.Finding {
	if e.pluginManager == nil {
		return nil
	}

	plugins := e.pluginManager.List()
	if len(plugins) == 0 {
		return nil
	}

	e.logger.Info("running %d plugin(s)", len(plugins))

	var allFindings []*models.Finding
	for _, p := range plugins {
		select {
		case <-ctx.Done():
			return allFindings
		default:
		}
		if p.Module == nil {
			continue
		}

		e.logger.ModuleStart(p.Manifest.Name)
		start := time.Now()
		findings, err := p.Module.Scan(ctx, target)
		dur := time.Since(start)
		if err != nil {
			e.logger.Error("plugin %s error: %v", p.Manifest.Name, err)
			continue
		}
		e.logger.ModuleComplete(p.Manifest.Name, len(findings), dur)
		allFindings = append(allFindings, findings...)
	}

	return allFindings
}

func (e *Engine) runActiveStage(ctx context.Context, target *models.Target) []*models.ModuleResult {
	modules := e.filterModules(e.registry.List())
	if len(modules) == 0 {
		return nil
	}

	pool := NewWorkerPool(ctx, e.config.Threads, e.logger, e.config)
	pool.Start()

	for _, m := range modules {
		select {
		case <-ctx.Done():
			pool.Stop()
			return nil
		default:
		}
		pool.Submit(Job{Module: m, Target: target})
	}

	var results []*models.ModuleResult
	for i := 0; i < len(modules); i++ {
		select {
		case <-ctx.Done():
			pool.Stop()
			return results
		case result := <-pool.Results():
			if result != nil {
				for _, f := range result.Findings {
					if f != nil {
						if f.ModuleID == "" {
							f.ModuleID = result.ModuleID
						}
						models.EnrichFinding(f)
					}
				}
			}
			results = append(results, result)
		}
	}

	pool.Stop()
	return results
}

func (e *Engine) filterModules(modules []Module) []Module {
	var filtered []Module
	for _, m := range modules {
		id := m.ID()
		if len(e.config.Modules) > 0 {
			include := false
			for _, allowed := range e.config.Modules {
				if id == allowed {
					include = true
					break
				}
			}
			if !include {
				continue
			}
		}
		if len(e.config.ExcludeModules) > 0 {
			exclude := false
			for _, denied := range e.config.ExcludeModules {
				if id == denied {
					exclude = true
					break
				}
			}
			if exclude {
				continue
			}
		}
		if e.config.Quick && m.Severity() == models.Info {
			continue
		}
		filtered = append(filtered, m)
	}
	return filtered
}

func (e *Engine) RunModule(ctx context.Context, id string, target string) (*models.ModuleResult, error) {
	m, ok := e.registry.Get(id)
	if !ok {
		return nil, fmt.Errorf("module %s not found", id)
	}

	t, err := e.createTarget(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	if err := m.Init(ctx, e.config); err != nil {
		return nil, fmt.Errorf("module %s init failed: %w", id, err)
	}

	start := time.Now()
	findings, err := m.Scan(ctx, t)
	dur := time.Since(start)

	for _, f := range findings {
		if f != nil {
			models.EnrichFinding(f)
		}
	}

	return &models.ModuleResult{
		ModuleID:   m.ID(),
		ModuleName: m.Name(),
		Findings:   findings,
		Error:      err,
		Duration:   dur,
	}, nil
}

func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopped = true
}

func (e *Engine) TargetFromURL(rawURL string) (*models.Target, error) {
	return e.createTarget(rawURL)
}
