package workflow

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

type Workflow struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Enabled   bool           `json:"enabled"`
	Trigger   TriggerConfig  `json:"trigger"`
	Actions   []ActionConfig `json:"actions"`
	CreatedAt time.Time      `json:"created_at"`
}

type TriggerConfig struct {
	Type       TriggerType       `json:"type"`
	Conditions map[string]string `json:"conditions"`
}

type TriggerType string

const (
	TriggerScanComplete TriggerType = "scan_complete"
	TriggerFindingFound TriggerType = "finding_found"
	TriggerSeverityMet  TriggerType = "severity_met"
	TriggerSchedule     TriggerType = "schedule"
	TriggerNewTarget    TriggerType = "new_target"
)

type ActionConfig struct {
	Type   ActionType        `json:"type"`
	Config map[string]string `json:"config"`
}

type ActionType string

const (
	ActionWebhook      ActionType = "webhook"
	ActionSlackNotify  ActionType = "slack_notify"
	ActionEmailNotify  ActionType = "email_notify"
	ActionJiraIssue    ActionType = "jira_issue"
	ActionGitHubIssue  ActionType = "github_issue"
	ActionScriptExec   ActionType = "script_exec"
	ActionNotification ActionType = "notification"
)

type Engine struct {
	workflows []*Workflow
	mu        sync.RWMutex
}

func NewEngine() *Engine {
	return &Engine{
		workflows: make([]*Workflow, 0),
	}
}

func (e *Engine) Add(w *Workflow) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if w.ID == "" {
		return fmt.Errorf("workflow id is required")
	}
	for _, existing := range e.workflows {
		if existing.ID == w.ID {
			return fmt.Errorf("workflow %s already exists", w.ID)
		}
	}
	e.workflows = append(e.workflows, w)
	return nil
}

func (e *Engine) Remove(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i, w := range e.workflows {
		if w.ID == id {
			e.workflows = append(e.workflows[:i], e.workflows[i+1:]...)
			return
		}
	}
}

func (e *Engine) List() []*Workflow {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*Workflow, len(e.workflows))
	copy(result, e.workflows)
	return result
}

func (e *Engine) Execute(ctx context.Context, trigger TriggerType, data map[string]interface{}) {
	e.mu.RLock()
	matching := make([]*Workflow, 0)
	for _, w := range e.workflows {
		if w.Enabled && w.Trigger.Type == trigger {
			matching = append(matching, w)
		}
	}
	e.mu.RUnlock()

	if len(matching) == 0 {
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	for _, w := range matching {
		wg.Add(1)
		sem <- struct{}{}
		go func(wf *Workflow) {
			defer wg.Done()
			defer func() { <-sem }()

			for _, action := range wf.Actions {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if err := runAction(ctx, action, data); err != nil {
					log.Printf("[workflow] action %s failed for workflow %s: %v", action.Type, wf.ID, err)
				}
			}
		}(w)
	}

	wg.Wait()
}

func runAction(ctx context.Context, action ActionConfig, data map[string]interface{}) error {
	switch action.Type {
	case ActionWebhook:
		return runWebhook(ctx, action.Config, data)
	case ActionSlackNotify:
		return runSlackNotify(ctx, action.Config, data)
	case ActionEmailNotify:
		return runEmailNotify(ctx, action.Config, data)
	case ActionJiraIssue:
		return runJiraIssue(ctx, action.Config, data)
	case ActionGitHubIssue:
		return runGitHubIssue(ctx, action.Config, data)
	case ActionScriptExec:
		return runScriptExec(ctx, action.Config, data)
	case ActionNotification:
		return runNotification(ctx, action.Config, data)
	default:
		return fmt.Errorf("unknown action type: %s", action.Type)
	}
}
