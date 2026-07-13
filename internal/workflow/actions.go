package workflow

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/aydocs/fang/internal/db"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/internal/integration"
)

func runWebhook(ctx context.Context, config map[string]string, data map[string]interface{}) error {
	url, ok := config["url"]
	if !ok || url == "" {
		return fmt.Errorf("webhook: url is required")
	}

	payload := map[string]interface{}{
		"event": data,
	}
	if method, ok := config["method"]; ok && method != "" {
	} else {
		config["method"] = "POST"
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook marshal: %w", err)
	}

	client := fanghttp.NewClient(
		fanghttp.WithTimeout(30 * time.Second),
	)
	_, err = client.DoRaw(config["method"], url, map[string]string{
		"Content-Type": "application/json",
	}, string(body))
	return err
}

func runSlackNotify(ctx context.Context, config map[string]string, data map[string]interface{}) error {
	webhookURL, ok := config["webhook_url"]
	if !ok || webhookURL == "" {
		cfg := integration.GetConfig()
		if cfg.Slack != nil && cfg.Slack.WebhookURL != "" {
			webhookURL = cfg.Slack.WebhookURL
		} else {
			return fmt.Errorf("slack: no webhook_url in config or integration settings")
		}
	}

	message := config["message"]
	if message == "" {
		message = "Workflow notification"
	}

	payload := map[string]interface{}{
		"text": message,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("slack marshal: %w", err)
	}

	client := fanghttp.NewClient(
		fanghttp.WithTimeout(30 * time.Second),
	)
	_, err = client.DoRaw("POST", webhookURL, map[string]string{
		"Content-Type": "application/json",
	}, string(body))
	return err
}

func runEmailNotify(ctx context.Context, config map[string]string, data map[string]interface{}) error {
	to := config["to"]
	subject := config["subject"]
	message := config["message"]

	log.Printf("[workflow] email notification: to=%s subject=%s message=%s", to, subject, message)
	return nil
}

func runJiraIssue(ctx context.Context, config map[string]string, data map[string]interface{}) error {
	cfg := integration.GetConfig()
	if cfg.Jira == nil {
		return fmt.Errorf("jira: not configured")
	}

	summary := config["summary"]
	if summary == "" {
		summary = "Workflow generated issue"
	}
	description := config["description"]

	body := map[string]interface{}{
		"fields": map[string]interface{}{
			"project": map[string]interface{}{
				"key": cfg.Jira.Project,
			},
			"summary":     summary,
			"description": description,
			"issuetype": map[string]interface{}{
				"name": cfg.Jira.IssueType,
			},
			"labels": []string{"fang", "workflow"},
		},
	}

	jsonBody, _ := json.Marshal(body)
	client := fanghttp.NewClient(
		fanghttp.WithTimeout(30 * time.Second),
	)
	auth := "Basic " + basicAuth(cfg.Jira.Username, cfg.Jira.APIToken)
	_, err := client.DoRaw("POST", strings.TrimRight(cfg.Jira.URL, "/")+"/rest/api/2/issue", map[string]string{
		"Authorization": auth,
		"Content-Type":  "application/json",
	}, string(jsonBody))
	return err
}

func runGitHubIssue(ctx context.Context, config map[string]string, data map[string]interface{}) error {
	cfg := integration.GetConfig()
	if cfg.GitHub == nil {
		return fmt.Errorf("github: not configured")
	}

	title := config["title"]
	if title == "" {
		title = "Workflow generated issue"
	}
	bodyText := config["body"]

	body := map[string]interface{}{
		"title":  title,
		"body":   bodyText,
		"labels": []string{"fang"},
	}

	jsonBody, _ := json.Marshal(body)
	client := fanghttp.NewClient(
		fanghttp.WithTimeout(30 * time.Second),
	)
	_, err := client.DoRaw("POST", fmt.Sprintf("https://api.github.com/repos/%s/%s/issues", cfg.GitHub.Owner, cfg.GitHub.Repo), map[string]string{
		"Authorization": "Bearer " + cfg.GitHub.Token,
		"Content-Type":  "application/json",
		"Accept":        "application/vnd.github.v3+json",
	}, string(jsonBody))
	return err
}

func runScriptExec(ctx context.Context, config map[string]string, data map[string]interface{}) error {
	command, ok := config["command"]
	if !ok || command == "" {
		return fmt.Errorf("script_exec: command is required")
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("script exec: %w: stderr=%s", err, stderr.String())
	}
	return nil
}

func runNotification(ctx context.Context, config map[string]string, data map[string]interface{}) error {
	title := config["title"]
	if title == "" {
		title = "Workflow Notification"
	}
	message := config["message"]
	notifType := config["type"]
	if notifType == "" {
		notifType = "workflow"
	}

	_, err := db.CreateNotification("", "", notifType, title, message, "in_app")
	return err
}

func basicAuth(username, password string) string {
	raw := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(raw))
}
