package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type GitHubConfig struct {
	Token string `json:"token"`
	Owner string `json:"owner"`
	Repo  string `json:"repo"`
}

type GitHubClient struct {
	config *GitHubConfig
	client *fanghttp.Client
}

func NewGitHubClient(cfg *GitHubConfig) *GitHubClient {
	c := fanghttp.NewClient(
		fanghttp.WithTimeout(30*time.Second),
		fanghttp.WithRetries(2),
		fanghttp.WithFollowRedirects(true),
	)
	return &GitHubClient{
		config: cfg,
		client: c,
	}
}

func (c *GitHubClient) apiURL(path string) string {
	return "https://api.github.com" + path
}

func (c *GitHubClient) authHeaders() map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + c.config.Token,
		"Content-Type":  "application/json",
		"Accept":        "application/vnd.github.v3+json",
	}
}

func (c *GitHubClient) CreateIssue(ctx context.Context, finding *models.Finding, targetURL string) (string, error) {
	body := map[string]interface{}{
		"title": fmt.Sprintf("[Fang] %s", finding.Title),
		"body": fmt.Sprintf("## Finding: %s\n\n**Target**: %s\n**Module**: %s\n**Severity**: %s\n**CWE**: %s\n\n%s\n\n**Evidence**:\n```\n%s\n```",
			finding.Title, targetURL, finding.ModuleID, finding.Severity.String(), finding.CWEID,
			finding.Description, truncate(finding.Evidence, 30000)),
		"labels": []string{"fang", "security"},
	}

	data, _ := json.Marshal(body)
	resp, err := c.client.DoRaw("POST", c.apiURL(fmt.Sprintf("/repos/%s/%s/issues", c.config.Owner, c.config.Repo)), c.authHeaders(), string(data))
	if err != nil {
		return "", fmt.Errorf("github create issue: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("github create issue: status %d: %s", resp.StatusCode, truncate(resp.Body, 500))
	}

	var result struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
		return "", fmt.Errorf("github parse response: %w", err)
	}
	return strconv.Itoa(result.Number), nil
}

func (c *GitHubClient) FindIssue(ctx context.Context, findingID string) (string, error) {
	resp, err := c.client.DoRaw("GET", c.apiURL(fmt.Sprintf("/repos/%s/%s/issues?labels=fang&state=all&per_page=50", c.config.Owner, c.config.Repo)), c.authHeaders(), "")
	if err != nil {
		return "", fmt.Errorf("github search: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("github search: status %d: %s", resp.StatusCode, truncate(resp.Body, 500))
	}

	var issues []struct {
		Number int    `json:"number"`
		Title  string `json:"title"`
		Body   string `json:"body"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &issues); err != nil {
		return "", fmt.Errorf("github parse issues: %w", err)
	}

	for _, issue := range issues {
		if strings.Contains(issue.Body, findingID) || strings.Contains(issue.Title, findingID) {
			return strconv.Itoa(issue.Number), nil
		}
	}
	return "", nil
}

func (c *GitHubClient) CloseIssue(ctx context.Context, issueNumber int) error {
	body := map[string]interface{}{
		"state": "closed",
	}
	data, _ := json.Marshal(body)
	resp, err := c.client.DoRaw("PATCH", c.apiURL(fmt.Sprintf("/repos/%s/%s/issues/%d", c.config.Owner, c.config.Repo, issueNumber)), c.authHeaders(), string(data))
	if err != nil {
		return fmt.Errorf("github close issue: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("github close issue: status %d: %s", resp.StatusCode, truncate(resp.Body, 500))
	}
	return nil
}
