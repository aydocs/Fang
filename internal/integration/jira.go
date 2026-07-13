package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type JiraConfig struct {
	URL       string `json:"url"`
	Username  string `json:"username"`
	APIToken  string `json:"api_token"`
	Project   string `json:"project"`
	IssueType string `json:"issue_type"`
}

type JiraClient struct {
	config *JiraConfig
	client *fanghttp.Client
}

func NewJiraClient(cfg *JiraConfig) *JiraClient {
	c := fanghttp.NewClient(
		fanghttp.WithTimeout(30*time.Second),
		fanghttp.WithRetries(2),
		fanghttp.WithFollowRedirects(true),
	)
	return &JiraClient{
		config: cfg,
		client: c,
	}
}

func (c *JiraClient) authHeader() string {
	raw := c.config.Username + ":" + c.config.APIToken
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
}

func (c *JiraClient) apiURL(path string) string {
	return strings.TrimRight(c.config.URL, "/") + path
}

func (c *JiraClient) CreateIssue(ctx context.Context, finding *models.Finding, targetURL string) (string, error) {
	desc := fmt.Sprintf("h2. Finding: %s\n\n*Target*: %s\n*Module*: %s\n*Severity*: %s\n*CWE*: %s\n\n%s\n\n*Evidence*:\n{code}%s{code}",
		finding.Title, targetURL, finding.ModuleID, finding.Severity.String(), finding.CWEID,
		finding.Description, truncate(finding.Evidence, 30000))

	labels := []string{"fang", "fang-" + finding.Title}
	body := map[string]interface{}{
		"fields": map[string]interface{}{
			"project": map[string]interface{}{
				"key": c.config.Project,
			},
			"summary":     fmt.Sprintf("[Fang] %s", finding.Title),
			"description": desc,
			"issuetype": map[string]interface{}{
				"name": c.config.IssueType,
			},
			"labels": labels,
		},
	}

	data, _ := json.Marshal(body)
	resp, err := c.client.DoRaw("POST", c.apiURL("/rest/api/2/issue"), map[string]string{
		"Authorization": c.authHeader(),
		"Content-Type":  "application/json",
	}, string(data))
	if err != nil {
		return "", fmt.Errorf("jira create issue: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("jira create issue: status %d: %s", resp.StatusCode, truncate(resp.Body, 500))
	}

	var result struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
		return "", fmt.Errorf("jira parse response: %w", err)
	}
	return result.Key, nil
}

func (c *JiraClient) FindIssue(ctx context.Context, findingID string) (string, error) {
	jql := fmt.Sprintf(`labels = "fang-%s" ORDER BY created DESC`, findingID)
	searchURL := c.apiURL("/rest/api/2/search?jql=" + strings.ReplaceAll(jql, " ", "+"))
	resp, err := c.client.DoRaw("GET", searchURL, map[string]string{
		"Authorization": c.authHeader(),
		"Content-Type":  "application/json",
	}, "")
	if err != nil {
		return "", fmt.Errorf("jira search: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("jira search: status %d: %s", resp.StatusCode, truncate(resp.Body, 500))
	}

	var searchResult struct {
		Issues []struct {
			Key string `json:"key"`
		} `json:"issues"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &searchResult); err != nil {
		return "", fmt.Errorf("jira parse search: %w", err)
	}
	if len(searchResult.Issues) == 0 {
		return "", nil
	}
	return searchResult.Issues[0].Key, nil
}

func (c *JiraClient) UpdateIssueStatus(ctx context.Context, issueKey, status string) error {
	transitionsResp, err := c.client.DoRaw("GET", c.apiURL("/rest/api/2/issue/"+issueKey+"/transitions"), map[string]string{
		"Authorization": c.authHeader(),
		"Content-Type":  "application/json",
	}, "")
	if err != nil {
		return fmt.Errorf("jira get transitions: %w", err)
	}
	if transitionsResp.StatusCode < 200 || transitionsResp.StatusCode >= 300 {
		return fmt.Errorf("jira get transitions: status %d", transitionsResp.StatusCode)
	}

	var transitions struct {
		Transitions []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"transitions"`
	}
	if err := json.Unmarshal([]byte(transitionsResp.Body), &transitions); err != nil {
		return fmt.Errorf("jira parse transitions: %w", err)
	}

	var transitionID string
	for _, t := range transitions.Transitions {
		if strings.EqualFold(t.Name, status) {
			transitionID = t.ID
			break
		}
	}
	if transitionID == "" {
		return fmt.Errorf("no transition found for status: %s", status)
	}

	body := map[string]interface{}{
		"transition": map[string]interface{}{
			"id": transitionID,
		},
	}
	data, _ := json.Marshal(body)
	resp, err := c.client.DoRaw("POST", c.apiURL("/rest/api/2/issue/"+issueKey+"/transitions"), map[string]string{
		"Authorization": c.authHeader(),
		"Content-Type":  "application/json",
	}, string(data))
	if err != nil {
		return fmt.Errorf("jira update status: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("jira update status: status %d", resp.StatusCode)
	}
	return nil
}

func (c *JiraClient) AddComment(ctx context.Context, issueKey, comment string) error {
	body := map[string]interface{}{
		"body": comment,
	}
	data, _ := json.Marshal(body)
	resp, err := c.client.DoRaw("POST", c.apiURL("/rest/api/2/issue/"+issueKey+"/comment"), map[string]string{
		"Authorization": c.authHeader(),
		"Content-Type":  "application/json",
	}, string(data))
	if err != nil {
		return fmt.Errorf("jira add comment: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("jira add comment: status %d: %s", resp.StatusCode, truncate(resp.Body, 500))
	}
	return nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
