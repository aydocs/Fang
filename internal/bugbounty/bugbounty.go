package bugbounty

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aydocs/fang/pkg/models"
)

type Platform string

const (
	HackerOne Platform = "hackerone"
	Bugcrowd  Platform = "bugcrowd"
	Intigriti Platform = "intigriti"
	YesWeHack Platform = "yeswehack"
)

type BugBountyConfig struct {
	Platform  Platform `json:"platform"`
	Username  string   `json:"username"`
	APIKey    string   `json:"api_key"`
	ProgramID string   `json:"program_id"`
}

type Client struct {
	config *BugBountyConfig
	client *http.Client
}

func New(cfg *BugBountyConfig) *Client {
	return &Client{
		config: cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) CreateDraftReport(ctx context.Context, finding *models.Finding) (string, error) {
	switch c.config.Platform {
	case HackerOne:
		return c.createHackerOneDraft(ctx, finding)
	case Bugcrowd:
		return c.createBugcrowdDraft(ctx, finding)
	case Intigriti:
		return c.createIntigritiDraft(ctx, finding)
	case YesWeHack:
		return c.createYesWeHackDraft(ctx, finding)
	default:
		return "", fmt.Errorf("unsupported platform: %s", c.config.Platform)
	}
}

func (c *Client) SubmitReport(ctx context.Context, draftID string) error {
	switch c.config.Platform {
	case HackerOne:
		return c.submitHackerOne(ctx, draftID)
	case Bugcrowd:
		return c.submitBugcrowd(ctx, draftID)
	case Intigriti:
		return c.submitIntigriti(ctx, draftID)
	case YesWeHack:
		return c.submitYesWeHack(ctx, draftID)
	default:
		return fmt.Errorf("unsupported platform: %s", c.config.Platform)
	}
}

func (c *Client) ListPrograms() ([]string, error) {
	switch c.config.Platform {
	case HackerOne:
		return c.listHackerOnePrograms()
	case Bugcrowd:
		return c.listBugcrowdPrograms()
	case Intigriti:
		return c.listIntigritiPrograms()
	case YesWeHack:
		return c.listYesWeHackPrograms()
	default:
		return nil, fmt.Errorf("unsupported platform: %s", c.config.Platform)
	}
}

func (c *Client) createHackerOneDraft(ctx context.Context, finding *models.Finding) (string, error) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "report",
			"attributes": map[string]interface{}{
				"title": finding.Title,
				"vulnerability_information": fmt.Sprintf(
					"**Description:** %s\n\n**URL:** %s\n\n**Parameter:** %s\n\n**Payload:** %s\n\n**Evidence:** %s\n\n**Remediation:** %s",
					finding.Description, finding.URL, finding.Parameter, finding.Payload, finding.Evidence, finding.Remediation,
				),
				"severity_rating": finding.Severity.String(),
				"cwe":             map[string]string{"cwe_id": finding.CWEID},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.hackerone.com/v1/reports", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	c.auth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("hackerone returned status %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}

	return result.Data.ID, nil
}

func (c *Client) submitHackerOne(ctx context.Context, draftID string) error {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "report-submission",
		},
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("https://api.hackerone.com/v1/reports/%s/submit", draftID),
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.auth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("hackerone submit returned %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) listHackerOnePrograms() ([]string, error) {
	req, err := http.NewRequest("GET", "https://api.hackerone.com/v1/programs", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	c.auth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				Name string `json:"name"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	programs := make([]string, len(result.Data))
	for i, p := range result.Data {
		programs[i] = fmt.Sprintf("%s (%s)", p.Attributes.Name, p.ID)
	}
	return programs, nil
}

func (c *Client) createBugcrowdDraft(ctx context.Context, finding *models.Finding) (string, error) {
	body, err := json.Marshal(map[string]interface{}{
		"title": finding.Title,
		"vulnerability_details": fmt.Sprintf(
			"**Description:** %s\n\n**URL:** %s\n\n**Parameter:** %s\n\n**Payload:** %s\n\n**Evidence:** %s\n\n**Remediation:** %s",
			finding.Description, finding.URL, finding.Parameter, finding.Payload, finding.Evidence, finding.Remediation,
		),
		"severity": finding.Severity.String(),
		"cwe":      finding.CWEID,
		"program":  map[string]string{"id": c.config.ProgramID},
	})
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.bugcrowd.com/submissions", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	c.auth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("bugcrowd returned status %d", resp.StatusCode)
	}

	var result struct {
		Id string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	return result.Id, nil
}

func (c *Client) submitBugcrowd(ctx context.Context, draftID string) error {
	body, _ := json.Marshal(map[string]interface{}{"state": "submitted"})
	req, err := http.NewRequestWithContext(ctx, "PATCH",
		fmt.Sprintf("https://api.bugcrowd.com/submissions/%s", draftID), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.auth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("bugcrowd submit returned %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) listBugcrowdPrograms() ([]string, error) {
	req, err := http.NewRequest("GET", "https://api.bugcrowd.com/programs", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	c.auth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Programs []struct {
			Id   string `json:"id"`
			Name string `json:"name"`
		} `json:"programs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	programs := make([]string, len(result.Programs))
	for i, p := range result.Programs {
		programs[i] = fmt.Sprintf("%s (%s)", p.Name, p.Id)
	}
	return programs, nil
}

func (c *Client) createIntigritiDraft(ctx context.Context, finding *models.Finding) (string, error) {
	body, err := json.Marshal(map[string]interface{}{
		"title": finding.Title,
		"description": fmt.Sprintf(
			"**Description:** %s\n\n**URL:** %s\n\n**Parameter:** %s\n\n**Payload:** %s\n\n**Evidence:** %s\n\n**Remediation:** %s",
			finding.Description, finding.URL, finding.Parameter, finding.Payload, finding.Evidence, finding.Remediation,
		),
		"severity":           finding.Severity.String(),
		"vulnerability_type": finding.CWEID,
	})
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("https://api.intigriti.com/programs/%s/submissions/draft", c.config.ProgramID),
		bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.auth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("intigriti returned status %d", resp.StatusCode)
	}

	var result struct {
		Submission struct {
			Id string `json:"id"`
		} `json:"submission"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	return result.Submission.Id, nil
}

func (c *Client) submitIntigriti(ctx context.Context, draftID string) error {
	req, err := http.NewRequestWithContext(ctx, "PUT",
		fmt.Sprintf("https://api.intigriti.com/programs/%s/submissions/%s/submit", c.config.ProgramID, draftID), nil)
	if err != nil {
		return err
	}
	c.auth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("intigriti submit returned %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) listIntigritiPrograms() ([]string, error) {
	req, err := http.NewRequest("GET", "https://api.intigriti.com/programs", nil)
	if err != nil {
		return nil, err
	}
	c.auth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var programs []struct {
		Id   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&programs); err != nil {
		return nil, err
	}

	out := make([]string, len(programs))
	for i, p := range programs {
		out[i] = fmt.Sprintf("%s (%s)", p.Name, p.Id)
	}
	return out, nil
}

func (c *Client) createYesWeHackDraft(ctx context.Context, finding *models.Finding) (string, error) {
	body, err := json.Marshal(map[string]interface{}{
		"title":              finding.Title,
		"severity":           finding.Severity.String(),
		"vulnerability_type": finding.CWEID,
		"description": fmt.Sprintf(
			"**Description:** %s\n\n**URL:** %s\n\n**Parameter:** %s\n\n**Payload:** %s\n\n**Evidence:** %s\n\n**Remediation:** %s",
			finding.Description, finding.URL, finding.Parameter, finding.Payload, finding.Evidence, finding.Remediation,
		),
	})
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("https://api.yeswehack.com/programs/%s/reports", c.config.ProgramID),
		bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.auth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("yeswehack returned status %d", resp.StatusCode)
	}

	var result struct {
		Report struct {
			Id string `json:"id"`
		} `json:"report"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	return result.Report.Id, nil
}

func (c *Client) submitYesWeHack(ctx context.Context, draftID string) error {
	body, _ := json.Marshal(map[string]interface{}{"status": "submitted"})
	req, err := http.NewRequestWithContext(ctx, "PATCH",
		fmt.Sprintf("https://api.yeswehack.com/programs/%s/reports/%s", c.config.ProgramID, draftID),
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.auth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("yeswehack submit returned %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) listYesWeHackPrograms() ([]string, error) {
	req, err := http.NewRequest("GET", "https://api.yeswehack.com/programs", nil)
	if err != nil {
		return nil, err
	}
	c.auth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var programs []struct {
		Id   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&programs); err != nil {
		return nil, err
	}

	out := make([]string, len(programs))
	for i, p := range programs {
		out[i] = fmt.Sprintf("%s (%s)", p.Name, p.Id)
	}
	return out, nil
}

func (c *Client) auth(req *http.Request) {
	switch c.config.Platform {
	case HackerOne:
		req.SetBasicAuth(c.config.APIKey, "")
	case Bugcrowd:
		req.Header.Set("Authorization", "Token "+c.config.APIKey)
	default:
		req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	}
}
