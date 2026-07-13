package terraform

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type TerraformModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *TerraformModule) ID() string   { return "terraform" }
func (m *TerraformModule) Name() string { return "Terraform State & Config Exposure" }
func (m *TerraformModule) Description() string {
	return "Detects exposed Terraform state files, backend configs, and plan files on web servers"
}
func (m *TerraformModule) Severity() models.Severity { return models.Critical }

func (m *TerraformModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *TerraformModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkStateFiles(ctx, target)...)
	findings = append(findings, m.checkBackendConfig(ctx, target)...)
	findings = append(findings, m.checkPlanEndpoints(ctx, target)...)
	findings = append(findings, m.checkGitLeaks(ctx, target)...)

	return findings, nil
}

func (m *TerraformModule) checkStateFiles(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	statePaths := []string{
		"/terraform.tfstate", "/terraform.tfstate.backup", "/terraform.tfvars",
		"/terraform.tfvars.json", "/terraform.tfvars.enc", "/terraform.tf",
		"/main.tf", "/outputs.tf", "/variables.tf", "/provider.tf",
		"/backend.tf", "/versions.tf", "/.terraform/terraform.tfstate",
		"/terraform/terraform.tfstate", "/state/terraform.tfstate",
	}
	for _, path := range statePaths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := resp.Body
			lower := strings.ToLower(body)
			if strings.Contains(lower, "terraform") || strings.Contains(lower, "provider") || strings.Contains(lower, "resource") || strings.Contains(lower, "variable") || strings.Contains(lower, "output") || strings.Contains(lower, "backend") || strings.Contains(lower, "required_providers") {
				title := "Terraform State File Exposed"
				sev := models.Critical
				if strings.Contains(path, ".tfvars") {
					title = "Terraform Variables File Exposed"
					sev = models.Critical
				} else if strings.Contains(path, ".tf") && !strings.Contains(path, ".tfstate") {
					title = "Terraform Source File Exposed"
					sev = models.High
				}
				findings = append(findings, &models.Finding{
					Title:       title,
					Severity:    sev,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("Terraform file %s accessible with content containing Terraform keywords", path),
					Description: "Terraform configuration or state files are exposed on the web server, leaking infrastructure configuration, provider credentials, and sensitive variables.",
					Remediation: "Block .tf, .tfstate, and .tfvars files in web server config. Store state remotely with encryption. Use .gitignore to exclude these files.",
					CWEID:       "CWE-200",
					ModuleID:    "terraform",
				})
			}
		}
	}
	return findings
}

func (m *TerraformModule) checkBackendConfig(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	backendPaths := []string{
		"/terraform/backend.tf", "/backend.tf", "/.terraform/backend.tf",
		"/terraform/backend.tf.backend", "/backend.tf.backend",
		"/terraform/config.tf", "/config.tf",
	}
	for _, path := range backendPaths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "backend") || strings.Contains(body, "s3") || strings.Contains(body, "bucket") || strings.Contains(body, "key") || strings.Contains(body, "dynamodb") || strings.Contains(body, "terraform") {
				findings = append(findings, &models.Finding{
					Title:       "Terraform Backend Configuration Exposed",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("Backend config file %s exposed with backend configuration data", path),
					Description: "Terraform backend configuration is exposed, potentially revealing state storage locations, bucket names, and access keys.",
					Remediation: "Block .backend files in web server config. Use remote state with encryption and never store backend configs in web-accessible directories.",
					CWEID:       "CWE-200",
					ModuleID:    "terraform",
				})
			}
		}
	}
	return findings
}

func (m *TerraformModule) checkPlanEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	planPaths := []string{
		"/plan", "/apply", "/terraform/plan", "/terraform/apply",
		"/terraform/plan.json", "/plan.json", "/apply.json",
		"/terraform/plan.out", "/plan.out",
	}
	for _, path := range planPaths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "terraform") || strings.Contains(body, "plan") || strings.Contains(body, "apply") || strings.Contains(body, "resource") || strings.Contains(body, "provider") {
				findings = append(findings, &models.Finding{
					Title:       "Terraform Plan/Apply Endpoint Exposed",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("Terraform plan/apply endpoint %s returned 200 with Terraform content", path),
					Description: "Terraform plan or apply endpoints are exposed, potentially allowing attackers to view infrastructure changes or trigger infrastructure modifications.",
					Remediation: "Remove plan/apply endpoints from production web servers. Use CI/CD pipelines with proper authentication for Terraform operations.",
					CWEID:       "CWE-200",
					ModuleID:    "terraform",
				})
			}
		}
	}
	return findings
}

func (m *TerraformModule) checkGitLeaks(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	gitPaths := []string{
		"/.git/config", "/.git/HEAD", "/.git/index",
		"/.git/refs/heads/master", "/.git/refs/heads/main",
	}
	for _, path := range gitPaths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := resp.Body
			if strings.Contains(body, "ref:") || strings.Contains(body, "repositoryformatversion") || strings.Contains(body, "master") {
				findings = append(findings, &models.Finding{
					Title:       "Git Repository Exposed with Terraform Files",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("Git metadata accessible at %s - repository may contain Terraform files", path),
					Description: "A .git directory is exposed on the web server. If this repository contains Terraform files, all infrastructure configuration and state is leaked.",
					Remediation: "Remove .git directories from production web roots. Use .gitignore for Terraform files and never deploy .git folders.",
					CWEID:       "CWE-200",
					ModuleID:    "terraform",
				})
			}
		}
	}
	return findings
}

func init() {
	engine.GetRegistry().Register(&TerraformModule{})
}
