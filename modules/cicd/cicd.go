package cicd

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type CicdModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *CicdModule) ID() string   { return "cicd" }
func (m *CicdModule) Name() string { return "CI/CD Pipeline Exposure" }
func (m *CicdModule) Description() string {
	return "Detects exposed CI/CD systems including Jenkins, GitHub Actions, GitLab CI, and CircleCI configurations"
}
func (m *CicdModule) Severity() models.Severity { return models.High }

func (m *CicdModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *CicdModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkJenkins(ctx, target)...)
	findings = append(findings, m.checkGithubActions(ctx, target)...)
	findings = append(findings, m.checkGitlabCI(ctx, target)...)
	findings = append(findings, m.checkCircleCI(ctx, target)...)

	return findings, nil
}

func (m *CicdModule) checkJenkins(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/jenkins", "/jenkins/login", "/jenkins/api/json",
		"/jenkins/job/", "/jenkins/script",
		"/jenkins/manage", "/jenkins/configure",
		"/api/json", "/login", "/script",
		"/jnlpJars/jenkins-cli.jar",
	}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			finding := &models.Finding{
				Title:       "Jenkins CI/CD Endpoint Exposed",
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         u,
				Evidence:    fmt.Sprintf("Jenkins endpoint accessible at %s (status: 200)", path),
				Description: fmt.Sprintf("A Jenkins CI/CD endpoint is exposed at %s. Jenkins instances are prime targets for attackers due to their ability to execute arbitrary code, access credentials, and modify build pipelines.", path),
				Remediation: "Restrict Jenkins access with VPN or firewall. Enable authentication. Keep Jenkins updated. Use role-based access control. Disable the Jenkins CLI if not needed.",
				CWEID:       "CWE-200",
				ModuleID:    "cicd",
			}
			if strings.Contains(body, "jenkins") || strings.Contains(body, "jenkins version") || strings.Contains(body, "hudson") || strings.Contains(body, "Manage Jenkins") || strings.Contains(body, "jenkins") {
				finding.Evidence = fmt.Sprintf("Jenkins instance confirmed at %s - Jenkins version metadata detected", path)
			}
			if strings.Contains(body, "anonymous") && strings.Contains(body, "read") || strings.Contains(body, "overall/read") {
				finding.Title = "Jenkins - Anonymous Access Enabled"
				finding.Severity = models.Critical
				finding.Evidence = fmt.Sprintf("Jenkins anonymous access confirmed at %s", path)
				finding.Description = "Jenkins has anonymous read access enabled, allowing unauthenticated users to view jobs, builds, configurations, and potentially access credentials and artifacts."
			}
			if strings.Contains(path, "api/json") && strings.Contains(body, "jobs") {
				finding.Title = "Jenkins API - Job Listing Exposed"
				finding.Severity = models.Critical
				finding.Evidence = fmt.Sprintf("Jenkins API at %s returns job listing (jobs: %s)", path, extractJobs(body))
			}
			findings = append(findings, finding)
		}
	}
	return findings
}

func (m *CicdModule) checkGithubActions(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/.github/workflows/", "/.github/workflows/main.yml",
		"/.github/workflows/ci.yml", "/.github/workflows/deploy.yml",
		"/.github/workflows/test.yml", "/.github/workflows/release.yml",
		"/.github/workflows/build.yml", "/.github/workflows/cd.yml",
		"/.github/workflows/production.yml", "/.github/workflows/staging.yml",
		"/.github/", "/.github/dependabot.yml",
	}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "name:") && strings.Contains(body, "on:") || strings.Contains(body, "runs-on:") || strings.Contains(body, "actions/checkout") || strings.Contains(body, "github.actor") || strings.Contains(body, "secrets.") || strings.Contains(body, "uses:") {
				finding := &models.Finding{
					Title:       "GitHub Actions Workflow Exposed",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("GitHub Actions workflow file exposed at %s", path),
					Description: fmt.Sprintf("A GitHub Actions workflow file at %s is exposed, revealing CI/CD pipeline configuration, environment variables, secrets usage, and deployment logic.", path),
					Remediation: "Do not expose .github/workflows on production servers. Use private repositories for sensitive workflows. Audit workflow files for hardcoded secrets.",
					CWEID:       "CWE-200",
					ModuleID:    "cicd",
				}
				if strings.Contains(body, "secrets.") {
					finding.Title = "GitHub Actions Workflow with Secrets Exposed"
					finding.Severity = models.Critical
					finding.Evidence = fmt.Sprintf("GitHub Actions workflow at %s references GitHub secrets", path)
					finding.Description = "A GitHub Actions workflow file referencing secrets is exposed. While secrets themselves are masked, the names of secrets and how they are used provide valuable intelligence to attackers."
				}
				findings = append(findings, finding)
			}
		}
	}
	return findings
}

func (m *CicdModule) checkGitlabCI(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/.gitlab-ci.yml", "/.gitlab-ci.yaml",
		"/.gitlab/auto-deploy.yml", "/.gitlab/ci/",
		"/ci/lint", "/api/v4/projects",
	}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "stages:") || strings.Contains(body, "script:") || strings.Contains(body, "image:") || strings.Contains(body, "before_script") || strings.Contains(body, "after_script") || strings.Contains(body, "gitlab") || strings.Contains(body, "variables:") || strings.Contains(body, "only:") || strings.Contains(body, "except:") || strings.Contains(body, "artifacts:") {
				finding := &models.Finding{
					Title:       "GitLab CI Configuration Exposed",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("GitLab CI config exposed at %s", path),
					Description: fmt.Sprintf("A GitLab CI configuration file at %s is exposed, revealing the CI/CD pipeline definition, build scripts, deployment targets, and environment variables.", path),
					Remediation: "Remove CI configuration files from production builds. Use CI/CD variables instead of hardcoded values. Restrict access to pipeline configurations.",
					CWEID:       "CWE-200",
					ModuleID:    "cicd",
				}
				if strings.Contains(body, "variables:") && (strings.Contains(body, "password") || strings.Contains(body, "token") || strings.Contains(body, "secret") || strings.Contains(body, "key")) {
					finding.Title = "GitLab CI Configuration with Secrets Exposed"
					finding.Severity = models.Critical
					finding.Evidence = fmt.Sprintf("GitLab CI config at %s contains variable definitions with potential secrets (password/token/key)", path)
				}
				findings = append(findings, finding)
			}
		}
	}
	return findings
}

func (m *CicdModule) checkCircleCI(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/.circleci/config.yml", "/.circleci/",
		"/circle.yml", "/.circleci/config.yaml",
	}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "version:") && strings.Contains(body, "jobs:") || strings.Contains(body, "steps:") || strings.Contains(body, "circleci") || strings.Contains(body, "workflows:") || strings.Contains(body, "orbs:") || strings.Contains(body, "docker:") && strings.Contains(body, "steps:") {
				finding := &models.Finding{
					Title:       "CircleCI Configuration Exposed",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("CircleCI configuration exposed at %s", path),
					Description: fmt.Sprintf("A CircleCI configuration file at %s is exposed, revealing build jobs, workflow orchestration, Docker image usage, and deployment pipelines.", path),
					Remediation: "Remove .circleci/ from production deployments. Use CircleCI contexts for secrets. Audit configuration for hardcoded credentials.",
					CWEID:       "CWE-200",
					ModuleID:    "cicd",
				}
				if strings.Contains(body, "context:") || strings.Contains(body, "${") {
					finding.Title = "CircleCI Configuration with Context References Exposed"
					finding.Severity = models.Critical
					finding.Evidence = fmt.Sprintf("CircleCI config at %s references contexts or environment variables", path)
					finding.Description = "CircleCI configuration referencing contexts or environment variables is exposed. This reveals which secrets are used and how the pipeline is structured."
				}
				findings = append(findings, finding)
			}
		}
	}
	return findings
}

func extractJobs(body string) string {
	var count int
	bodyLower := strings.ToLower(body)
	idx := 0
	for {
		pos := strings.Index(bodyLower[idx:], "\"name\"")
		if pos == -1 {
			break
		}
		count++
		idx += pos + 6
	}
	if count == 0 {
		idx = 0
		for {
			pos := strings.Index(bodyLower[idx:], "\"job\"")
			if pos == -1 {
				break
			}
			count++
			idx += pos + 5
		}
	}
	return fmt.Sprintf("%d jobs found", count)
}

func init() {
	engine.GetRegistry().Register(&CicdModule{})
}
