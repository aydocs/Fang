package git

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type GitModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *GitModule) ID() string   { return "git" }
func (m *GitModule) Name() string { return "Git & VCS Exposure" }
func (m *GitModule) Description() string {
	return "Detects exposed Git repositories, VCS metadata, and leaked credentials in source files"
}
func (m *GitModule) Severity() models.Severity { return models.Critical }

func (m *GitModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *GitModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkGitDir(ctx, target)...)
	findings = append(findings, m.checkGitFiles(ctx, target)...)
	findings = append(findings, m.checkTokenLeaks(ctx, target)...)
	findings = append(findings, m.checkOtherVCS(ctx, target)...)
	findings = append(findings, m.checkCommitEndpoints(ctx, target)...)

	return findings, nil
}

func (m *GitModule) checkGitDir(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/.git/config", "/.git/HEAD", "/.git/index",
		"/.git/refs/heads/master", "/.git/refs/heads/main",
		"/.git/logs/HEAD", "/.git/objects/info/packs",
		"/.git/packed-refs", "/.git/description",
	}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := resp.Body
			finding := &models.Finding{
				Title:       ".git Directory Exposed",
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         u,
				Evidence:    fmt.Sprintf("Git file %s accessible (status: 200, size: %d bytes)", path, resp.BodyLength),
				Description: "The .git directory is publicly exposed, allowing attackers to download the entire repository history, source code, credentials, and sensitive configuration. This is a complete source code compromise.",
				Remediation: "Block .git directory access in web server config. Remove .git from production deployments. Use .htaccess or nginx rules to deny access.",
				CWEID:       "CWE-200",
				ModuleID:    "git",
			}
			if strings.Contains(body, "ref:") || strings.Contains(body, "repositoryformatversion") || strings.Contains(body, "[core]") || strings.Contains(body, "refs/heads/") {
				finding.Evidence = fmt.Sprintf("Git repository fully exposed - %s returns valid Git metadata", path)
				finding.Title = "Git Repository Fully Exposed"
			}
			findings = append(findings, finding)
		}
	}
	return findings
}

func (m *GitModule) checkGitFiles(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/.gitignore", "/.gitattributes", "/.gitmodules",
		"/.gitkeep", "/.gitlab-ci.yml",
		"/.github/", "/.github/workflows/",
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
				Title:       "Git Configuration File Exposed",
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         u,
				Evidence:    fmt.Sprintf("Git configuration file %s exposed (size: %d bytes)", path, resp.BodyLength),
				Description: fmt.Sprintf("A Git configuration file (%s) is exposed, potentially revealing submodule URLs, build artifacts, and CI/CD pipeline configurations.", path),
				Remediation: "Block access to .git* files. Remove from production deployments. Review exposed files for sensitive data.",
				CWEID:       "CWE-200",
				ModuleID:    "git",
			}
			if strings.Contains(body, "node_modules") || strings.Contains(body, ".env") || strings.Contains(body, "secret") || strings.Contains(body, "password") || strings.Contains(body, "token") || strings.Contains(body, "key") {
				finding.Title = "Git Configuration with Sensitive Patterns Exposed"
				finding.Severity = models.Critical
				finding.Evidence = fmt.Sprintf("Git config %s exposed with sensitive patterns (e.g., .env, secrets, tokens)", path)
			}
			findings = append(findings, finding)
		}
	}
	return findings
}

func (m *GitModule) checkTokenLeaks(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	jsFiles := []string{"/app.js", "/bundle.js", "/main.js", "/index.js", "/config.js"}
	for _, path := range jsFiles {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := resp.Body
			patterns := map[string]string{
				"GitHub Token":     `ghp_[0-9a-zA-Z]{36}`,
				"GitHub OAuth":     `gho_[0-9a-zA-Z]{36}`,
				"GitHub App Token": `ghu_[0-9a-zA-Z]{36}`,
				"GitLab Token":     `glpat-[0-9a-zA-Z\-]{20,}`,
				"GitLab CI Token":  `glcicd_[0-9a-zA-Z]{20,}`,
			}
			for name, pattern := range patterns {
				re, err := regexp.Compile(pattern)
				if err != nil {
					continue
				}
				matches := re.FindAllString(body, -1)
				if len(matches) > 0 {
					maskedMatches := make([]string, len(matches))
					for i, m := range matches {
						if len(m) > 8 {
							maskedMatches[i] = m[:4] + "..." + m[len(m)-4:]
						} else {
							maskedMatches[i] = "[REDACTED]"
						}
					}
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("Exposed %s in JavaScript", name),
						Severity:    models.Critical,
						Confidence:  models.CriticalConfidence,
						URL:         u,
						Evidence:    fmt.Sprintf("Found %d %s(s) in %s: %s", len(matches), name, path, strings.Join(maskedMatches, ", ")),
						Description: fmt.Sprintf("A %s was found embedded in a JavaScript file at %s. Attackers can use these tokens to access repositories, CI/CD pipelines, and source code.", name, path),
						Remediation: "Revoke the exposed tokens immediately. Rotate all associated credentials. Use environment variables and secret managers instead of hardcoding tokens.",
						CWEID:       "CWE-522",
						ModuleID:    "git",
					})
				}
			}
		}
	}
	return findings
}

func (m *GitModule) checkOtherVCS(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	vcsPaths := []struct {
		path    string
		name    string
		indices []string
	}{
		{"/.svn/entries", "Subversion (.svn)", []string{"svn", "entries", "dir"}},
		{"/.svn/wc.db", "Subversion (.svn)", []string{"repository", "svn"}},
		{"/.svn/pristine/", "Subversion (.svn)", []string{"svn"}},
		{"/.hg/store/", "Mercurial (.hg)", []string{"hg", "mercurial"}},
		{"/.hg/requires", "Mercurial (.hg)", []string{"hg", "mercurial"}},
		{"/.bzr/", "Bazaar (.bzr)", nil},
		{"/_darcs/", "Darcs (_darcs)", nil},
	}
	for _, vcs := range vcsPaths {
		u := base + vcs.path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			matched := len(vcs.indices) == 0
			for _, ind := range vcs.indices {
				if strings.Contains(body, ind) {
					matched = true
					break
				}
			}
			if matched {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("%s Repository Exposed", vcs.name),
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("%s VCS metadata exposed at %s", vcs.name, vcs.path),
					Description: fmt.Sprintf("A %s repository directory is publicly exposed, revealing source code history, version metadata, and potential credentials.", vcs.name),
					Remediation: fmt.Sprintf("Remove %s directories from production deployments. Block access via web server rules.", vcs.name),
					CWEID:       "CWE-200",
					ModuleID:    "git",
				})
			}
		}
	}
	return findings
}

func (m *GitModule) checkCommitEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/commit", "/commits", "/api/commit", "/api/commits",
		"/git/commit", "/git/commits", "/latest-commit",
		"/revisions", "/changeset", "/changelog",
	}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "commit") || strings.Contains(body, "author") || strings.Contains(body, "committer") || strings.Contains(body, "sha") || strings.Contains(body, "hash") || strings.Contains(body, "message") || strings.Contains(body, "diff") || strings.Contains(body, "revision") {
				findings = append(findings, &models.Finding{
					Title:       "Commit / Revision History Endpoint Exposed",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("Commit history endpoint accessible at %s (matched commit metadata)", path),
					Description: fmt.Sprintf("A commit or revision history endpoint is exposed at %s. This reveals commit messages, authors, timestamps, and potentially sensitive code changes.", path),
					Remediation: "Disable commit history API endpoints in production. Use authentication for repository browsing. Remove web-based Git viewers from production.",
					CWEID:       "CWE-200",
					ModuleID:    "git",
				})
			}
		}
	}
	return findings
}

func init() {
	engine.GetRegistry().Register(&GitModule{})
}
