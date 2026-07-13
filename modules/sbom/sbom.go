package sbom

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type SbomModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *SbomModule) ID() string   { return "sbom" }
func (m *SbomModule) Name() string { return "SBOM & Dependency Exposure" }
func (m *SbomModule) Description() string {
	return "Detects exposed Software Bill of Materials, dependency files, and vulnerability advisory endpoints"
}
func (m *SbomModule) Severity() models.Severity { return models.High }

func (m *SbomModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *SbomModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkSbomFiles(ctx, target)...)
	findings = append(findings, m.checkDepFiles(ctx, target)...)
	findings = append(findings, m.checkDepConfusion(ctx, target)...)
	findings = append(findings, m.checkVulnAdvisories(ctx, target)...)

	return findings, nil
}

func (m *SbomModule) checkSbomFiles(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/sbom", "/sbom.json", "/cyclonedx", "/cyclonedx.json",
		"/spdx", "/spdx.json", "/spdx.xml", "/bom.json", "/bom.xml",
		"/bom", "/dependency-graph", "/dependencies.json",
	}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "bomFormat") || strings.Contains(body, "spdxid") || strings.Contains(body, "cyclonedx") || strings.Contains(body, "sbom") || strings.Contains(body, "packages") || strings.Contains(body, "dependencies") || strings.Contains(body, "spdxVersion") || strings.Contains(body, "dataLicense") {
				findings = append(findings, &models.Finding{
					Title:       "SBOM File Exposed",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("SBOM file exposed at %s with dependency metadata", path),
					Description: "A Software Bill of Materials file is publicly exposed, revealing all dependencies, versions, and licenses used by the application. This information can be used to identify vulnerable components.",
					Remediation: "Restrict access to SBOM files. Use authenticated endpoints for SBOM distribution. Remove SBOM files from public web servers.",
					CWEID:       "CWE-200",
					ModuleID:    "sbom",
				})
			}
		}
	}
	return findings
}

func (m *SbomModule) checkDepFiles(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/package.json", "/requirements.txt", "/go.mod", "/go.sum",
		"/pom.xml", "/build.gradle", "/Gemfile", "/Gemfile.lock",
		"/Cargo.toml", "/Cargo.lock", "/composer.json", "/composer.lock",
		"/yarn.lock", "/pnpm-lock.yaml", "/Podfile", "/Podfile.lock",
		"/packages.config", "/project.assets.json",
	}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			bodyStr := resp.Body
			if strings.Contains(body, "dependencies") || strings.Contains(body, "require") || strings.Contains(body, "module ") || strings.Contains(body, "go ") && strings.Contains(body, "require") || strings.Contains(body, "modelVersion") || strings.Contains(body, "groupId") || strings.Contains(body, "artifactId") || strings.Contains(body, "packages") || strings.Contains(body, "\"name\"") || strings.Contains(body, "\"version\"") {
				findings = append(findings, &models.Finding{
					Title:       "Dependency File Exposed",
					Severity:    models.Medium,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("Dependency manifest %s exposed (size: %d bytes)", path, len(bodyStr)),
					Description: fmt.Sprintf("A dependency manifest file (%s) is publicly exposed, revealing the software supply chain, exact dependency versions, and enabling identification of known vulnerabilities.", path),
					Remediation: "Restrict access to dependency files. Use private package registries. Remove manifest files from public web server roots.",
					CWEID:       "CWE-200",
					ModuleID:    "sbom",
				})
			}
		}
	}
	return findings
}

func (m *SbomModule) checkDepConfusion(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{"/package.json", "/requirements.txt", "/Gemfile", "/Cargo.toml", "/composer.json"}
	confusionIndicators := map[string][]string{
		"npm":      {"\"dependencies\"", "\"devDependencies\"", "\"name\""},
		"pip":      {"==", ">=", "<="},
		"gem":      {"gem ", "source "},
		"cargo":    {"[dependencies]", "[package]"},
		"composer": {"\"require\"", "\"require-dev\""},
	}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := resp.Body
			for pkgType, indicators := range confusionIndicators {
				matched := true
				for _, ind := range indicators {
					if !strings.Contains(body, ind) {
						matched = false
						break
					}
				}
				if matched {
					var packages []string
					lines := strings.Split(body, "\n")
					for _, line := range lines {
						trimmed := strings.TrimSpace(line)
						if pkgType == "npm" && (strings.Contains(trimmed, "\":") || strings.Contains(trimmed, "@")) {
							if strings.Contains(trimmed, "@") && !strings.Contains(trimmed, "@scope/") && !strings.Contains(trimmed, "\"@") {
								parts := strings.SplitN(trimmed, "@", 2)
								if len(parts) == 2 {
									pkg := strings.Trim(parts[0], "\" ,")
									if pkg != "" && !strings.Contains(pkg, "version") && !strings.Contains(pkg, "name") {
										packages = append(packages, pkg)
									}
								}
							}
						}
					}
					if len(packages) > 0 {
						findings = append(findings, &models.Finding{
							Title:       "Potential Dependency Confusion Vectors",
							Severity:    models.Medium,
							Confidence:  models.MediumConfidence,
							URL:         u,
							Evidence:    fmt.Sprintf("Found %d packages in %s that may be susceptible to dependency confusion: %s", len(packages), path, strings.Join(packages[:min(len(packages), 10)], ", ")),
							Description: fmt.Sprintf("A %s dependency file at %s contains packages that could be subject to dependency confusion attacks. Private packages may be claimed by attackers in public registries.", pkgType, path),
							Remediation: "Scope all private packages properly (e.g., @scope/package for npm). Use lockfiles with integrity checks. Implement namespace isolation and verify package origins in CI/CD.",
							CWEID:       "CWE-200",
							ModuleID:    "sbom",
						})
					}
				}
			}
		}
	}
	return findings
}

func (m *SbomModule) checkVulnAdvisories(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/vulnerabilities", "/advisories", "/security/advisories",
		"/api/vulnerabilities", "/api/advisories", "/vulns",
		"/security/vulnerabilities", "/.well-known/security.txt",
		"/security/policy", "/SECURITY.md",
	}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "vulnerability") || strings.Contains(body, "cve") || strings.Contains(body, "advisory") || strings.Contains(body, "cwe") || strings.Contains(body, "affected") || strings.Contains(body, "security") || strings.Contains(body, "contact") || strings.Contains(body, "disclosure") {
				findings = append(findings, &models.Finding{
					Title:       "Vulnerability / Advisory Endpoint Exposed",
					Severity:    models.Medium,
					Confidence:  models.MediumConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("Vulnerability/advisory endpoint accessible at %s", path),
					Description: fmt.Sprintf("A vulnerability or advisory endpoint is exposed at %s. This may leak vulnerability information before patches are available or provide attackers with a roadmap of exploitable weaknesses.", path),
					Remediation: "Restrict access to advisory endpoints. Implement authentication for vulnerability disclosures. Use responsible disclosure policies with embargo periods.",
					CWEID:       "CWE-200",
					ModuleID:    "sbom",
				})
			}
		}
	}
	return findings
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func init() {
	engine.GetRegistry().Register(&SbomModule{})
}
