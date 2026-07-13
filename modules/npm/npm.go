package npm

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type NpmModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *NpmModule) ID() string   { return "npm" }
func (m *NpmModule) Name() string { return "NPM & JavaScript Package Exposure" }
func (m *NpmModule) Description() string {
	return "Detects exposed npm configuration, lockfiles, registry tokens, and dependency confusion vectors"
}
func (m *NpmModule) Severity() models.Severity { return models.High }

func (m *NpmModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *NpmModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkPackageFiles(ctx, target)...)
	findings = append(findings, m.checkNpmrc(ctx, target)...)
	findings = append(findings, m.checkNodeModules(ctx, target)...)
	findings = append(findings, m.checkDepConfusion(ctx, target)...)

	return findings, nil
}

func (m *NpmModule) checkPackageFiles(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/package.json", "/package-lock.json", "/yarn.lock",
		"/pnpm-lock.yaml", "/npm-shrinkwrap.json",
		"/bower.json", "/.bowerrc", "/lerna.json",
		"/package-lock.json", "/yarn.lock",
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
				Title:       fmt.Sprintf("NPM Package File Exposed (%s)", path),
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         u,
				Evidence:    fmt.Sprintf("NPM package file %s exposed (size: %d bytes)", path, resp.BodyLength),
				Description: fmt.Sprintf("The %s file is publicly exposed, revealing all JavaScript dependencies, exact versions, integrity hashes, and the full dependency tree.", path),
				Remediation: "Remove package files from production web servers. Restrict access to manifest files. Use private npm registries with authentication.",
				CWEID:       "CWE-200",
				ModuleID:    "npm",
			}
			if strings.Contains(body, "\"resolved\"") && strings.Contains(body, "\"integrity\"") {
				finding.Title = fmt.Sprintf("NPM Lockfile with Integrity Hashes Exposed (%s)", path)
				finding.Evidence = fmt.Sprintf("Lockfile %s exposed with resolved URLs and integrity hashes for all dependencies", path)
			}
			if strings.Contains(body, "\"name\"") && strings.Contains(body, "\"version\"") && strings.Contains(body, "\"dependencies\"") {
				if strings.Contains(body, "\"scripts\"") && strings.Contains(body, "\"postinstall\"") || strings.Contains(body, "\"preinstall\"") {
					finding.Title = fmt.Sprintf("NPM Package.json with Install Scripts Exposed (%s)", path)
				}
			}
			findings = append(findings, finding)
		}
	}
	return findings
}

func (m *NpmModule) checkNpmrc(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/.npmrc", "/.yarnrc", "/.yarnrc.yml",
		"/.npm/_cacache/", "/.npm/_locks/",
		"/~/.npmrc", "/npmrc",
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
				Title:       "NPM/Yarn Configuration File Exposed",
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         u,
				Evidence:    fmt.Sprintf("Package manager config %s exposed (size: %d bytes)", path, resp.BodyLength),
				Description: fmt.Sprintf("The %s file is exposed, potentially containing registry URLs, authentication tokens, and proxy configuration.", path),
				Remediation: "Remove .npmrc and .yarnrc from production. Use environment variables for npm tokens. Never commit registry tokens to source control.",
				CWEID:       "CWE-522",
				ModuleID:    "npm",
			}
			if strings.Contains(body, "_authToken") || strings.Contains(body, "_auth") || strings.Contains(body, "//registry.npmjs.org/:_authToken") || strings.Contains(body, "npm_token") || strings.Contains(body, "NPM_TOKEN") || strings.Contains(body, "token") {
				finding.Title = "NPM Registry Authentication Token Exposed"
				finding.Severity = models.Critical
				finding.Evidence = fmt.Sprintf("NPM auth token found in %s - registry authentication credentials leaked", path)
				finding.Description = "An npm registry authentication token is exposed in the configuration file. Attackers can use this token to publish malicious packages, access private packages, or compromise the npm account."
				finding.CWEID = "CWE-522"
			}
			findings = append(findings, finding)
		}
	}
	return findings
}

func (m *NpmModule) checkNodeModules(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{
		"/node_modules/", "/node_modules/.package-lock.json",
		"/node_modules/react/package.json",
		"/static/node_modules/", "/assets/node_modules/",
		"/public/node_modules/",
	}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "\"name\"") || strings.Contains(body, "\"version\"") || strings.Contains(body, "license") || strings.Contains(body, "node_modules") {
				findings = append(findings, &models.Finding{
					Title:       "node_modules Directory Exposed",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("node_modules directory listing accessible at %s", path),
					Description: "The node_modules directory is publicly exposed, revealing all installed npm packages, their versions, and bundled source code. This increases the attack surface and may expose known vulnerable packages.",
					Remediation: "Block access to node_modules in web server configuration. Use bundlers like webpack or esbuild for production. Never deploy node_modules to production servers.",
					CWEID:       "CWE-200",
					ModuleID:    "npm",
				})
			}
		}
	}
	return findings
}

func (m *NpmModule) checkDepConfusion(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	paths := []string{"/package.json"}
	for _, path := range paths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := resp.Body
			if !strings.Contains(body, "\"dependencies\"") && !strings.Contains(body, "\"devDependencies\"") {
				continue
			}
			var suspiciousPackages []string
			lines := strings.Split(body, "\n")
			inDeps := false
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.Contains(trimmed, "\"dependencies\"") || strings.Contains(trimmed, "\"devDependencies\"") {
					inDeps = true
					continue
				}
				if inDeps && strings.Contains(trimmed, "}") {
					inDeps = false
					continue
				}
				if inDeps {
					if strings.Contains(trimmed, "\": \"") {
						parts := strings.SplitN(trimmed, "\": \"", 2)
						if len(parts) == 2 {
							pkgName := strings.Trim(parts[0], "\" ,")
							if pkgName != "" && !strings.HasPrefix(pkgName, "@") && !strings.Contains(pkgName, "/") {
								version := strings.Trim(parts[1], "\" ,")
								if !strings.HasPrefix(version, "file:") && !strings.HasPrefix(version, "git+") && !strings.HasPrefix(version, "workspace:") && !strings.HasPrefix(version, "npm:") {
									suspiciousPackages = append(suspiciousPackages, pkgName)
								}
							}
						}
					}
				}
			}
			if len(suspiciousPackages) > 10 {
				findings = append(findings, &models.Finding{
					Title:       "NPM Dependency Confusion - Potential Claimable Packages",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("Found %d packages that could be susceptible to dependency confusion attacks in package.json", len(suspiciousPackages)),
					Description: "The package.json contains unscoped packages (lacking @scope prefix) that could be claimed by attackers on the public npm registry. This is a dependency confusion supply chain attack vector.",
					Remediation: "Scope all private packages with @scope/ prefix. Use npm's allowed packages configuration. Verify package origins in CI/CD. Use lockfiles with integrity checking.",
					CWEID:       "CWE-200",
					ModuleID:    "npm",
				})
			}
		}
	}
	return findings
}

func init() {
	engine.GetRegistry().Register(&NpmModule{})
}
