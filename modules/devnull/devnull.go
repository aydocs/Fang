package devnull

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type DevNullModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *DevNullModule) ID() string   { return "devnull" }
func (m *DevNullModule) Name() string { return "DevNull - Supply Chain Sabotage Module" }
func (m *DevNullModule) Description() string {
	return "Dependency confusion, repojacking, CI/CD poisoning, container backdoor, dependency scanning, pre-commit hook abuse"
}
func (m *DevNullModule) Severity() models.Severity { return models.Critical }

func (m *DevNullModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *DevNullModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkDependencyConfusion(ctx, target)...)
	findings = append(findings, m.checkCICD(ctx, target)...)
	findings = append(findings, m.checkContainer(ctx, target)...)
	findings = append(findings, m.checkSourceControl(ctx, target)...)
	findings = append(findings, m.checkRepoBackdoor(ctx, target)...)
	findings = append(findings, m.checkDepDetect(ctx, target)...)

	return findings, nil
}

func (m *DevNullModule) checkDependencyConfusion(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	manifestPaths := []string{
		"/package.json", "/package-lock.json",
		"/requirements.txt", "/Pipfile",
		"/Gemfile", "/Gemfile.lock",
		"/go.mod", "/go.sum",
		"/Cargo.toml", "/Cargo.lock",
		"/composer.json", "/composer.lock",
		"/build.gradle", "/pom.xml",
		"/yarn.lock", "/webpack.config.js",
		".env", "/.env.example",
	}

	for _, path := range manifestPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 && len(resp.Body) > 10 {
			body := resp.Body

			for _, check := range []string{"dependency", "require", "import", "from",
				"devDependencies", "dependencies"} {
				if strings.Contains(body, check) {
					fileType := "dependency"
					if strings.Contains(path, "go.mod") {
						fileType = "Go module"
					} else if strings.Contains(path, "package.json") {
						fileType = "npm package"
					} else if strings.Contains(path, "requirements.txt") {
						fileType = "Python requirements"
					} else if strings.Contains(path, "Gemfile") {
						fileType = "Ruby gem"
					} else if strings.Contains(path, "Cargo.toml") {
						fileType = "Rust crate"
					} else if strings.Contains(path, ".env") {
						fileType = "environment config"
					}

					severity := models.High
					if strings.Contains(path, ".env") {
						severity = models.Critical
					}

					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("DevNull - %s File Exposed (%s)", fileType, path),
						Severity:    severity,
						Confidence:  models.HighConfidence,
						URL:         fullURL,
						Evidence:    fmt.Sprintf("Build/dependency file exposed (status: %d, size: %d bytes)", resp.StatusCode, len(body)),
						Description: fmt.Sprintf("Dependency file %s is publicly accessible. Enables dependency confusion attacks and reveals dependency versions.", path),
						Remediation: "Block dependency files from production. Use private package registries. Implement dependency verification (SRI, lockfiles).",
						CWEID:       "CWE-200",
						ModuleID:    "devnull",
					})
					break
				}
			}
		}
	}

	return findings
}

func (m *DevNullModule) checkCICD(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	ciPaths := []string{
		"/.github/workflows", "/.gitlab-ci.yml", "/Jenkinsfile",
		"/.circleci/config.yml", "/.travis.yml", "/azure-pipelines.yml",
		"/Dockerfile", "/docker-compose.yml", "/.drone.yml",
		"/.woodpecker.yml", "/taskfile.yml", "/Makefile",
	}

	for _, path := range ciPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 && len(resp.Body) > 5 {
			for _, check := range []string{"pipeline", "deploy", "build", "test", "install",
				"env:", "environment", "secret", "token", "password", "key"} {
				if strings.Contains(resp.Body, check) {
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("DevNull - CI/CD Config Exposed (%s)", path),
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         fullURL,
						Evidence:    fmt.Sprintf("CI/CD configuration exposed (matched: %s)", check),
						Description: fmt.Sprintf("CI/CD configuration file %s exposed. May contain secrets, tokens, and deployment logic.", path),
						Remediation: "Use CI/CD secrets management. Never hardcode secrets in pipeline configs. Restrict access to pipeline files.",
						CWEID:       "CWE-200",
						ModuleID:    "devnull",
					})
					break
				}
			}
		}
	}

	return findings
}

func (m *DevNullModule) checkContainer(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	containerPaths := []string{
		"/Dockerfile", "/Dockerfile.prod", "/docker-compose.yml",
		"/.dockerignore", "/Dockerfile.dev",
		"/.containerenv", "/etc/docker/",
	}

	for _, path := range containerPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		for _, check := range []string{"FROM", "RUN", "COPY", "docker", "container",
			"image", "repository", "Docker"} {
			if strings.Contains(resp.Body, check) || strings.Contains(resp.Status, check) {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("DevNull - Container Config Exposed (%s)", path),
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("Container config exposed (matched: %s, status: %d)", check, resp.StatusCode),
					Description: fmt.Sprintf("Container configuration at %s exposed. Can be used for supply chain attacks via image backdooring.", path),
					Remediation: "Do not expose Dockerfiles in production. Use multi-stage builds. Scan container images for vulnerabilities.",
					CWEID:       "CWE-200",
					ModuleID:    "devnull",
				})
				break
			}
		}
	}

	return findings
}

func (m *DevNullModule) checkSourceControl(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	gitPaths := []string{
		"/.git/config", "/.git/HEAD", "/.git/logs/HEAD",
		"/.git/index", "/.gitignore",
		"/.svn/entries", "/.svn/wc.db",
		"/.hg/store", "/.bzr/README",
	}

	for _, path := range gitPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 && len(resp.Body) > 5 {
			for _, check := range []string{"repository", "ref:", "refs/heads", "master", "main",
				"[core]", "repositoryformatversion", "gitdir", "origin"} {
				if strings.Contains(resp.Body, check) {
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("DevNull - Git/VCS Metadata Exposed (%s)", path),
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         fullURL,
						Evidence:    fmt.Sprintf("Source control metadata exposed (matched: %s, status: %d)", check, resp.StatusCode),
						Description: fmt.Sprintf("Version control metadata file %s exposed. Full source code and history can be reconstructed.", path),
						Remediation: "Block .git and .svn directories at web server level. Remove VCS directories from production. Use .htaccess or nginx rules.",
						CWEID:       "CWE-200",
						ModuleID:    "devnull",
					})
					break
				}
			}
		}
	}

	return findings
}

func (m *DevNullModule) checkRepoBackdoor(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	hookPaths := []string{
		"/.git/hooks/pre-commit", "/.git/hooks/pre-push",
		"/.git/hooks/post-commit", "/.git/hooks/post-checkout",
		"/.git/hooks/pre-receive", "/.git/hooks/post-receive",
		"/.git/hooks/commit-msg", "/.git/hooks/prepare-commit-msg",
		"/.git/hooks/applypatch-msg", "/.git/hooks/pre-applypatch",
		"/.github/workflows/backdoor.yml",
		"/.github/workflows/evil.yml",
		"/.github/workflows/malicious.yml",
	}

	for _, path := range hookPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 && len(resp.Body) > 5 {
			body := strings.ToLower(resp.Body)
			maliciousIndicators := []string{
				"curl", "wget", "nc ", "ncat", "bash -i",
				"reverse shell", "bind shell", "exfil", "exfiltrate",
				"chmod +x", "/dev/tcp", "mkfifo",
				"python -c", "perl -e", "ruby -e",
				"base64", "openssl", "socat",
				"git clone", "npm install", "pip install",
				"eval", "exec(", "os.system",
				"subprocess", "payload", "backdoor",
				"evil", "malicious", "trojan",
				"creds", "password", "secret",
				"token", "api_key", "ssh-key",
				"crypto", "miner", "coin",
			}

			for _, ind := range maliciousIndicators {
				if strings.Contains(body, ind) {
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("DevNull - Repo Backdoor / Malicious Hook (%s)", path),
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         fullURL,
						Evidence:    fmt.Sprintf("Malicious content in hook file (matched: %s)", ind),
						Description: fmt.Sprintf("Git hook or workflow file %s contains suspicious/malicious content. Pre-commit hooks can exfiltrate credentials, CI/CD workflows can deploy malware.", path),
						Remediation: "Review all git hooks and CI/CD workflow files. Use signed commits. Implement hook allowlisting. Audit workflow changes.",
						CWEID:       "CWE-506",
						ModuleID:    "devnull",
					})
					break
				}
			}
		}
	}

	ciPoisonPaths := []string{
		"/.github/workflows/ci.yml", "/.github/workflows/deploy.yml",
		"/.github/workflows/publish.yml", "/.github/workflows/test.yml",
		"/.github/workflows/build.yml", "/.gitlab-ci.yml",
		"/Jenkinsfile", "/.circleci/config.yml",
	}

	for _, path := range ciPoisonPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 && len(resp.Body) > 5 {
			body := strings.ToLower(resp.Body)
			poisonIndicators := []string{
				"pull_request_target", "workflow_run",
				"issue_comment", "pull_request_review",
				"self-hosted", "runs-on: self-hosted",
				"ref: refs/heads/*", "push: branches: *",
				"GITHUB_TOKEN", "secrets.",
				"aws-access-key", "aws_secret",
				"docker login", "docker push",
				"npm publish", "gem push", "twine upload",
				"deploy", "production", "prod",
				"env:", "environment:",
			}

			for _, ind := range poisonIndicators {
				if strings.Contains(body, ind) {
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("DevNull - CI/CD Poison Vector (%s)", path),
						Severity:    models.Critical,
						Confidence:  models.MediumConfidence,
						URL:         fullURL,
						Evidence:    fmt.Sprintf("CI/CD poison indicator found: %s", ind),
						Description: fmt.Sprintf("CI/CD pipeline %s has poisonable triggers. pull_request_target, self-hosted runners, or broad branch patterns can allow attackers to inject malicious code.", path),
						Remediation: "Avoid pull_request_target. Use pinned actions with commit SHAs. Restrict trigger conditions. Use ephemeral runners. Implement branch protection rules.",
						CWEID:       "CWE-506",
						ModuleID:    "devnull",
					})
					break
				}
			}
		}
	}

	return findings
}

func (m *DevNullModule) checkDepDetect(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	depFiles := []struct {
		path      string
		ecosystem string
		markers   []string
	}{
		{"/package.json", "npm", []string{"\"dependencies\"", "\"devDependencies\"", "\"name\""}},
		{"/requirements.txt", "PyPI", []string{"==", ">=", "~="}},
		{"/Pipfile", "PyPI", []string{"[[source]]", "[packages]", "[dev-packages]"}},
		{"/Gemfile", "RubyGems", []string{"gem '", "source '", "ruby '"}},
		{"/Gemfile.lock", "RubyGems", []string{"GEM", "remote:", "specs:"}},
		{"/go.mod", "Go", []string{"module ", "require (", "go "}},
		{"/go.sum", "Go", []string{"h1:", "go.sum"}},
		{"/Cargo.toml", "crates.io", []string{"[dependencies]", "[package]", "edition"}},
		{"/Cargo.lock", "crates.io", []string{"[[package]]", "version =", "source"}},
		{"/composer.json", "Packagist", []string{"\"require\"", "\"require-dev\"", "\"autoload\""}},
		{"/composer.lock", "Packagist", []string{"\"packages\"", "\"content-hash\""}},
		{"/build.gradle", "Maven/Gradle", []string{"dependencies {", "implementation ", "compile "}},
		{"/pom.xml", "Maven", []string{"<dependency>", "<artifactId>", "<groupId>"}},
		{"/yarn.lock", "npm", []string{"yarn lockfile", "version:", "resolved:"}},
		{"/nuget.config", "NuGet", []string{"<packageSources>", "<add key=", "nuget.org"}},
		{"/packages.config", "NuGet", []string{"<package ", "id=", "version="}},
		{"/Podfile", "CocoaPods", []string{"platform :", "pod '", "target '"}},
		{"/mix.exs", "Hex", []string{"defp deps", "{:", "~>"}},
		{"/pubspec.yaml", "pub.dev", []string{"dependencies:", "dev_dependencies:", "sdk:"}},
		{"/Packages/manifest.json", "Unity", []string{"\"dependencies\"", "\"registry\""}},
	}

	for _, df := range depFiles {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + df.path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 || len(resp.Body) < 10 {
			continue
		}

		matched := 0
		for _, marker := range df.markers {
			if strings.Contains(resp.Body, marker) {
				matched++
			}
		}

		if matched > 0 {
			severity := models.Medium
			if df.ecosystem == "Go" || df.ecosystem == "npm" {
				severity = models.High
			}

			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("DevNull - Dependency File Detected (%s - %s)", df.ecosystem, df.path),
				Severity:    severity,
				Confidence:  models.HighConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("Dependency file %s detected for ecosystem %s (status: %d, size: %d bytes)", df.path, df.ecosystem, resp.StatusCode, len(resp.Body)),
				Description: fmt.Sprintf("Dependency file %s (%s) is accessible. Enumerates exact versions used, enabling dependency confusion and known vulnerability matching.", df.path, df.ecosystem),
				Remediation: "Block dependency manifest files from public access. Use .gitignore and web server deny rules. Verify dependency integrity with lockfiles.",
				CWEID:       "CWE-200",
				ModuleID:    "devnull",
			})
		}
	}

	return findings
}

func init() {
	engine.GetRegistry().Register(&DevNullModule{})
}
