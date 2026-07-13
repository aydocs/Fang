package helm

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type HelmModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *HelmModule) ID() string   { return "helm" }
func (m *HelmModule) Name() string { return "Helm & Chart Repository Security" }
func (m *HelmModule) Description() string {
	return "Detects exposed Helm repositories, Tiller (v2) services, and chart value leaks"
}
func (m *HelmModule) Severity() models.Severity { return models.High }

func (m *HelmModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *HelmModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkHelmRepo(ctx, target)...)
	findings = append(findings, m.checkTiller(ctx, target)...)
	findings = append(findings, m.checkValuesFiles(ctx, target)...)
	findings = append(findings, m.checkPluginExposure(ctx, target)...)

	return findings, nil
}

func (m *HelmModule) checkHelmRepo(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	repoPaths := []string{
		"/index.yaml", "/charts/", "/charts/index.yaml",
		"/helm/index.yaml", "/helm/charts/", "/repo/index.yaml",
		"/helm/charts/index.yaml", "/chart/index.yaml",
	}
	for _, path := range repoPaths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "apiVersion") || strings.Contains(body, "entries") || strings.Contains(body, "created") || strings.Contains(body, "digest") || strings.Contains(body, "urls") || strings.Contains(body, "helm") {
				findings = append(findings, &models.Finding{
					Title:       "Helm Chart Repository Exposed",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("Helm repository index accessible at %s with chart metadata", path),
					Description: "A Helm chart repository index is exposed, revealing all available charts, versions, and download URLs.",
					Remediation: "Secure Helm repositories with authentication. Use OCI-based registries with access controls. Restrict index.yaml access.",
					CWEID:       "CWE-200",
					ModuleID:    "helm",
				})
			}
		}
	}
	return findings
}

func (m *HelmModule) checkTiller(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	ports := []string{"44134"}
	tillerPaths := []string{"/", "/healthz", "/metrics"}
	for _, port := range ports {
		for _, path := range tillerPaths {
			u := fmt.Sprintf("http://%s:%s%s", target.Domain, port, path)
			resp, err := m.client.Get(u)
			if err != nil || resp == nil {
				continue
			}
			if resp.StatusCode == 200 {
				body := strings.ToLower(resp.Body)
				if strings.Contains(body, "tiller") || strings.Contains(body, "helm") || strings.Contains(body, "grpc") || strings.Contains(body, "application/grpc") {
					findings = append(findings, &models.Finding{
						Title:       "Helm Tiller (v2) Service Exposed",
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         u,
						Evidence:    fmt.Sprintf("Tiller service accessible on port 44134 at %s", path),
						Description: "Helm Tiller (v2) is exposed on port 44134. Tiller runs with cluster-admin privileges and allows any authenticated user to deploy or modify Kubernetes resources. Helm v2 is deprecated and has known vulnerabilities.",
						Remediation: "Upgrade to Helm v3 which removes Tiller entirely. If Tiller is required, enable TLS authentication and restrict access with network policies.",
						CWEID:       "CWE-306",
						ModuleID:    "helm",
					})
				}
			}
		}
	}
	return findings
}

func (m *HelmModule) checkValuesFiles(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	valuesPaths := []string{
		"/values.yaml", "/values-production.yaml", "/values-staging.yaml",
		"/values-dev.yaml", "/values-prod.yaml", "/values-test.yaml",
		"/helm/values.yaml", "/helm/values-production.yaml",
		"/chart/values.yaml", "/charts/values.yaml",
		"/config/values.yaml", "/deploy/values.yaml",
	}
	for _, path := range valuesPaths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "replicaCount") || strings.Contains(body, "image") || strings.Contains(body, "repository") || strings.Contains(body, "tag") || strings.Contains(body, "service") || strings.Contains(body, "ingress") || strings.Contains(body, "config") || strings.Contains(body, "secret") || strings.Contains(body, "password") || strings.Contains(body, "token") || strings.Contains(body, "key:") {
				title := "Helm Values File Exposed"
				sev := models.High
				if strings.Contains(body, "password") || strings.Contains(body, "token") || strings.Contains(body, "secret") || strings.Contains(body, "key:") {
					title = "Helm Values File with Secrets Exposed"
					sev = models.Critical
				}
				findings = append(findings, &models.Finding{
					Title:       title,
					Severity:    sev,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("Helm values file %s exposed with chart configuration data", path),
					Description: "Helm values files are exposed, revealing application configuration, secrets, passwords, and API keys.",
					Remediation: "Block values.yaml files in web server config. Use Helm secrets plugins or external secret stores. Never commit sensitive values to version control.",
					CWEID:       "CWE-200",
					ModuleID:    "helm",
				})
			}
		}
	}
	return findings
}

func (m *HelmModule) checkPluginExposure(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	pluginPaths := []string{
		"/helm/plugins/", "/plugins/", "/helm/plugin.yaml",
		"/kustomization.yaml", "/kustomization.yml",
		"/helm/kustomization.yaml", "/kustomize/",
	}
	for _, path := range pluginPaths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "kustomize") || strings.Contains(body, "kustomization") || strings.Contains(body, "helm") || strings.Contains(body, "plugin") || strings.Contains(body, "lua") || strings.Contains(body, "patches") || strings.Contains(body, "resources") {
				findings = append(findings, &models.Finding{
					Title:       "Helm/Kustomize Plugin Configuration Exposed",
					Severity:    models.Medium,
					Confidence:  models.MediumConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("Plugin or Kustomize configuration exposed at %s", path),
					Description: "Helm plugin or Kustomize configuration files are exposed, revealing deployment customization logic and potential security misconfigurations.",
					Remediation: "Restrict access to plugin and Kustomize configuration files. Use proper CI/CD pipelines instead of exposing build configuration on web servers.",
					CWEID:       "CWE-200",
					ModuleID:    "helm",
				})
			}
		}
	}
	return findings
}

func init() {
	engine.GetRegistry().Register(&HelmModule{})
}
