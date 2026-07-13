package docker

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type DockerModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *DockerModule) ID() string   { return "docker" }
func (m *DockerModule) Name() string { return "Docker & Container Security" }
func (m *DockerModule) Description() string {
	return "Detects exposed Docker API sockets, unauthenticated registries, and container breakout indicators"
}
func (m *DockerModule) Severity() models.Severity { return models.Critical }

func (m *DockerModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *DockerModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkDockerAPI(ctx, target)...)
	findings = append(findings, m.checkDockerSocket(ctx, target)...)
	findings = append(findings, m.checkRegistry(ctx, target)...)
	findings = append(findings, m.checkPrivileged(ctx, target)...)

	return findings, nil
}

func (m *DockerModule) checkDockerAPI(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	ports := []string{"2375", "2376"}
	apiEndpoints := []string{"/info", "/version", "/v1.41/info", "/v1.41/version", "/v1.40/info", "/v1.39/info"}
	for _, port := range ports {
		scheme := "http"
		if port == "2376" {
			scheme = "https"
		}
		for _, ep := range apiEndpoints {
			u := fmt.Sprintf("%s://%s:%s%s", scheme, target.Domain, port, ep)
			resp, err := m.client.Get(u)
			if err != nil || resp == nil {
				continue
			}
			if resp.StatusCode == 200 {
				body := strings.ToLower(resp.Body)
				if strings.Contains(body, "docker") || strings.Contains(body, "containers") || strings.Contains(body, "images") || strings.Contains(body, "kernelversion") || strings.Contains(body, "operatingsystem") || strings.Contains(body, "serverversion") {
					findings = append(findings, &models.Finding{
						Title:       "Exposed Docker API",
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         u,
						Evidence:    fmt.Sprintf("Docker API endpoint %s returned 200 with Docker system info", ep),
						Description: "The Docker daemon API is exposed without authentication on port " + port + ". Attackers can create, modify, and delete containers, images, and volumes.",
						Remediation: "Never expose the Docker API without TLS client authentication. Use firewall rules, enable iptables, and configure Docker for mutual TLS.",
						CWEID:       "CWE-306",
						ModuleID:    "docker",
					})
				}
			}
		}
	}
	return findings
}

func (m *DockerModule) checkDockerSocket(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	socketPaths := []string{"/var/run/docker.sock", "/run/docker.sock", "/docker.sock"}
	for _, sock := range socketPaths {
		u := strings.TrimRight(target.URL, "/") + sock
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "docker") || strings.Contains(body, "containers") || strings.Contains(body, "stream") || strings.Contains(body, "HttpHeaders") {
				findings = append(findings, &models.Finding{
					Title:       "Docker Socket Exposed via Web",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    "Docker socket accessible via HTTP - Docker API response received",
					Description: "The Docker socket (/var/run/docker.sock) is exposed through a web endpoint. This allows full container escape and host compromise.",
					Remediation: "Never mount the Docker socket into web applications. Use Docker-in-Docker or rootless Docker instead.",
					CWEID:       "CWE-306",
					ModuleID:    "docker",
				})
			}
		}
	}
	return findings
}

func (m *DockerModule) checkRegistry(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	ports := []string{"5000", "443", "8443"}
	registryPaths := []string{"/v2/_catalog", "/v2/", "/v2/_catalog?n=100"}
	for _, port := range ports {
		for _, path := range registryPaths {
			u := fmt.Sprintf("https://%s:%s%s", target.Domain, port, path)
			resp, err := m.client.Get(u)
			if err != nil || resp == nil {
				u = fmt.Sprintf("http://%s:%s%s", target.Domain, port, path)
				resp, err = m.client.Get(u)
				if err != nil || resp == nil {
					continue
				}
			}
			if resp.StatusCode == 200 {
				body := strings.ToLower(resp.Body)
				if strings.Contains(body, "repositories") || strings.Contains(body, "docker") || strings.Contains(body, "registry") || strings.Contains(body, "\"name\"") {
					findings = append(findings, &models.Finding{
						Title:       "Exposed Docker Registry v2",
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         u,
						Evidence:    fmt.Sprintf("Docker Registry v2 accessible on port %s at %s - repository listing available", port, path),
						Description: "Docker Registry v2 is exposed without authentication. Attackers can enumerate and pull all container images, potentially accessing proprietary code and secrets.",
						Remediation: "Enable authentication on the registry, use TLS, restrict access with firewall rules, and use Docker Content Trust for image signing.",
						CWEID:       "CWE-306",
						ModuleID:    "docker",
					})
				}
			}
		}
	}
	return findings
}

func (m *DockerModule) checkPrivileged(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	ports := []string{"2375", "2376"}
	containerPaths := []string{"/containers/json?all=true", "/containers/json"}
	for _, port := range ports {
		scheme := "http"
		if port == "2376" {
			scheme = "https"
		}
		for _, path := range containerPaths {
			u := fmt.Sprintf("%s://%s:%s%s", scheme, target.Domain, port, path)
			resp, err := m.client.Get(u)
			if err != nil || resp == nil {
				continue
			}
			if resp.StatusCode == 200 {
				body := strings.ToLower(resp.Body)
				if strings.Contains(body, "privileged") && strings.Contains(body, "true") {
					findings = append(findings, &models.Finding{
						Title:       "Privileged Container Detected via Docker API",
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         u,
						Evidence:    "Docker API returned containers with 'Privileged: true'",
						Description: "Containers running with --privileged flag were detected via the Docker API. Privileged containers can access all host devices and break out of container isolation.",
						Remediation: "Avoid running containers with --privileged. Use specific capabilities (--cap-add) instead of full privileged access.",
						CWEID:       "CWE-250",
						ModuleID:    "docker",
					})
				}
			}
		}
	}
	return findings
}

func init() {
	engine.GetRegistry().Register(&DockerModule{})
}
