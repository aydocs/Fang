package k8s

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type K8sModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *K8sModule) ID() string   { return "k8s" }
func (m *K8sModule) Name() string { return "Kubernetes Security Audit" }
func (m *K8sModule) Description() string {
	return "Detects exposed Kubernetes API servers, etcd, kubelet, dashboards, and monitoring endpoints"
}
func (m *K8sModule) Severity() models.Severity { return models.Critical }

func (m *K8sModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *K8sModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkAPIServer(ctx, target)...)
	findings = append(findings, m.checkAnonymousAuth(ctx, target)...)
	findings = append(findings, m.checkDebugEndpoints(ctx, target)...)
	findings = append(findings, m.checkEtcd(ctx, target)...)
	findings = append(findings, m.checkKubelet(ctx, target)...)
	findings = append(findings, m.checkDashboard(ctx, target)...)
	findings = append(findings, m.checkMonitoring(ctx, target)...)

	return findings, nil
}

func (m *K8sModule) checkAPIServer(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	ports := []string{"6443", "443"}
	apiEndpoints := []string{"/api", "/api/v1", "/version"}
	for _, port := range ports {
		for _, ep := range apiEndpoints {
			u := fmt.Sprintf("https://%s:%s%s", target.Domain, port, ep)
			resp, err := m.client.Get(u)
			if err != nil || resp == nil {
				continue
			}
			if resp.StatusCode == 200 {
				body := strings.ToLower(resp.Body)
				if strings.Contains(body, "kubernetes") || strings.Contains(body, "\"major\"") || strings.Contains(body, "\"minor\"") || strings.Contains(body, "kind") {
					findings = append(findings, &models.Finding{
						Title:       "Exposed Kubernetes API Server",
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         u,
						Evidence:    fmt.Sprintf("Kubernetes API accessible on port %s at %s - response contains API version info", port, ep),
						Description: "The Kubernetes API server is exposed without authentication on a non-standard or standard port. This allows full cluster management access.",
						Remediation: "Restrict API server access to trusted IPs, enable RBAC, use network policies, and never expose the API server directly to the internet.",
						CWEID:       "CWE-306",
						ModuleID:    "k8s",
					})
				}
			}
		}
	}
	return findings
}

func (m *K8sModule) checkAnonymousAuth(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	ports := []string{"6443", "443"}
	sensitivePaths := []string{"/api/v1", "/api/v1/pods", "/api/v1/secrets", "/api/v1/namespaces", "/api/v1/nodes"}
	for _, port := range ports {
		for _, path := range sensitivePaths {
			u := fmt.Sprintf("https://%s:%s%s", target.Domain, port, path)
			resp, err := m.client.Get(u)
			if err != nil || resp == nil {
				continue
			}
			if resp.StatusCode == 200 || resp.StatusCode == 403 {
				body := strings.ToLower(resp.Body)
				if strings.Contains(body, "kind") || strings.Contains(body, "items") || strings.Contains(body, "metadata") {
					sev := models.Critical
					conf := models.HighConfidence
					if resp.StatusCode == 403 {
						sev = models.Medium
						conf = models.MediumConfidence
					}
					title := "Kubernetes API Anonymous Access"
					if resp.StatusCode == 200 {
						title = "Kubernetes API Fully Accessible (No Auth)"
					}
					findings = append(findings, &models.Finding{
						Title:       title,
						Severity:    sev,
						Confidence:  conf,
						URL:         u,
						Evidence:    fmt.Sprintf("K8s API %s returned %d with Kubernetes response body", path, resp.StatusCode),
						Description: "The Kubernetes API server allows anonymous access to sensitive endpoints. This can lead to full cluster compromise.",
						Remediation: "Disable anonymous authentication, enable RBAC, and use webhook token authentication.",
						CWEID:       "CWE-306",
						ModuleID:    "k8s",
					})
				}
			}
		}
	}
	return findings
}

func (m *K8sModule) checkDebugEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	ports := []string{"6443", "443"}
	debugPaths := []string{"/openapi/v2", "/swagger.json", "/swaggerapi", "/healthz", "/readyz", "/livez"}
	for _, port := range ports {
		for _, path := range debugPaths {
			u := fmt.Sprintf("https://%s:%s%s", target.Domain, port, path)
			resp, err := m.client.Get(u)
			if err != nil || resp == nil {
				continue
			}
			if resp.StatusCode == 200 {
				evidence := ""
				title := "Kubernetes Debug Endpoint Exposed"
				if strings.Contains(path, "healthz") || strings.Contains(path, "readyz") || strings.Contains(path, "livez") {
					title = "Kubernetes Health/Readiness Endpoint Exposed"
					evidence = fmt.Sprintf("Health check endpoint %s returned 200", path)
				} else if strings.Contains(path, "swagger") || strings.Contains(path, "openapi") {
					title = "Kubernetes OpenAPI/Swagger Endpoint Exposed"
					evidence = fmt.Sprintf("API documentation endpoint %s returned 200", path)
				}
				findings = append(findings, &models.Finding{
					Title:       title,
					Severity:    models.Medium,
					Confidence:  models.MediumConfidence,
					URL:         u,
					Evidence:    evidence,
					Description: "Kubernetes debug and health endpoints are exposed without authentication, leaking cluster metadata.",
					Remediation: "Disable anonymous access to health endpoints or restrict them via network policies and authentication.",
					CWEID:       "CWE-200",
					ModuleID:    "k8s",
				})
			}
		}
	}
	return findings
}

func (m *K8sModule) checkEtcd(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	ports := []string{"2379"}
	etcdEndpoints := []string{"/version", "/health", "/v2/keys", "/v3alpha/kv/range"}
	for _, port := range ports {
		for _, ep := range etcdEndpoints {
			u := fmt.Sprintf("http://%s:%s%s", target.Domain, port, ep)
			resp, err := m.client.Get(u)
			if err != nil || resp == nil {
				continue
			}
			if resp.StatusCode == 200 {
				lower := strings.ToLower(resp.Body)
				if strings.Contains(lower, "etcd") || strings.Contains(lower, "\"version\"") || strings.Contains(lower, "action") || strings.Contains(lower, "node") {
					findings = append(findings, &models.Finding{
						Title:       "Exposed etcd Server (No Auth)",
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         u,
						Evidence:    fmt.Sprintf("etcd endpoint %s returned 200 with etcd response body", ep),
						Description: "etcd is exposed without authentication on port 2379. Attackers can read/write all cluster state including secrets and configuration.",
						Remediation: "Enable etcd TLS client authentication, restrict network access to etcd, and use firewall rules to block port 2379 from untrusted networks.",
						CWEID:       "CWE-306",
						ModuleID:    "k8s",
					})
				}
			}
		}
	}
	return findings
}

func (m *K8sModule) checkKubelet(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	ports := []string{"10250", "10255"}
	kubeletPaths := []string{"/pods/", "/healthz", "/spec/", "/stats/", "/metrics"}
	for _, port := range ports {
		for _, path := range kubeletPaths {
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
				if strings.Contains(body, "kind") || strings.Contains(body, "pods") || strings.Contains(body, "containers") || strings.Contains(body, "spec") {
					findings = append(findings, &models.Finding{
						Title:       "Kubelet Anonymous Auth Enabled",
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         u,
						Evidence:    fmt.Sprintf("Kubelet endpoint %s on port %s returned 200 with pod/container data", path, port),
						Description: "Kubelet is exposed with anonymous authentication enabled on port " + port + ". Attackers can enumerate pods, exec into containers, and access node metrics.",
						Remediation: "Disable anonymous auth on kubelet (--anonymous-auth=false), enable webhook authorization, and restrict port 10250/10255 access.",
						CWEID:       "CWE-306",
						ModuleID:    "k8s",
					})
				}
			}
		}
	}
	return findings
}

func (m *K8sModule) checkDashboard(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	ports := []string{"30000", "30001", "30002"}
	dashPaths := []string{"/", "/api/v1/namespace", "/api/v1/pod", "/#!/overview"}
	for _, port := range ports {
		for _, path := range dashPaths {
			u := fmt.Sprintf("http://%s:%s%s", target.Domain, port, path)
			resp, err := m.client.Get(u)
			if err != nil || resp == nil {
				continue
			}
			if resp.StatusCode == 200 {
				body := strings.ToLower(resp.Body)
				if strings.Contains(body, "kubernetes dashboard") || strings.Contains(body, "kubernetes-dashboard") || strings.Contains(body, "kube-system") || strings.Contains(body, "angular") && strings.Contains(body, "dashboard") {
					findings = append(findings, &models.Finding{
						Title:       "Exposed Kubernetes Dashboard",
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         u,
						Evidence:    fmt.Sprintf("Kubernetes Dashboard accessible on port %s at %s", port, path),
						Description: "The Kubernetes Dashboard is exposed without proper authentication. Attackers can gain full cluster admin access through the dashboard.",
						Remediation: "Never expose the dashboard publicly. Use kubectl proxy or authenticate via OIDC. Restrict access with network policies.",
						CWEID:       "CWE-306",
						ModuleID:    "k8s",
					})
				}
			}
		}
	}
	return findings
}

func (m *K8sModule) checkMonitoring(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	monEndpoints := []struct {
		port string
		path string
		name string
	}{
		{"8080", "/metrics", "kube-state-metrics"},
		{"8081", "/metrics", "kube-state-metrics (alt)"},
		{"9090", "/api/v1/query?query=up", "Prometheus"},
		{"9090", "/metrics", "Prometheus"},
		{"9090", "/graph", "Prometheus UI"},
		{"9091", "/metrics", "Prometheus Operator"},
		{"10250", "/metrics", "Kubelet Metrics"},
		{"10249", "/metrics", "kube-proxy Metrics"},
	}
	for _, ep := range monEndpoints {
		u := fmt.Sprintf("https://%s:%s%s", target.Domain, ep.port, ep.path)
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			u = fmt.Sprintf("http://%s:%s%s", target.Domain, ep.port, ep.path)
			resp, err = m.client.Get(u)
			if err != nil || resp == nil {
				continue
			}
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "prometheus") || strings.Contains(body, "kube_") || strings.Contains(body, "container_") || strings.Contains(body, "node_") || strings.Contains(body, "etcd_request") || strings.Contains(body, "go_goroutines") {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("Exposed %s Endpoint", ep.name),
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("%s metrics endpoint on port %s returned 200 with metric data", ep.name, ep.port),
					Description: fmt.Sprintf("%s is exposed without authentication, leaking cluster metrics and operational data.", ep.name),
					Remediation: "Secure metrics endpoints with authentication, use network policies, and consider using Prometheus with mTLS.",
					CWEID:       "CWE-200",
					ModuleID:    "k8s",
				})
			}
		}
	}
	return findings
}

func init() {
	engine.GetRegistry().Register(&K8sModule{})
}
