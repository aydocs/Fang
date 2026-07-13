package cloud

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type CloudModule struct {
	cfg        *engine.Config
	client     *fanghttp.Client
	targetHost string
}

func (m *CloudModule) ID() string   { return "cloud" }
func (m *CloudModule) Name() string { return "Cloud Infrastructure Exposure" }
func (m *CloudModule) Description() string {
	return "Cloud storage enumeration, metadata SSRF and Kubernetes API exposure"
}
func (m *CloudModule) Severity() models.Severity { return models.Critical }

func (m *CloudModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *CloudModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	m.targetHost = target.Domain
	var findings []*models.Finding

	findings = append(findings, m.checkS3Buckets(ctx, target)...)
	findings = append(findings, m.checkAzureBlobs(ctx, target)...)
	findings = append(findings, m.checkGCPBuckets(ctx, target)...)
	findings = append(findings, m.checkMetadataSSRF(ctx, target)...)
	findings = append(findings, m.checkKubernetes(ctx, target)...)
	findings = append(findings, m.checkProviderHeaders(ctx, target)...)

	return findings, nil
}

func (m *CloudModule) candidateNames() []string {
	base := strings.ReplaceAll(m.targetHost, ".", "-")
	baseU := strings.ReplaceAll(m.targetHost, ".", "")
	cands := []string{
		base, baseU,
		base + "-assets", base + "-static", base + "-media", base + "-prod", base + "-dev",
		base + "-backup", base + "-storage", base + "-public", base + "-www",
	}
	seen := make(map[string]struct{}, len(cands))
	out := make([]string, 0, len(cands))
	for _, c := range cands {
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

func (m *CloudModule) checkS3Buckets(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	for _, name := range m.candidateNames() {
		u := fmt.Sprintf("https://%s.s3.amazonaws.com/", name)
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		switch resp.StatusCode {
		case 200:
			findings = append(findings, m.finding(
				"Publicly Listable S3 Bucket",
				models.Critical, models.HighConfidence,
				u, "", name,
				"S3 bucket returned 200 with listable contents",
				"Restrict S3 bucket access with a bucket policy and block public listing.",
				"CWE-732",
			))
		case 403:
		}
	}
	return findings
}

func (m *CloudModule) checkAzureBlobs(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	for _, name := range m.candidateNames() {
		u := fmt.Sprintf("https://%s.blob.core.windows.net/", name)
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 && strings.Contains(resp.Body, "EnumerationResults") {
			findings = append(findings, m.finding(
				"Publicly Listable Azure Blob Container",
				models.Critical, models.HighConfidence,
				u, "", name,
				"Azure blob container returned enumerable results",
				"Set the container ACL to private and restrict SAS token scope.",
				"CWE-732",
			))
		}
	}
	return findings
}

func (m *CloudModule) checkGCPBuckets(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	for _, name := range m.candidateNames() {
		u := fmt.Sprintf("https://storage.googleapis.com/%s/", name)
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 && strings.Contains(resp.Body, "<ListBucketResult") {
			findings = append(findings, m.finding(
				"Publicly Listable GCP Storage Bucket",
				models.Critical, models.HighConfidence,
				u, "", name,
				"GCP storage bucket returned listable objects",
				"Apply Uniform Bucket-Level Access and remove allUsers/allAuthenticatedUsers roles.",
				"CWE-732",
			))
		}
	}
	return findings
}

func (m *CloudModule) checkMetadataSSRF(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base, err := url.Parse(target.URL)
	if err != nil {
		return findings
	}
	params := []string{"url", "redirect", "host", "path", "to", "site", "image", "file"}
	metaMarkers := []string{"ami-id", "instance-id", "privateKey", "security-credentials", "latest/meta-data"}
	payloads := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://metadata.google.internal/computeMetadata/v1/",
	}
	for _, p := range params {
		for _, payload := range payloads {
			testURL := fmt.Sprintf("%s://%s%s?%s=%s", base.Scheme, base.Host, base.Path, p, url.QueryEscape(payload))
			resp, err := m.client.Get(testURL)
			if err != nil || resp == nil {
				continue
			}
			lower := strings.ToLower(resp.Body)
			for _, marker := range metaMarkers {
				if strings.Contains(lower, marker) {
					findings = append(findings, m.finding(
						"Cloud Metadata SSRF",
						models.Critical, models.HighConfidence,
						testURL, p, payload,
						fmt.Sprintf("Response contains cloud metadata marker '%s'", marker),
						"Block egress to link-local metadata endpoints (169.254.169.254) and validate user-supplied URLs.",
						"CWE-918",
					))
					break
				}
			}
		}
	}
	return findings
}

func (m *CloudModule) checkKubernetes(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	endpoints := []string{"/api", "/api/v1", "/healthz", "/version", "/readyz"}
	for _, ep := range endpoints {
		u := strings.TrimRight(target.URL, "/") + ep
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 && (strings.Contains(resp.Body, "kind") || strings.Contains(resp.Body, "Kubernetes") || strings.Contains(resp.Body, "\"major\"")) {
			findings = append(findings, m.finding(
				"Exposed Kubernetes API",
				models.High, models.MediumConfidence,
				u, "", ep,
				"Kubernetes API endpoint is reachable without authentication",
				"Enable RBAC and restrict API server access to trusted networks.",
				"CWE-306",
			))
		}
	}
	return findings
}

func (m *CloudModule) checkProviderHeaders(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	resp, err := m.client.Get(target.URL)
	if err != nil || resp == nil || resp.Headers == nil {
		return findings
	}
	server := resp.Headers.Get("Server")
	xaws := resp.Headers.Get("X-Amz-Cf-Id")
	xazure := resp.Headers.Get("X-Azure-Ref")
	if strings.Contains(server, "AmazonS3") || xaws != "" {
		findings = append(findings, m.finding(
			"Hosted on AWS",
			models.Info, models.MediumConfidence,
			target.URL, "", "",
			"Response headers indicate AWS hosting",
			"Ensure AWS metadata endpoints are not reachable from application code.",
			"CWE-200",
		))
	}
	if xazure != "" {
		findings = append(findings, m.finding(
			"Hosted on Azure",
			models.Info, models.MediumConfidence,
			target.URL, "", "",
			"Response headers indicate Azure hosting",
			"Ensure Azure Instance Metadata Service is not reachable from application code.",
			"CWE-200",
		))
	}
	return findings
}

func (m *CloudModule) finding(title string, severity models.Severity, confidence models.Confidence, urlStr, param, payload, evidence, remediation, cwe string) *models.Finding {
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
		ModuleID:    "cloud",
	}
}

func init() {
	engine.GetRegistry().Register(&CloudModule{})
}
