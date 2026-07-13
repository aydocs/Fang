package central

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type CentralModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *CentralModule) ID() string   { return "central" }
func (m *CentralModule) Name() string { return "Central Scan Management Detection" }
func (m *CentralModule) Description() string {
	return "Discovers scan management REST APIs, report generators, dashboards, schedulers, and webhook endpoints used by centralized security platforms"
}
func (m *CentralModule) Severity() models.Severity { return models.Medium }

func (m *CentralModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

var apiEndpoints = []struct {
	Path        string
	Method      string
	Description string
}{
	{"/api/v1/scans", "GET", "Scan listing"},
	{"/api/v1/scans", "POST", "Scan creation"},
	{"/api/v1/scans/{id}", "GET", "Scan details"},
	{"/api/v1/scans/{id}/start", "POST", "Start scan"},
	{"/api/v1/scans/{id}/stop", "POST", "Stop scan"},
	{"/api/v1/scans/{id}/pause", "POST", "Pause scan"},
	{"/api/v1/scans/{id}/resume", "POST", "Resume scan"},
	{"/api/v1/scans/{id}/status", "GET", "Scan status"},
	{"/api/v1/scans/{id}/results", "GET", "Scan results"},
	{"/api/v1/targets", "GET", "Target listing"},
	{"/api/v1/targets", "POST", "Target creation"},
	{"/api/v1/targets/{id}", "GET", "Target details"},
	{"/api/v1/results", "GET", "Results listing"},
	{"/api/v1/results/{id}", "GET", "Result details"},
	{"/api/v1/findings", "GET", "Findings listing"},
	{"/api/v1/findings/{id}", "GET", "Finding details"},
	{"/api/v1/templates", "GET", "Template listing"},
	{"/api/v1/plugins", "GET", "Plugin listing"},
	{"/api/v1/modules", "GET", "Module listing"},
	{"/api/v1/config", "GET", "Configuration"},
	{"/api/v1/config", "PUT", "Update configuration"},
	{"/api/v1/users", "GET", "User management"},
	{"/api/v1/users/{id}", "GET", "User details"},
	{"/api/v1/auth/login", "POST", "Authentication"},
	{"/api/v1/auth/logout", "POST", "Logout"},
	{"/api/v1/auth/register", "POST", "Registration"},
	{"/api/v1/health", "GET", "Health check"},
	{"/api/v1/version", "GET", "Version info"},
	{"/api/v1/stats", "GET", "Statistics"},
	{"/api/v1/metrics", "GET", "Metrics"},
	{"/api/v1/export", "GET", "Data export"},
	{"/api/v1/import", "POST", "Data import"},
	{"/api/v2/scans", "GET", "Scan listing (v2)"},
	{"/api/v2/scans", "POST", "Scan creation (v2)"},
	{"/api/v2/results", "GET", "Results (v2)"},
	{"/api/scans", "GET", "Scan listing (legacy)"},
	{"/api/scans", "POST", "Scan creation (legacy)"},
	{"/api/targets", "GET", "Target listing (legacy)"},
	{"/api/results", "GET", "Results (legacy)"},
	{"/api/findings", "GET", "Findings (legacy)"},
	{"/api/config", "GET", "Configuration (legacy)"},
	{"/api/health", "GET", "Health check (legacy)"},
	{"/api/version", "GET", "Version (legacy)"},
}

var reportEndpoints = []struct {
	Path        string
	Description string
}{
	{"/reports", "Report listing"},
	{"/reports/{id}", "Report details"},
	{"/reports/{id}/pdf", "PDF report"},
	{"/reports/{id}/html", "HTML report"},
	{"/reports/{id}/json", "JSON report"},
	{"/reports/{id}/csv", "CSV report"},
	{"/reports/{id}/xml", "XML report"},
	{"/reports/{id}/export", "Report export"},
	{"/reports/generate", "Report generation"},
	{"/reports/schedule", "Scheduled reports"},
	{"/api/reports", "API report listing"},
	{"/api/reports/{id}", "API report details"},
	{"/api/reports/{id}/pdf", "API PDF report"},
	{"/api/reports/{id}/html", "API HTML report"},
	{"/api/reports/{id}/json", "API JSON report"},
	{"/api/reports/{id}/csv", "API CSV report"},
	{"/api/v1/reports", "Report listing (v1)"},
	{"/api/v1/reports/{id}", "Report details (v1)"},
	{"/api/v1/reports/{id}/pdf", "Report PDF export (v1)"},
	{"/api/v1/reports/{id}/html", "Report HTML export (v1)"},
	{"/api/v1/reports/{id}/json", "Report JSON export (v1)"},
	{"/api/v1/reports/generate", "Report generation (v1)"},
	{"/export/report", "Exported report"},
	{"/export/pdf", "PDF export"},
	{"/export/html", "HTML export"},
	{"/export/json", "JSON export"},
	{"/export/csv", "CSV export"},
	{"/download/report", "Report download"},
	{"/download/report.pdf", "PDF download"},
	{"/download/report.html", "HTML download"},
	{"/download/report.json", "JSON download"},
	{"/download/report.csv", "CSV download"},
}

var dashboardEndpoints = []string{
	"/dashboard", "/dashboard/", "/dashboard/login",
	"/dashboard/overview", "/dashboard/scans", "/dashboard/results",
	"/dashboard/findings", "/dashboard/targets", "/dashboard/reports",
	"/dashboard/config", "/dashboard/users", "/dashboard/settings",
	"/dashboard/analytics", "/dashboard/stats", "/dashboard/metrics",
	"/dashboard/activity", "/dashboard/logs", "/dashboard/events",
	"/dashboard/notifications", "/dashboard/alerts",
	"/ui", "/ui/", "/ui/dashboard", "/ui/scans", "/ui/results",
	"/ui/findings", "/ui/login", "/ui/config",
	"/admin", "/admin/", "/admin/dashboard", "/admin/scans",
	"/admin/results", "/admin/reports", "/admin/config",
	"/admin/users", "/admin/settings",
	"/console", "/console/", "/console/login",
	"/app", "/app/", "/app/dashboard", "/app/scans",
	"/web", "/web/", "/web/dashboard",
	"/portal", "/portal/", "/portal/dashboard",
	"/manage", "/manage/", "/manage/scans",
}

var schedulerEndpoints = []string{
	"/api/v1/scheduler", "/api/v1/scheduler/jobs",
	"/api/v1/scheduler/jobs/{id}", "/api/v1/scheduler/jobs/{id}/run",
	"/api/v1/scheduler/jobs/{id}/pause", "/api/v1/scheduler/jobs/{id}/resume",
	"/api/v1/scheduler/jobs/{id}/delete",
	"/api/v1/scheduler/triggers", "/api/v1/scheduler/calendars",
	"/api/scheduler", "/api/scheduler/jobs",
	"/api/scheduler/triggers",
	"/api/v1/cron", "/api/v1/cron/jobs",
	"/api/v1/periodic", "/api/v1/periodic/tasks",
	"/scheduler", "/scheduler/", "/scheduler/jobs",
	"/cron", "/cron/", "/cron/jobs",
	"/tasks", "/tasks/", "/tasks/schedule",
	"/jobs", "/jobs/", "/jobs/schedule",
	"/api/v1/tasks", "/api/v1/tasks/schedule",
	"/api/v1/jobs", "/api/v1/jobs/schedule",
}

var webhookEndpoints = []string{
	"/api/v1/webhooks", "/api/v1/webhooks/{id}",
	"/api/v1/webhooks/{id}/test", "/api/v1/webhooks/{id}/logs",
	"/api/webhooks", "/api/webhooks/{id}",
	"/api/v1/hooks", "/api/v1/hooks/{id}",
	"/api/hooks", "/api/hooks/{id}",
	"/webhook", "/webhooks", "/webhook/test",
	"/api/v1/notifications/webhook",
	"/api/v1/integrations/webhook",
	"/api/v1/alerting/webhook",
	"/hooks", "/hooks/", "/hooks/test",
	"/api/v1/callbacks", "/api/v1/callbacks/{id}",
	"/api/callbacks", "/api/callbacks/{id}",
}

func (m *CentralModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	apiFindings := m.scanAPI(ctx, target)
	findings = append(findings, apiFindings...)

	select {
	case <-ctx.Done():
		return findings, nil
	default:
	}

	reportFindings := m.scanReports(ctx, target)
	findings = append(findings, reportFindings...)

	select {
	case <-ctx.Done():
		return findings, nil
	default:
	}

	dashFindings := m.scanDashboard(ctx, target)
	findings = append(findings, dashFindings...)

	select {
	case <-ctx.Done():
		return findings, nil
	default:
	}

	schedFindings := m.scanScheduler(ctx, target)
	findings = append(findings, schedFindings...)

	select {
	case <-ctx.Done():
		return findings, nil
	default:
	}

	webhookFindings := m.scanWebhook(ctx, target)
	findings = append(findings, webhookFindings...)

	return findings, nil
}

func (m *CentralModule) scanAPI(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := m.resolveBaseURL(target.URL)

	for _, ep := range apiEndpoints {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		testURL := base + ep.Path
		var resp *fanghttp.Response
		var err error

		switch ep.Method {
		case "GET":
			resp, err = m.client.Get(testURL)
		case "POST":
			resp, err = m.client.Post(testURL, "{}")
		case "PUT":
			req := fanghttp.NewRequest(http.MethodPut, testURL).WithBody("{}")
			resp, err = m.client.Do(req)
		default:
			resp, err = m.client.Get(testURL)
		}

		if err != nil {
			continue
		}

		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusForbidden {
			bodySample := strings.TrimSpace(resp.Body)
			if len(bodySample) > 100 {
				bodySample = bodySample[:100] + "..."
			}

			findings = append(findings, m.makeFinding(
				fmt.Sprintf("Scan Management API Endpoint - %s (%s)", ep.Description, ep.Method),
				models.Medium, models.HighConfidence,
				testURL, "", ep.Method,
				fmt.Sprintf("HTTP %d - %s", resp.StatusCode, bodySample),
				"Central management API endpoint discovered.",
				"Restrict API endpoint access. Implement proper authentication, authorization, and rate limiting on all management interfaces.",
				"CWE-200",
			))
		}
	}

	if len(findings) == 0 {
		return nil
	}
	return findings
}

func (m *CentralModule) scanReports(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := m.resolveBaseURL(target.URL)

	for _, ep := range reportEndpoints {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		testURL := base + ep.Path
		resp, err := m.client.Get(testURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusForbidden {
			bodySample := strings.TrimSpace(resp.Body)
			if len(bodySample) > 100 {
				bodySample = bodySample[:100] + "..."
			}

			findings = append(findings, m.makeFinding(
				fmt.Sprintf("Report Generation Endpoint - %s", ep.Description),
				models.Medium, models.HighConfidence,
				testURL, "", ep.Path,
				fmt.Sprintf("HTTP %d - %s", resp.StatusCode, bodySample),
				"Report generation endpoint discovered.",
				"Restrict report generation endpoints. Ensure reports don't expose sensitive data. Implement access controls on generated reports.",
				"CWE-200",
			))
		}
	}

	if len(findings) == 0 {
		return nil
	}
	return findings
}

func (m *CentralModule) scanDashboard(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := m.resolveBaseURL(target.URL)

	for _, path := range dashboardEndpoints {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		testURL := base + path
		resp, err := m.client.Get(testURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != http.StatusNotFound {
			bodyLower := strings.ToLower(resp.Body)
			dashboardIndicators := []string{"dashboard", "login", "admin", "scans", "findings", "manage", "console", "panel"}

			matchedIndicators := []string{}
			for _, ind := range dashboardIndicators {
				if strings.Contains(bodyLower, ind) {
					matchedIndicators = append(matchedIndicators, ind)
				}
			}

			if len(matchedIndicators) > 0 || resp.StatusCode == http.StatusOK {
				findings = append(findings, m.makeFinding(
					fmt.Sprintf("Dashboard/UI Endpoint - %s", path),
					models.Low, models.MediumConfidence,
					testURL, "", path,
					fmt.Sprintf("HTTP %d (indicators: %s)", resp.StatusCode, strings.Join(matchedIndicators, ", ")),
					"Dashboard or management UI endpoint discovered.",
					"Restrict dashboard access to authorized IPs. Implement strong authentication. Use VPN for management interfaces.",
					"CWE-200",
				))
			}
		}
	}

	if len(findings) == 0 {
		return nil
	}
	return findings
}

func (m *CentralModule) scanScheduler(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := m.resolveBaseURL(target.URL)

	for _, path := range schedulerEndpoints {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		testURL := base + path
		resp, err := m.client.Get(testURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusForbidden {
			bodyLower := strings.ToLower(resp.Body)
			schedIndicators := []string{"cron", "schedule", "job", "trigger", "periodic", "task", "scheduler"}

			matched := false
			for _, ind := range schedIndicators {
				if strings.Contains(bodyLower, ind) {
					matched = true
					break
				}
			}

			if matched || resp.StatusCode == http.StatusOK {
				bodySample := strings.TrimSpace(resp.Body)
				if len(bodySample) > 100 {
					bodySample = bodySample[:100] + "..."
				}

				findings = append(findings, m.makeFinding(
					fmt.Sprintf("Scheduler/Cron Endpoint - %s", path),
					models.High, models.MediumConfidence,
					testURL, "", path,
					fmt.Sprintf("HTTP %d - %s", resp.StatusCode, bodySample),
					"Task scheduler or cron job endpoint discovered.",
					"Restrict scheduler endpoints. Schedulers with remote execution can lead to RCE. Use proper authentication and input validation.",
					"CWE-200",
				))
			}
		}
	}

	if len(findings) == 0 {
		return nil
	}
	return findings
}

func (m *CentralModule) scanWebhook(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := m.resolveBaseURL(target.URL)

	for _, path := range webhookEndpoints {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		testURL := base + path
		resp, err := m.client.Get(testURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusForbidden {
			bodyLower := strings.ToLower(resp.Body)
			webhookIndicators := []string{"webhook", "hook", "callback", "notif", "alert", "integration", "endpoint", "url"}

			matched := false
			for _, ind := range webhookIndicators {
				if strings.Contains(bodyLower, ind) {
					matched = true
					break
				}
			}

			if matched || resp.StatusCode == http.StatusOK {
				bodySample := strings.TrimSpace(resp.Body)
				if len(bodySample) > 100 {
					bodySample = bodySample[:100] + "..."
				}

				findings = append(findings, m.makeFinding(
					fmt.Sprintf("Webhook Endpoint - %s", path),
					models.Medium, models.MediumConfidence,
					testURL, "", path,
					fmt.Sprintf("HTTP %d - %s", resp.StatusCode, bodySample),
					"Webhook endpoint discovered.",
					"Restrict webhook configuration endpoints. Validate webhook URLs to prevent SSRF. Implement secret verification for incoming webhooks.",
					"CWE-200",
				))
			}
		}
	}

	if len(findings) == 0 {
		return nil
	}
	return findings
}

func (m *CentralModule) resolveBaseURL(rawURL string) string {
	base := rawURL
	if idx := strings.Index(rawURL, "?"); idx >= 0 {
		base = rawURL[:idx]
	}
	base = strings.TrimRight(base, "/")
	return base
}

func (m *CentralModule) makeFinding(title string, severity models.Severity, confidence models.Confidence, urlStr, param, payload, evidence, description, remediation, cwe string) *models.Finding {
	return &models.Finding{
		Title:       title,
		Severity:    severity,
		Confidence:  confidence,
		URL:         urlStr,
		Parameter:   param,
		Payload:     payload,
		Evidence:    evidence,
		Description: description,
		Remediation: remediation,
		CWEID:       cwe,
		ModuleID:    "central",
	}
}

func init() {
	engine.GetRegistry().Register(&CentralModule{})
}
