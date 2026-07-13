package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type RESTModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *RESTModule) ID() string   { return "rest" }
func (m *RESTModule) Name() string { return "REST API Security Scanner" }
func (m *RESTModule) Description() string {
	return "Checks REST APIs for exposed endpoints, CORS misconfig, mass assignment, rate limiting, and verbose errors"
}
func (m *RESTModule) Severity() models.Severity { return models.Critical }

func (m *RESTModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *RESTModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	baseURL := strings.TrimRight(target.URL, "/")

	endpoints := []string{
		"/api", "/api/v1", "/api/v2", "/api/v3",
		"/swagger.json", "/openapi.json", "/docs", "/redoc",
		"/api/swagger.json", "/api/openapi.json", "/api/docs",
	}

	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		testURL := baseURL + ep
		resp, err := m.client.Get(testURL)
		if err != nil {
			continue
		}

		if ep == "/swagger.json" || ep == "/openapi.json" || ep == "/api/swagger.json" || ep == "/api/openapi.json" {
			var tmp interface{}
			if err := json.Unmarshal([]byte(resp.Body), &tmp); err == nil {
				findings = append(findings, &models.Finding{
					Title:       "REST API - OpenAPI/Swagger Spec Exposed",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Evidence:    fmt.Sprintf("Endpoint: %s, Status: %d", ep, resp.StatusCode),
					Description: "API specification document is publicly accessible, revealing full API surface, endpoints, parameters, and authentication schemes.",
					Remediation: "Restrict access to API documentation behind authentication. Remove from public exposure.",
					CWEID:       "CWE-200",
					ModuleID:    "rest",
				})
				continue
			}
		}

		if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			bodyLower := strings.ToLower(resp.Body)
			if ep == "/docs" || ep == "/redoc" || ep == "/api/docs" {
				if strings.Contains(bodyLower, "swagger") || strings.Contains(bodyLower, "openapi") || strings.Contains(bodyLower, "redoc") || strings.Contains(bodyLower, "api documentation") {
					findings = append(findings, &models.Finding{
						Title:       "REST API - Documentation UI Exposed",
						Severity:    models.Medium,
						Confidence:  models.HighConfidence,
						URL:         testURL,
						Evidence:    fmt.Sprintf("Endpoint: %s returned %d with API docs content", ep, resp.StatusCode),
						Description: "API documentation UI is exposed without authentication.",
						Remediation: "Protect API documentation behind authentication or remove from public access.",
						CWEID:       "CWE-200",
						ModuleID:    "rest",
					})
					continue
				}
			}

			findings = append(findings, &models.Finding{
				Title:       "REST API - Common Endpoint Exposed",
				Severity:    models.Medium,
				Confidence:  models.MediumConfidence,
				URL:         testURL,
				Evidence:    fmt.Sprintf("Endpoint: %s returned HTTP %d", ep, resp.StatusCode),
				Description: "A common REST API endpoint is accessible. May expose API functionality to unauthenticated users.",
				Remediation: "Ensure API endpoints require proper authentication and are not unnecessarily exposed.",
				CWEID:       "CWE-200",
				ModuleID:    "rest",
			})
		}
	}

	apiEndpoints := []string{"/api", "/api/v1", "/api/v2"}
	for _, ep := range apiEndpoints {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		testURL := baseURL + ep

		resp, err := m.client.DoRaw("OPTIONS", testURL, map[string]string{
			"Origin":                        "https://evil.com",
			"Access-Control-Request-Method": "GET",
		}, "")
		if err != nil {
			continue
		}

		acao := resp.Headers.Get("Access-Control-Allow-Origin")
		if acao == "*" {
			findings = append(findings, &models.Finding{
				Title:       "REST API - CORS Wildcard on API Endpoint",
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         testURL,
				Evidence:    fmt.Sprintf("OPTIONS %s returned ACAO: *", ep),
				Description: "API endpoint allows CORS wildcard origin, enabling cross-origin reads from any website.",
				Remediation: "Configure CORS to allow only specific trusted origins. Avoid using wildcard for API endpoints.",
				CWEID:       "CWE-942",
				ModuleID:    "rest",
			})
		}
	}

	rateLimitPaths := []string{"/api", "/api/v1", "/api/v2", "/api/v3"}
	for _, rlp := range rateLimitPaths {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		testURL := baseURL + rlp
		limited := false

		for i := 0; i < 50; i++ {
			select {
			case <-ctx.Done():
				return findings, nil
			default:
			}

			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}
			if resp.StatusCode == 429 || resp.StatusCode == 503 {
				limited = true
				findings = append(findings, &models.Finding{
					Title:       "REST API - Rate Limiting Detected",
					Severity:    models.Info,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Evidence:    fmt.Sprintf("Hit rate limit after ~%d requests on %s (HTTP %d)", i, rlp, resp.StatusCode),
					Description: "Rate limiting is active on this API endpoint, which is good security practice.",
					Remediation: "Ensure rate limits are configured appropriately to prevent abuse.",
					CWEID:       "CWE-200",
					ModuleID:    "rest",
				})
				break
			}
		}

		if !limited {
			findings = append(findings, &models.Finding{
				Title:       "REST API - No Rate Limiting Detected",
				Severity:    models.Medium,
				Confidence:  models.MediumConfidence,
				URL:         testURL,
				Evidence:    fmt.Sprintf("Endpoint %s did not return 429/503 after 50 rapid requests", rlp),
				Description: "No rate limiting detected on this API endpoint. This allows brute force and DoS attacks.",
				Remediation: "Implement rate limiting (e.g., 100 requests/min per IP) on all API endpoints.",
				CWEID:       "CWE-200",
				ModuleID:    "rest",
			})
		}

		break
	}

	massAssignEndpoints := []string{"/api/v1/users", "/api/v1/admin", "/api/users", "/api/admin"}
	params := []string{"?role=admin", "?isAdmin=true", "?admin=true", "?privilegeLevel=root", "?group=administrators"}
	for _, ep := range massAssignEndpoints {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		for _, param := range params {
			testURL := baseURL + ep + param
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}
			if resp.StatusCode == 200 {
				bodyLower := strings.ToLower(resp.Body)
				if strings.Contains(bodyLower, "admin") || strings.Contains(bodyLower, "role") || strings.Contains(bodyLower, "privilege") {
					findings = append(findings, &models.Finding{
						Title:       "REST API - Mass Assignment Possible",
						Severity:    models.High,
						Confidence:  models.MediumConfidence,
						URL:         testURL,
						Payload:     param,
						Evidence:    fmt.Sprintf("Parameter '%s' accepted on %s (HTTP 200)", param, ep),
						Description: "API endpoint may be vulnerable to mass assignment. URL parameters appear to modify user roles or permissions.",
						Remediation: "Use allow-lists for bindable fields. Do not automatically bind all request parameters to internal objects.",
						CWEID:       "CWE-942",
						ModuleID:    "rest",
					})
					break
				}
			}
		}
	}

	errorPaths := []string{
		"/api/nonexistent", "/api/v1/../etc/passwd", "/api/v1/%00",
		"/api/v1/undefined", "/api/v1/null", "/api/v1/../../../etc/passwd",
	}
	for _, ep := range errorPaths {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		testURL := baseURL + ep
		resp, err := m.client.Get(testURL)
		if err != nil {
			continue
		}

		bodyLower := strings.ToLower(resp.Body)
		stackIndicators := []string{
			"stack trace", "stacktrace", "stack:", "at ", "in ",
			"on line", "line number", "exception", "traceback",
			"file:/", "internal server error", "debug trace",
			"java.lang", "system.exception", "trace:",
		}
		matched := false
		var evidence string
		for _, ind := range stackIndicators {
			if strings.Contains(bodyLower, ind) {
				matched = true
				evidence = fmt.Sprintf("Endpoint %s returned verbose error containing: '%s'", ep, ind)
				break
			}
		}

		if resp.StatusCode == 500 && matched {
			severity := models.High
			if ep == "/api/v1/../etc/passwd" || ep == "/api/v1/../../../etc/passwd" {
				severity = models.Critical
			}
			findings = append(findings, &models.Finding{
				Title:       "REST API - Verbose Error Message / Stack Trace",
				Severity:    severity,
				Confidence:  models.HighConfidence,
				URL:         testURL,
				Evidence:    truncate(evidence, 160),
				Description: "API returns verbose error messages containing stack traces or internal paths, aiding attackers in reconnaissance.",
				Remediation: "Implement custom error handlers that return generic error messages. Log detailed errors server-side only.",
				CWEID:       "CWE-200",
				ModuleID:    "rest",
			})
		}
	}

	return findings, nil
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func init() {
	engine.GetRegistry().Register(&RESTModule{})
}
