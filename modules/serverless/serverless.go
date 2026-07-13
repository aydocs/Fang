package serverless

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type ServerlessModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *ServerlessModule) ID() string   { return "serverless" }
func (m *ServerlessModule) Name() string { return "Serverless Function Security" }
func (m *ServerlessModule) Description() string {
	return "Detects exposed serverless function endpoints, env leaks, and cold start timing anomalies"
}
func (m *ServerlessModule) Severity() models.Severity { return models.High }

func (m *ServerlessModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *ServerlessModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkAWSLambda(ctx, target)...)
	findings = append(findings, m.checkGCF(ctx, target)...)
	findings = append(findings, m.checkAzureFunctions(ctx, target)...)
	findings = append(findings, m.checkEnvExposure(ctx, target)...)
	findings = append(findings, m.checkColdStart(ctx, target)...)

	return findings, nil
}

func (m *ServerlessModule) checkAWSLambda(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	lambdaDomains := []string{
		"lambda-url." + target.Domain,
		"lambda." + target.Domain,
	}
	for _, ld := range lambdaDomains {
		u := fmt.Sprintf("https://%s/", ld)
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 502 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "lambda") || strings.Contains(body, "function") || strings.Contains(body, "runtime") || strings.Contains(body, "handler") || strings.Contains(body, "aws") || strings.Contains(body, "x-amz-") {
				findings = append(findings, &models.Finding{
					Title:       "AWS Lambda Function URL Exposed",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("AWS Lambda function URL accessible at %s", ld),
					Description: "An AWS Lambda function URL is publicly accessible. Lambda function URLs can expose backend logic and potentially sensitive data.",
					Remediation: "Restrict Lambda function URL access with AWS IAM authorization (AWS_IAM auth type). Use API Gateway with WAF for production workloads.",
					CWEID:       "CWE-200",
					ModuleID:    "serverless",
				})
			}
		}
	}
	return findings
}

func (m *ServerlessModule) checkGCF(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	gcfPaths := []string{
		"/function", "/function-", "/functions", "/cloudfunction",
		"/cloud-function", "/gcf", "/cloud-function-",
	}
	for _, path := range gcfPaths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 404 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "google") || strings.Contains(body, "cloud function") || strings.Contains(body, "gcf") || strings.Contains(body, "function") || strings.Contains(body, "serverless") {
				findings = append(findings, &models.Finding{
					Title:       "Google Cloud Function Endpoint Exposed",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("Google Cloud Function accessible at %s", path),
					Description: "A Google Cloud Function endpoint is exposed. Cloud Functions may leak source code, environment variables, or sensitive business logic.",
					Remediation: "Use IAM authentication for Cloud Functions, restrict invocation to authorized service accounts, and avoid exposing sensitive logic in function code.",
					CWEID:       "CWE-200",
					ModuleID:    "serverless",
				})
			}
		}
	}
	return findings
}

func (m *ServerlessModule) checkAzureFunctions(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	azurePaths := []string{
		"/api/", "/api/functions", "/api/function",
		"/admin/functions", "/admin/host/status", "/admin/host/logs",
		"/admin/functions/", "/runtime/webhooks/",
	}
	for _, path := range azurePaths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "azure") || strings.Contains(body, "function") || strings.Contains(body, "functionapp") || strings.Contains(body, "runtime") || strings.Contains(body, "invoke") || strings.Contains(body, "admin") || strings.Contains(body, "masterkey") || strings.Contains(body, "hoststatus") {
				title := "Azure Functions Endpoint Exposed"
				sev := models.High
				if strings.Contains(path, "admin") {
					title = "Azure Functions Admin Endpoint Exposed"
					sev = models.Critical
				}
				findings = append(findings, &models.Finding{
					Title:       title,
					Severity:    sev,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("Azure Functions endpoint %s returned 200 with function metadata", path),
					Description: "Azure Functions endpoints are exposed, potentially allowing unauthorized function invocation or admin access.",
					Remediation: "Enable Azure Functions authentication (EasyAuth), use function-level authorization keys, and restrict CORS policies.",
					CWEID:       "CWE-200",
					ModuleID:    "serverless",
				})
			}
		}
	}
	return findings
}

func (m *ServerlessModule) checkEnvExposure(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := strings.TrimRight(target.URL, "/")
	envPaths := []string{
		"/env", "/.env", "/.env.production", "/.env.development",
		"/.env.local", "/.env.prod", "/env.json", "/env.yaml",
		"/.env.example", "/environment", "/config/env",
	}
	for _, path := range envPaths {
		u := base + path
		resp, err := m.client.Get(u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "aws_access_key") || strings.Contains(body, "aws_secret_key") || strings.Contains(body, "api_key") || strings.Contains(body, "api_secret") || strings.Contains(body, "password") || strings.Contains(body, "secret") || strings.Contains(body, "token") || strings.Contains(body, "database_url") || strings.Contains(body, "connection_string") || strings.Contains(body, "auth_token") || strings.Contains(body, "access_key") || strings.Contains(body, "secret_key") || strings.Contains(body, "azure") || strings.Contains(body, "gcp") || strings.Contains(body, "aws") {
				findings = append(findings, &models.Finding{
					Title:       "Serverless Environment Variables Exposed",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         u,
					Evidence:    fmt.Sprintf("Environment file %s exposed with credential data", path),
					Description: "Serverless environment configuration files are exposed, leaking cloud provider credentials, API keys, and database connection strings.",
					Remediation: "Use serverless platform secret management (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager). Never store secrets in .env files deployed with functions.",
					CWEID:       "CWE-538",
					ModuleID:    "serverless",
				})
			}
		}
	}
	return findings
}

func (m *ServerlessModule) checkColdStart(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	var durations []time.Duration
	for i := 0; i < 5; i++ {
		resp, err := m.client.Get(target.URL)
		if err != nil || resp == nil {
			continue
		}
		durations = append(durations, resp.Duration)
	}
	if len(durations) >= 3 {
		var avg time.Duration
		for _, d := range durations {
			avg += d
		}
		avg /= time.Duration(len(durations))
		first := durations[0]
		ratio := float64(first) / float64(avg)
		if ratio > 3.0 && first > 2*time.Second {
			findings = append(findings, &models.Finding{
				Title:       "Serverless Cold Start Timing Anomaly",
				Severity:    models.Info,
				Confidence:  models.MediumConfidence,
				URL:         target.URL,
				Evidence:    fmt.Sprintf("First request took %v vs average %v (ratio: %.2f) - indicates cold start", first, avg, ratio),
				Description: "Response time variance suggests a serverless function with cold start behavior. Cold starts can be exploited for timing attacks and may indicate misconfigured concurrency limits.",
				Remediation: "Use provisioned concurrency for latency-sensitive functions. Set reserved concurrency to prevent cold start abuse.",
				CWEID:       "CWE-200",
				ModuleID:    "serverless",
			})
		}
	}
	return findings
}

func init() {
	engine.GetRegistry().Register(&ServerlessModule{})
}
