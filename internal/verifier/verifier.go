package verifier

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aydocs/fang/pkg/models"
)

type Config struct {
	BaselineCompare bool
	RepeatedChecks  int
	TimingThreshold time.Duration
	MaxAttempts     int
}

var defaultConfig = &Config{
	BaselineCompare: true,
	RepeatedChecks:  3,
	TimingThreshold: 5 * time.Second,
	MaxAttempts:     5,
}

type Verifier struct {
	client *http.Client
	config *Config
}

func New(cfg *Config) *Verifier {
	if cfg == nil {
		cfg = defaultConfig
	}
	if cfg.RepeatedChecks <= 0 {
		cfg.RepeatedChecks = 3
	}
	if cfg.TimingThreshold <= 0 {
		cfg.TimingThreshold = 5 * time.Second
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 5
	}
	return &Verifier{
		client: &http.Client{Timeout: 30 * time.Second},
		config: cfg,
	}
}

func (v *Verifier) Verify(ctx context.Context, finding *models.Finding, target string) (*models.Verification, error) {
	if finding == nil {
		return &models.Verification{Confirmed: false, Evidence: "nil finding"}, nil
	}
	methods := v.selectMethods(finding)

	for _, method := range methods {
		select {
		case <-ctx.Done():
			return &models.Verification{Confirmed: false}, ctx.Err()
		default:
		}

		result := v.runMethod(ctx, method, finding, target)
		if result.Confirmed {
			return result, nil
		}
	}

	return &models.Verification{Confirmed: false, Evidence: "no verification method confirmed"}, nil
}

func (v *Verifier) VerifyBatch(ctx context.Context, findings []*models.Finding, target string) []*models.Verification {
	results := make([]*models.Verification, len(findings))
	for i, f := range findings {
		r, _ := v.Verify(ctx, f, target)
		results[i] = r
	}
	return results
}

func (v *Verifier) selectMethods(finding *models.Finding) []string {
	var methods []string

	if finding.Payload != "" {
		methods = append(methods, "reflection")
	}

	methods = append(methods, "differential", "error_pattern")

	if v.config.BaselineCompare {
		methods = append(methods, "baseline")
	}

	methods = append(methods, "repeated")

	desc := strings.ToLower(finding.Description)
	if strings.Contains(desc, "time") || strings.Contains(desc, "blind") || strings.Contains(desc, "delay") {
		methods = append(methods, "timing")
	}

	return methods
}

func (v *Verifier) runMethod(ctx context.Context, method string, finding *models.Finding, target string) *models.Verification {
	switch method {
	case "baseline":
		return v.baselineCompare(ctx, finding, target)
	case "repeated":
		return v.repeatedRequest(ctx, finding, target)
	case "differential":
		return v.differentialAnalysis(ctx, finding, target)
	case "timing":
		return v.timingAnalysis(ctx, finding, target)
	case "reflection":
		return v.reflectionConfirmation(ctx, finding, target)
	case "error_pattern":
		return v.errorPatternConfirmation(ctx, finding, target)
	default:
		return &models.Verification{Confirmed: false}
	}
}

type responseInfo struct {
	statusCode int
	body       string
	bodyLen    int
	duration   time.Duration
	err        error
}

func (v *Verifier) fetch(ctx context.Context, url string) responseInfo {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return responseInfo{err: err}
	}

	start := time.Now()
	resp, err := v.client.Do(req)
	dur := time.Since(start)
	if err != nil {
		return responseInfo{err: err, duration: dur}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return responseInfo{statusCode: resp.StatusCode, duration: dur, err: err}
	}

	return responseInfo{
		statusCode: resp.StatusCode,
		body:       string(body),
		bodyLen:    len(body),
		duration:   dur,
	}
}

func (v *Verifier) reflectionConfirmation(ctx context.Context, finding *models.Finding, target string) *models.Verification {
	resp := v.fetch(ctx, finding.URL)
	if resp.err != nil {
		return &models.Verification{Confirmed: false, Evidence: resp.err.Error(), Method: "reflection", Duration: resp.duration}
	}

	if finding.Payload != "" && strings.Contains(resp.body, finding.Payload) {
		return &models.Verification{
			Confirmed: true,
			Evidence:  fmt.Sprintf("Payload %q reflected in response body", finding.Payload),
			Method:    "reflection",
			Duration:  resp.duration,
		}
	}

	return &models.Verification{Confirmed: false, Method: "reflection", Duration: resp.duration}
}

func (v *Verifier) differentialAnalysis(ctx context.Context, finding *models.Finding, target string) *models.Verification {
	cleanResp := v.fetch(ctx, target)
	if cleanResp.err != nil {
		return &models.Verification{Confirmed: false, Evidence: cleanResp.err.Error(), Method: "differential"}
	}

	malResp := v.fetch(ctx, finding.URL)
	if malResp.err != nil {
		return &models.Verification{Confirmed: false, Evidence: malResp.err.Error(), Method: "differential"}
	}

	confirmed := false
	evidence := ""

	if cleanResp.statusCode != malResp.statusCode {
		confirmed = true
		evidence = fmt.Sprintf("Status code changed: %d -> %d", cleanResp.statusCode, malResp.statusCode)
	} else if cleanResp.bodyLen != malResp.bodyLen {
		if cleanResp.body != malResp.body {
			confirmed = true
			evidence = fmt.Sprintf("Response body differs (length: %d -> %d)", cleanResp.bodyLen, malResp.bodyLen)
		}
	}

	return &models.Verification{
		Confirmed: confirmed,
		Evidence:  evidence,
		Method:    "differential",
		Duration:  cleanResp.duration + malResp.duration,
	}
}

func (v *Verifier) baselineCompare(ctx context.Context, finding *models.Finding, target string) *models.Verification {
	baseResp := v.fetch(ctx, target)
	if baseResp.err != nil {
		return &models.Verification{Confirmed: false, Evidence: baseResp.err.Error(), Method: "baseline"}
	}

	findingResp := v.fetch(ctx, finding.URL)
	if findingResp.err != nil {
		return &models.Verification{Confirmed: false, Evidence: findingResp.err.Error(), Method: "baseline"}
	}

	if baseResp.body != findingResp.body {
		return &models.Verification{
			Confirmed: true,
			Evidence:  "Response content differs from baseline",
			Method:    "baseline",
			Duration:  baseResp.duration + findingResp.duration,
		}
	}

	return &models.Verification{Confirmed: false, Method: "baseline", Duration: baseResp.duration + findingResp.duration}
}

func (v *Verifier) repeatedRequest(ctx context.Context, finding *models.Finding, target string) *models.Verification {
	var prevStatus, prevLen int
	consistent := true
	var totalDur time.Duration

	for i := 0; i < v.config.RepeatedChecks; i++ {
		resp := v.fetch(ctx, finding.URL)
		if resp.err != nil {
			return &models.Verification{Confirmed: false, Evidence: resp.err.Error(), Method: "repeated"}
		}
		totalDur += resp.duration
		if i > 0 && (resp.statusCode != prevStatus || resp.bodyLen != prevLen) {
			consistent = false
			break
		}
		prevStatus = resp.statusCode
		prevLen = resp.bodyLen
	}

	if consistent && prevStatus > 0 {
		return &models.Verification{
			Confirmed: true,
			Evidence:  fmt.Sprintf("Consistent across %d requests (status %d, length %d)", v.config.RepeatedChecks, prevStatus, prevLen),
			Method:    "repeated",
			Duration:  totalDur,
		}
	}

	return &models.Verification{
		Confirmed: false,
		Evidence:  "Inconsistent responses across repeated requests",
		Method:    "repeated",
		Duration:  totalDur,
	}
}

func (v *Verifier) timingAnalysis(ctx context.Context, finding *models.Finding, target string) *models.Verification {
	resp := v.fetch(ctx, finding.URL)
	if resp.err != nil {
		return &models.Verification{Confirmed: false, Evidence: resp.err.Error(), Method: "timing"}
	}

	if resp.duration >= v.config.TimingThreshold {
		return &models.Verification{
			Confirmed: true,
			Evidence:  fmt.Sprintf("Response time %v exceeds threshold %v", resp.duration, v.config.TimingThreshold),
			Method:    "timing",
			Duration:  resp.duration,
		}
	}

	return &models.Verification{
		Confirmed: false,
		Evidence:  fmt.Sprintf("Response time %v below threshold %v", resp.duration, v.config.TimingThreshold),
		Method:    "timing",
		Duration:  resp.duration,
	}
}

var errorPatterns = []string{
	"SQL syntax",
	"mysql_fetch",
	"ORA-",
	"PostgreSQL",
	"Warning:",
	"Fatal error",
	"Uncaught Exception",
	"Stack trace",
	"unexpected",
	"syntax error",
	"division by zero",
}

func (v *Verifier) errorPatternConfirmation(ctx context.Context, finding *models.Finding, target string) *models.Verification {
	resp := v.fetch(ctx, finding.URL)
	if resp.err != nil {
		return &models.Verification{Confirmed: false, Evidence: resp.err.Error(), Method: "error_pattern"}
	}

	bodyLower := strings.ToLower(resp.body)
	for _, pattern := range errorPatterns {
		if strings.Contains(bodyLower, strings.ToLower(pattern)) {
			return &models.Verification{
				Confirmed: true,
				Evidence:  fmt.Sprintf("Error pattern %q found in response", pattern),
				Method:    "error_pattern",
				Duration:  resp.duration,
			}
		}
	}

	return &models.Verification{Confirmed: false, Method: "error_pattern", Duration: resp.duration}
}
