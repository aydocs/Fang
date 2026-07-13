package sqli

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/internal/inject"
	"github.com/aydocs/fang/pkg/models"
)

type SQLiModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *SQLiModule) ID() string   { return "sqli" }
func (m *SQLiModule) Name() string { return "SQL Injection Scanner" }
func (m *SQLiModule) Description() string {
	return "Detects SQL injection including error-based, blind boolean, time-based, union-based, and NoSQL injection"
}
func (m *SQLiModule) Severity() models.Severity { return models.Critical }

func (m *SQLiModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

var timePayloads = []struct {
	payload string
	delay   float64
}{
	{"' OR SLEEP(5)--", 4.5},
	{"' AND SLEEP(5)--", 4.5},
	{"' OR SLEEP(3)--", 2.5},
	{"'; WAITFOR DELAY '0:0:5'--", 4.5},
	{"1' AND SLEEP(5)--", 4.5},
	{"1; SELECT SLEEP(5)--", 4.5},
}

func (m *SQLiModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}

	params, _ := url.ParseQuery(parsed.RawQuery)
	paramNames := make([]string, 0, len(params))
	for k := range params {
		paramNames = append(paramNames, k)
	}
	if len(paramNames) == 0 {
		paramNames = []string{"id", "user", "search", "q", "page", "cat", "item", "product", "article", "news", "sort", "order", "filter", "type", "name"}
	}

paramLoop:
	for _, paramName := range paramNames {
		var baselineVal string
		if vals, ok := params[paramName]; ok && len(vals) > 0 {
			baselineVal = vals[0]
		} else {
			baselineVal = "1"
		}

		baselineURL := m.buildTestURL(parsed, params, paramName, baselineVal)
		baselineResp, err := m.client.Get(baselineURL)
		if err != nil {
			continue
		}

		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		for _, p := range inject.SQLIErrorPayloads() {
			select {
			case <-ctx.Done():
				return findings, nil
			default:
			}
			testURL := m.buildTestURL(parsed, params, paramName, p)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			respBody := strings.ToLower(resp.Body)
			for _, errMsg := range inject.SQLIErrorPatterns() {
				if strings.Contains(respBody, strings.ToLower(errMsg)) {
					findings = append(findings, m.makeFinding(
						fmt.Sprintf("SQL Injection - Error Based (%s)", p),
						models.Critical, models.HighConfidence,
						testURL, paramName, p,
						fmt.Sprintf("SQL error detected: %s", errMsg),
						"Parameter '%s' is vulnerable to error-based SQL injection. The application reflects database error messages.",
						"Use parameterized queries/prepared statements with bound parameters. Implement proper error handling.",
						"CWE-89",
					))
					continue paramLoop
				}
			}
		}

		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		for _, p := range inject.NoSQLPayloads() {
			select {
			case <-ctx.Done():
				return findings, nil
			default:
			}
			testURL := m.buildTestURL(parsed, params, paramName, p)
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			respBody := strings.ToLower(resp.Body)
			for _, errMsg := range inject.NoSQLErrorPatterns() {
				if strings.Contains(respBody, strings.ToLower(errMsg)) {
					findings = append(findings, m.makeFinding(
						"NoSQL Injection",
						models.Critical, models.HighConfidence,
						testURL, paramName, p,
						fmt.Sprintf("NoSQL error detected: %s", errMsg),
						"Parameter '%s' is vulnerable to NoSQL injection.",
						"Sanitize NoSQL query inputs. Use parameterized queries for MongoDB.",
						"CWE-943",
					))
					continue paramLoop
				}
			}
		}

		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		truePayload := "1' AND '1'='1"
		falsePayload := "1' AND '1'='2"
		trueURL := m.buildTestURL(parsed, params, paramName, truePayload)
		falseURL := m.buildTestURL(parsed, params, paramName, falsePayload)

		trueResp, err := m.client.Get(trueURL)
		if err == nil {
			falseResp, err := m.client.Get(falseURL)
			if err == nil {
				bodyDiff := abs(len(trueResp.Body) - len(falseResp.Body))
				if bodyDiff > len(baselineResp.Body)/10 && bodyDiff > 50 {
					findings = append(findings, m.makeFinding(
						"SQL Injection - Blind Boolean Based",
						models.High, models.MediumConfidence,
						trueURL, paramName, truePayload,
						fmt.Sprintf("Response size differs by %d bytes between true/false conditions", bodyDiff),
						"Parameter '%s' shows different responses for true/false conditions, suggesting blind SQL injection.",
						"Use parameterized queries/prepared statements.",
						"CWE-89",
					))
				}
			}
		}

		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		for _, tp := range timePayloads {
			select {
			case <-ctx.Done():
				return findings, nil
			default:
			}
			testURL := m.buildTestURL(parsed, params, paramName, tp.payload)

			start := time.Now()
			tresp, terr := m.client.Get(testURL)
			elapsed := time.Since(start).Seconds()
			if terr != nil {
				continue
			}
			_ = tresp

			if elapsed >= tp.delay {
				baselineStart := time.Now()
				m.client.Get(baselineURL)
				baselineElapsed := time.Since(baselineStart).Seconds()

				if elapsed > baselineElapsed+2 {
					findings = append(findings, m.makeFinding(
						"SQL Injection - Time Based",
						models.Critical, models.HighConfidence,
						testURL, paramName, tp.payload,
						fmt.Sprintf("Response delay: %.2fs (baseline: %.2fs)", elapsed, baselineElapsed),
						"Parameter '%s' causes time delays matching SQL sleep functions.",
						"Use parameterized queries/prepared statements.",
						"CWE-89",
					))
					continue paramLoop
				}
			}
		}

		for _, count := range []int{1, 2, 3, 4, 5} {
			select {
			case <-ctx.Done():
				return findings, nil
			default:
			}
			nulls := strings.Repeat("NULL,", count)
			nulls = strings.TrimSuffix(nulls, ",")
			unionPayload := fmt.Sprintf("' UNION SELECT %s--", nulls)
			testURL := m.buildTestURL(parsed, params, paramName, unionPayload)

			uresp, uerr := m.client.Get(testURL)
			if uerr != nil {
				continue
			}

			if uresp.StatusCode == 200 && len(uresp.Body) > 0 {
				sizeDiff := abs(len(uresp.Body) - len(baselineResp.Body))
				if sizeDiff > 50 && uresp.StatusCode == baselineResp.StatusCode {
					findings = append(findings, m.makeFinding(
						fmt.Sprintf("SQL Injection - Union Based (%d columns)", count),
						models.High, models.MediumConfidence,
						testURL, paramName, unionPayload,
						fmt.Sprintf("Response changed: baseline %d bytes, union %d bytes", len(baselineResp.Body), len(uresp.Body)),
						"Parameter '%s' responds to UNION SELECT with different content.",
						"Use parameterized queries/prepared statements.",
						"CWE-89",
					))
				}
			}
		}

	}

	return findings, nil
}

func (m *SQLiModule) buildTestURL(parsed *url.URL, params url.Values, paramName, value string) string {
	newParams := make(url.Values)
	for k, v := range params {
		newParams[k] = v
	}
	newParams.Set(paramName, value)
	return fmt.Sprintf("%s://%s%s?%s", parsed.Scheme, parsed.Host, parsed.Path, newParams.Encode())
}

func (m *SQLiModule) makeFinding(title string, severity models.Severity, confidence models.Confidence, urlStr, param, payload, evidence, description, remediation, cwe string) *models.Finding {
	return &models.Finding{
		Title:       title,
		Severity:    severity,
		Confidence:  confidence,
		URL:         urlStr,
		Parameter:   param,
		Payload:     payload,
		Evidence:    evidence,
		Description: fmt.Sprintf(description, param),
		Remediation: remediation,
		CWEID:       cwe,
		ModuleID:    "sqli",
	}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func init() {
	engine.GetRegistry().Register(&SQLiModule{})
}
