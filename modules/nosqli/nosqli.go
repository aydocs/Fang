package nosqli

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/internal/inject"
	"github.com/aydocs/fang/pkg/models"
)

type NoSQLModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *NoSQLModule) ID() string   { return "nosqli" }
func (m *NoSQLModule) Name() string { return "NoSQL Injection Scanner" }
func (m *NoSQLModule) Description() string {
	return "Detects NoSQL injection in MongoDB and similar datastores"
}
func (m *NoSQLModule) Severity() models.Severity { return models.Critical }

func (m *NoSQLModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *NoSQLModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding
	params := inject.TargetParams(target)

	for _, param := range params {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		for _, p := range inject.NoSQLPayloads() {
			testURL := inject.BuildTestURL(target.URL, param, p)
			resp, err := m.client.Get(testURL)
			if err != nil || resp == nil {
				continue
			}
			body := strings.ToLower(resp.Body)
			for _, pat := range inject.NoSQLErrorPatterns() {
				if strings.Contains(body, strings.ToLower(pat)) {
					findings = append(findings, m.finding(
						"NoSQL Injection - Error Based",
						models.Critical, models.HighConfidence,
						testURL, param, p,
						fmt.Sprintf("NoSQL error detected: %s", pat),
						"Sanitize NoSQL query inputs. Use parameterized queries / ORM with bound parameters.",
						"CWE-943",
						"",
					))
					goto nextParam
				}
			}
		}

		for _, op := range []string{"{\"$ne\": null}", "{\"$gt\": \"\"}", "{\"$regex\": \".*\"}", "{\"$exists\": true}"} {
			testURL := inject.BuildTestURL(target.URL, param, op)
			resp, err := m.client.Get(testURL)
			if err != nil || resp == nil {
				continue
			}
			if resp.StatusCode == 200 && !strings.Contains(strings.ToLower(resp.Body), "error") && len(resp.Body) > 0 {
				findings = append(findings, m.finding(
					"NoSQL Injection - Operator Fuzzing",
					models.High, models.MediumConfidence,
					testURL, param, op,
					"Operator payload altered response without error",
					"Validate and type-check NoSQL query operators server-side.",
					"CWE-943",
					"",
				))
				break
			}
		}
	nextParam:
	}
	return findings, nil
}

func (m *NoSQLModule) finding(title string, severity models.Severity, confidence models.Confidence, urlStr, param, payload, evidence, description, remediation, cwe string) *models.Finding {
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
		ModuleID:    "nosqli",
	}
}

func init() {
	engine.GetRegistry().Register(&NoSQLModule{})
}
