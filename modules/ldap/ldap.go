package ldap

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/internal/inject"
	"github.com/aydocs/fang/pkg/models"
)

type LDAPModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *LDAPModule) ID() string   { return "ldap" }
func (m *LDAPModule) Name() string { return "LDAP Injection Scanner" }
func (m *LDAPModule) Description() string {
	return "Detects LDAP injection in authentication and directory queries"
}
func (m *LDAPModule) Severity() models.Severity { return models.Critical }

func (m *LDAPModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *LDAPModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding
	params := inject.TargetParams(target)

	errorMarkers := []string{"ldap", "malformed filter", "bad search filter", "operations error", "invalid dn"}

	for _, param := range params {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}
		baseline, _ := m.client.Get(inject.BuildTestURL(target.URL, param, "fang-baseline-xyz"))
		baselineBody := ""
		if baseline != nil {
			baselineBody = strings.ToLower(baseline.Body)
		}

		for _, pd := range inject.GenLDAPPayloads() {
			testURL := inject.BuildTestURL(target.URL, param, pd.Value)
			resp, err := m.client.Get(testURL)
			if err != nil || resp == nil {
				continue
			}
			body := strings.ToLower(resp.Body)

			if pd.Check != "" && strings.Contains(body, strings.ToLower(pd.Check)) && !strings.Contains(baselineBody, strings.ToLower(pd.Check)) {
				findings = append(findings, m.finding(
					"LDAP Injection - Filter Bypass",
					models.High, models.MediumConfidence,
					testURL, param, pd.Value,
					fmt.Sprintf("Marker '%s' reflected, indicating filter manipulation", pd.Check),
					"Use parameterized LDAP queries and strict input escaping for DN/filter characters.",
					"CWE-90",
					"",
				))
				goto nextParam
			}
			for _, em := range errorMarkers {
				if strings.Contains(body, em) {
					findings = append(findings, m.finding(
						"LDAP Injection - Error Based",
						models.Critical, models.HighConfidence,
						testURL, param, pd.Value,
						fmt.Sprintf("LDAP error signature detected: %s", em),
						"Validate and escape LDAP special characters (parentheses, asterisks, backslash).",
						"CWE-90",
						"",
					))
					goto nextParam
				}
			}
		}
	nextParam:
	}
	return findings, nil
}

func (m *LDAPModule) finding(title string, severity models.Severity, confidence models.Confidence, urlStr, param, payload, evidence, description, remediation, cwe string) *models.Finding {
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
		ModuleID:    "ldap",
	}
}

func init() {
	engine.GetRegistry().Register(&LDAPModule{})
}
