package phish

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type PhishModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *PhishModule) ID() string   { return "phish" }
func (m *PhishModule) Name() string { return "Phishing Detection" }
func (m *PhishModule) Description() string {
	return "Detects phishing kits, fake login pages, credential harvesting forms, and lookalike domain attacks"
}
func (m *PhishModule) Severity() models.Severity { return models.Critical }

func (m *PhishModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *PhishModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkPhishingKitEndpoints(ctx, target)...)
	findings = append(findings, m.checkSocialLoginClones(ctx, target)...)
	findings = append(findings, m.checkCredentialHarvesting(ctx, target)...)
	findings = append(findings, m.checkFakePasswordReset(ctx, target)...)
	findings = append(findings, m.checkLookalikeDomain(ctx, target)...)

	return findings, nil
}

var phishingKitPaths = []string{
	"/log", "/logs", "/capture", "/credentials",
	"/stealer", "/phish", "/phishing", "/webhook",
	"/callback", "/grabber", "/sniffer",
	"/admin/log", "/admin/capture", "/admin/credentials",
}

func (m *PhishModule) checkPhishingKitEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	for _, path := range phishingKitPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 {
			continue
		}

		bodyLower := strings.ToLower(resp.Body)
		kitIndicators := []string{"password", "email", "username", "credit", "card", "ssn",
			"log", "capture", "grab", "steal", "phish", "victim"}

		matched := 0
		var matchedIndicators []string
		for _, ind := range kitIndicators {
			if strings.Contains(bodyLower, ind) {
				matched++
				matchedIndicators = append(matchedIndicators, ind)
			}
		}

		if matched >= 3 {
			findings = append(findings, &models.Finding{
				Title:       "Phishing Kit Endpoint Detected",
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("Phishing kit indicators matched: %s", strings.Join(matchedIndicators, ", ")),
				Description: fmt.Sprintf("Endpoint %s responds with content matching phishing kit patterns. This may be a credential harvesting server.", path),
				Remediation: "Investigate the server for unauthorized phishing kit installations. Take down immediately if confirmed.",
				CWEID:       "CWE-200",
				ModuleID:    "phish",
			})
		}
	}

	return findings
}

var socialLoginPatterns = []struct {
	Name   string
	Checks []string
}{
	{Name: "Facebook", Checks: []string{"facebook", "fbcdn", "connect.facebook", "login.php"}},
	{Name: "Google", Checks: []string{"google", "accounts.google", "gstatic", "googleapis"}},
	{Name: "LinkedIn", Checks: []string{"linkedin", "linkedin.com", "li/signin"}},
	{Name: "Twitter/X", Checks: []string{"twitter", "x.com", "twimg"}},
	{Name: "Microsoft", Checks: []string{"microsoft", "login.live", "account.microsoft"}},
}

func (m *PhishModule) checkSocialLoginClones(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	resp, err := m.client.Get(target.URL)
	if err != nil {
		return nil
	}

	bodyLower := strings.ToLower(resp.Body)

	loginIndicators := []string{"login", "signin", "sign in", "email", "password",
		"continue with", "log in with", "authenticate"}

	hasLoginContext := 0
	for _, ind := range loginIndicators {
		if strings.Contains(bodyLower, ind) {
			hasLoginContext++
		}
	}

	if hasLoginContext < 2 {
		return nil
	}

	for _, sp := range socialLoginPatterns {
		matchCount := 0
		for _, check := range sp.Checks {
			if strings.Contains(bodyLower, check) {
				matchCount++
			}
		}
		if matchCount >= 2 {
			parsedURL, _ := url.Parse(target.URL)
			domain := ""
			if parsedURL != nil {
				domain = parsedURL.Hostname()
			}

			isSuspicious := false
			if !strings.Contains(bodyLower, sp.Name) {
				isSuspicious = true
			}
			if domain != "" && strings.Contains(bodyLower, sp.Name) && !strings.Contains(domain, strings.ToLower(sp.Name)) {
				isSuspicious = true
			}

			if isSuspicious {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("Suspicious %s Login Page Clone", sp.Name),
					Severity:    models.Critical,
					Confidence:  models.MediumConfidence,
					URL:         target.URL,
					Evidence:    fmt.Sprintf("Page contains %s authentication elements with indicators: %v", sp.Name, sp.Checks),
					Description: fmt.Sprintf("Page appears to mimic %s login functionality. Possible phishing page targeting %s credentials.", sp.Name, sp.Name),
					Remediation: "Report the phishing page to the brand and hosting provider. Take down immediately.",
					CWEID:       "CWE-522",
					ModuleID:    "phish",
				})
			}
		}
	}

	return findings
}

func (m *PhishModule) checkCredentialHarvesting(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	resp, err := m.client.Get(target.URL)
	if err != nil {
		return nil
	}

	bodyLower := strings.ToLower(resp.Body)

	formActionRe := regexp.MustCompile(`(?i)<form[^>]*action\s*=\s*["']([^"']+)["']`)
	matches := formActionRe.FindAllStringSubmatch(resp.Body, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		action := match[1]

		if action == "" || action == "#" || strings.HasPrefix(action, "/") || strings.HasPrefix(action, "./") {
			continue
		}

		actionURL, err := url.Parse(action)
		if err != nil {
			continue
		}

		if actionURL.Scheme == "" {
			continue
		}

		targetParsed, _ := url.Parse(target.URL)
		if targetParsed != nil && actionURL.Hostname() != targetParsed.Hostname() {
			hasPasswordField := strings.Contains(bodyLower, "type=\"password\"") ||
				strings.Contains(bodyLower, "type='password'") ||
				strings.Contains(bodyLower, "name=\"password\"") ||
				strings.Contains(bodyLower, "name='password'")

			if hasPasswordField {
				findings = append(findings, &models.Finding{
					Title:       "Credential Harvesting Form Detected",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         target.URL,
					Payload:     action,
					Evidence:    fmt.Sprintf("Form submits credentials to external URL: %s", action),
					Description: "A form with password fields submits data to an external domain, indicating credential harvesting.",
					Remediation: "Investigate the form submission endpoint. Ensure all credential forms submit to trusted first-party domains.",
					CWEID:       "CWE-522",
					ModuleID:    "phish",
				})
			}
		}
	}

	return findings
}

var passwordResetPaths = []string{
	"/reset", "/forgot", "/forgot-password", "/password-reset",
	"/reset-password", "/recover", "/account/recover",
	"/forgotpassword", "/lost-password",
}

func (m *PhishModule) checkFakePasswordReset(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	for _, path := range passwordResetPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 {
			continue
		}

		bodyLower := strings.ToLower(resp.Body)
		resetIndicators := []string{"reset", "forgot", "recover", "email", "password",
			"send", "submit", "verify"}

		matched := 0
		for _, ind := range resetIndicators {
			if strings.Contains(bodyLower, ind) {
				matched++
			}
		}

		if matched >= 4 {
			parsedURL, _ := url.Parse(target.URL)
			domain := ""
			if parsedURL != nil {
				domain = parsedURL.Hostname()
			}

			hasForm := strings.Contains(bodyLower, "<form") || strings.Contains(bodyLower, "<input")
			hasSubmit := strings.Contains(bodyLower, "type=\"submit\"") ||
				strings.Contains(bodyLower, "type='submit'")

			if hasForm && hasSubmit {
				findings = append(findings, &models.Finding{
					Title:       "Fake Password Reset Page Detected",
					Severity:    models.Critical,
					Confidence:  models.MediumConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("Password reset form found at %s on domain %s", path, domain),
					Description: "Password reset page detected. Verify this is a legitimate password reset form and not a phishing page designed to steal credentials.",
					Remediation: "Ensure password reset functionality uses proper validation. Monitor for phishing pages mimicking reset flows.",
					CWEID:       "CWE-522",
					ModuleID:    "phish",
				})
			}
		}
	}

	return findings
}

func (m *PhishModule) checkLookalikeDomain(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	resp, err := m.client.Get(target.URL)
	if err != nil {
		return nil
	}

	body := resp.Body

	lookalikeRe := regexp.MustCompile(`(?i)([a-zA-Z0-9][^\s<>"']*\.[a-zA-Z]{2,})`)
	domainsInPage := lookalikeRe.FindAllString(body, -1)

	parsedTarget, _ := url.Parse(target.URL)
	targetDomain := ""
	if parsedTarget != nil {
		targetDomain = parsedTarget.Hostname()
	}

	if targetDomain == "" {
		return nil
	}

	homographPatterns := []string{
		`\u0430`, `\u0435`, `\u043E`, `\u0440`, `\u0441`, `\u0443`, `\u0445`,
		`\u00E0`, `\u00E1`, `\u00E2`, `\u00E3`, `\u00E4`, `\u00E5`,
		`\u00E8`, `\u00E9`, `\u00EA`, `\u00EB`,
		`\u00EC`, `\u00ED`, `\u00EE`, `\u00EF`,
		`\u00F2`, `\u00F3`, `\u00F4`, `\u00F5`, `\u00F6`,
		`\u00F9`, `\u00FA`, `\u00FB`, `\u00FC`,
	}

	for _, dom := range domainsInPage {
		dom = strings.TrimSpace(dom)
		if dom == "" || strings.EqualFold(dom, targetDomain) {
			continue
		}

		for _, homo := range homographPatterns {
			if strings.Contains(dom, homo) {
				findings = append(findings, &models.Finding{
					Title:       "Homograph Attack Detected in Page Content",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         target.URL,
					Evidence:    fmt.Sprintf("Lookalike domain with homograph characters found: %s", dom),
					Description: fmt.Sprintf("Domain %s contains homograph (internationalized) characters that could be used for phishing by mimicking a legitimate domain.", dom),
					Remediation: "Consider registering internationalized domain variants. Implement IDN homograph attack detection in security monitoring.",
					CWEID:       "CWE-200",
					ModuleID:    "phish",
				})
				break
			}
		}
	}

	targetParts := strings.Split(targetDomain, ".")
	if len(targetParts) >= 2 {
		baseDomain := targetParts[len(targetParts)-2]

		for _, dom := range domainsInPage {
			dom = strings.TrimSpace(dom)
			if strings.Contains(dom, baseDomain) && !strings.EqualFold(dom, targetDomain) {
				seenHomograph := false
				for _, homo := range homographPatterns {
					if strings.Contains(dom, homo) {
						seenHomograph = true
						break
					}
				}

				if !seenHomograph {
					domParts := strings.Split(dom, ".")
					if len(domParts) >= 2 {
						domBase := domParts[len(domParts)-2]
						if strings.EqualFold(domBase, baseDomain) && !strings.EqualFold(dom, targetDomain) {
							findings = append(findings, &models.Finding{
								Title:       "Potential Domain Typo-Squatting in Page Content",
								Severity:    models.Medium,
								Confidence:  models.LowConfidence,
								URL:         target.URL,
								Evidence:    fmt.Sprintf("Domain similar to target referenced in page: %s", dom),
								Description: fmt.Sprintf("Page references domain %s which is similar to the target domain %s. Could indicate typo-squatting or a related phishing infrastructure.", dom, targetDomain),
								Remediation: "Monitor for typo-squatting domains. Consider defensive registration of similar domains.",
								CWEID:       "CWE-200",
								ModuleID:    "phish",
							})
						}
					}
				}
			}
		}
	}

	return findings
}

func init() {
	engine.GetRegistry().Register(&PhishModule{})
}
