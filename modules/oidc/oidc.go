package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type OIDCModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *OIDCModule) ID() string   { return "oidc" }
func (m *OIDCModule) Name() string { return "OpenID Connect Security Scanner" }
func (m *OIDCModule) Description() string {
	return "OIDC discovery, token endpoint auth check, redirect URI validation, JWKS exposure, claim injection"
}
func (m *OIDCModule) Severity() models.Severity { return models.Critical }

type OIDCDiscovery struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	JWKSUri                          string   `json:"jwks_uri"`
	RegistrationEndpoint             string   `json:"registration_endpoint"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

func (m *OIDCModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *OIDCModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkDiscoveryEndpoint(ctx, target)...)
	findings = append(findings, m.checkTokenEndpointAuth(ctx, target)...)
	findings = append(findings, m.checkRedirectURIValidation(ctx, target)...)
	findings = append(findings, m.checkJWKSExposure(ctx, target)...)
	findings = append(findings, m.checkClaimInjection(ctx, target)...)

	return findings, nil
}

func (m *OIDCModule) checkDiscoveryEndpoint(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	discoveryPaths := []string{
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
		"/oauth/.well-known/openid-configuration",
		"/auth/.well-known/openid-configuration",
		"/.well-known/webfinger",
	}

	for _, path := range discoveryPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		discURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Get(discURL)
		if err != nil || resp == nil {
			continue
		}

		body := resp.Body
		status := resp.StatusCode

		if status == 200 {
			var disc OIDCDiscovery
			if err := json.Unmarshal([]byte(body), &disc); err != nil {
				continue
			}

			if disc.Issuer != "" || disc.TokenEndpoint != "" || disc.JWKSUri != "" {
				findings = append(findings, &models.Finding{
					Title:       "OIDC - Discovery Endpoint Exposed",
					Severity:    models.Medium,
					Confidence:  models.HighConfidence,
					URL:         discURL,
					Evidence:    fmt.Sprintf("HTTP 200 - Issuer: %s, Token: %s, JWKS: %s", disc.Issuer, disc.TokenEndpoint, disc.JWKSUri),
					Description: fmt.Sprintf("OpenID Connect discovery document is publicly accessible at %s. Exposes issuer URL, token endpoint, authorization endpoint, JWKS URI, and supported scopes.", path),
					Remediation: "Discovery endpoints are intentionally public per OIDC spec. Ensure the endpoints they reference have proper authentication and rate limiting. Monitor for abuse.",
					CWEID:       "CWE-200",
					ModuleID:    "oidc",
				})

				if disc.JWKSUri != "" {
					jwksAbs := disc.JWKSUri
					if !strings.HasPrefix(jwksAbs, "http") {
						jwksAbs = strings.TrimRight(target.URL, "/") + "/" + strings.TrimLeft(jwksAbs, "/")
					}
					findings = append(findings, &models.Finding{
						Title:       "OIDC - JWKS Endpoint Discovered",
						Severity:    models.Info,
						Confidence:  models.HighConfidence,
						URL:         jwksAbs,
						Evidence:    fmt.Sprintf("JWKS URI from discovery: %s", disc.JWKSUri),
						Description: "JSON Web Key Set (JWKS) endpoint discovered from OIDC configuration. Contains public keys for ID token and access token verification.",
						Remediation: "Ensure JWKS serves only public keys, never private keys. Rotate signing keys periodically.",
						CWEID:       "CWE-200",
						ModuleID:    "oidc",
					})
				}

				if containsInsecureAlg(disc.IDTokenSigningAlgValuesSupported) {
					findings = append(findings, &models.Finding{
						Title:       "OIDC - Weak Signing Algorithm Supported",
						Severity:    models.High,
						Confidence:  models.HighConfidence,
						URL:         discURL,
						Evidence:    fmt.Sprintf("Supported algorithms: %v", disc.IDTokenSigningAlgValuesSupported),
						Description: "The OIDC provider supports 'none' or 'HS256' as ID token signing algorithms. The 'none' algorithm bypasses signature verification entirely. HS256 can enable key confusion attacks where the public key is used as the HMAC secret.",
						Remediation: "Disable 'none' and symmetric HMAC algorithms (HS256/HS384/HS512) for ID tokens. Use only asymmetric RS256, RS384, RS512, ES256, ES384, ES512 or EdDSA.",
						CWEID:       "CWE-287",
						ModuleID:    "oidc",
					})
				}
			}
		}
	}

	return findings
}

func (m *OIDCModule) checkTokenEndpointAuth(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	tokenPaths := []string{
		"/token", "/oauth/token", "/oauth2/token",
		"/auth/token", "/api/token", "/connect/token",
		"/v1/token", "/v2/token",
	}

	noAuthPayloads := []struct {
		name string
		body string
	}{
		{
			name: "No Client Credentials",
			body: "grant_type=client_credentials",
		},
		{
			name: "Empty Client ID and Secret",
			body: "grant_type=client_credentials&client_id=&client_secret=",
		},
		{
			name: "Authorization Code Grant Without Code",
			body: "grant_type=authorization_code&redirect_uri=https://attacker.evil.com/callback",
		},
		{
			name: "Refresh Token Grant",
			body: "grant_type=refresh_token&refresh_token=test_invalid_token",
		},
		{
			name: "Password Grant No Credentials",
			body: "grant_type=password&username=&password=",
		},
	}

	for _, tp := range tokenPaths {
		for _, payload := range noAuthPayloads {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			tokenURL := strings.TrimRight(target.URL, "/") + tp
			req := fanghttp.NewRequest("POST", tokenURL)
			req.Headers["Content-Type"] = "application/x-www-form-urlencoded"
			req.Body = payload.body

			resp, err := m.client.Do(req)
			if err != nil || resp == nil {
				continue
			}

			status := resp.StatusCode
			body := resp.Body

			if status == 200 {
				var tokenResp map[string]interface{}
				if err := json.Unmarshal([]byte(body), &tokenResp); err == nil {
					if _, hasAccessToken := tokenResp["access_token"]; hasAccessToken {
						findings = append(findings, &models.Finding{
							Title:       "OIDC - Token Endpoint Issues Token Without Auth",
							Severity:    models.Critical,
							Confidence:  models.CriticalConfidence,
							URL:         tokenURL,
							Payload:     payload.body,
							Evidence:    fmt.Sprintf("HTTP 200 - Access token returned for: %s", payload.name),
							Description: fmt.Sprintf("Token endpoint %s returned an access token without valid client authentication. This allows unauthenticated token issuance.", tp),
							Remediation: "Require client authentication (client_id + client_secret, client_assertion, or private_key_jwt) for all token endpoint requests. Validate all grant types. Implement PKCE for authorization code flow.",
							CWEID:       "CWE-287",
							ModuleID:    "oidc",
						})
					}
				}

				if strings.Contains(strings.ToLower(body), "access_token") {
					findings = append(findings, &models.Finding{
						Title:       "OIDC - Token Endpoint Responds Without Auth",
						Severity:    models.High,
						Confidence:  models.MediumConfidence,
						URL:         tokenURL,
						Payload:     payload.body,
						Evidence:    fmt.Sprintf("HTTP 200 with response body containing access_token reference for: %s", payload.name),
						Description: fmt.Sprintf("Token endpoint %s responded with HTTP 200 to an unauthenticated request. While the response may indicate an error, the endpoint should return 401 Unauthorized.", tp),
						Remediation: "Return HTTP 401 Unauthorized for unauthenticated token requests. Validate client credentials before processing any grant type.",
						CWEID:       "CWE-287",
						ModuleID:    "oidc",
					})
				}
			}

			if status == 302 || status == 303 {
				location := resp.Redirect
				if location != "" && !strings.Contains(location, target.URL) {
					findings = append(findings, &models.Finding{
						Title:       "OIDC - Token Endpoint Redirects Without Auth",
						Severity:    models.High,
						Confidence:  models.MediumConfidence,
						URL:         tokenURL,
						Payload:     payload.body,
						Evidence:    fmt.Sprintf("HTTP %d redirect to: %s", status, location),
						Description: "Token endpoint redirects unauthenticated requests. This may leak information or enable open redirect attacks.",
						Remediation: "Return HTTP 401 instead of redirecting. Validate redirect URIs against a whitelist.",
						CWEID:       "CWE-287",
						ModuleID:    "oidc",
					})
				}
			}
		}
	}

	return findings
}

func (m *OIDCModule) checkRedirectURIValidation(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	authPaths := []string{
		"/auth", "/oauth/auth", "/oauth2/auth",
		"/authorize", "/oauth/authorize", "/oauth2/authorize",
		"/connect/authorize", "/api/auth",
	}

	redirectURIs := []struct {
		name string
		uri  string
	}{
		{name: "Open Redirect", uri: "https://attacker.evil.com/callback"},
		{name: "XSS via javascript:", uri: "javascript:alert(1)"},
		{name: "Localhost Redirect", uri: "http://localhost:8080/callback"},
		{name: "Path Traversal in Redirect", uri: "https://target.com.evil.com/callback"},
		{name: "Data URI", uri: "data:text/html,<script>alert(1)</script>"},
		{name: "DNS Rebinding", uri: "http://127.0.0.1.xip.io/callback"},
		{name: "Unregistered Scheme", uri: "customapp://attacker.evil.com/callback"},
	}

	for _, ap := range authPaths {
		for _, ru := range redirectURIs {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			authURL := strings.TrimRight(target.URL, "/") + ap +
				"?response_type=code&client_id=test-client&redirect_uri=" + ru.uri +
				"&scope=openid%20profile&state=test_state"

			resp, err := m.client.Get(authURL)
			if err != nil || resp == nil {
				continue
			}

			status := resp.StatusCode
			location := resp.Redirect
			body := resp.Body

			if status >= 300 && status < 400 && location != "" {
				locLower := strings.ToLower(location)
				containsAttacker := strings.Contains(locLower, "attacker.evil.com") ||
					strings.Contains(locLower, "evil.com") ||
					strings.Contains(locLower, "xip.io")

				if containsAttacker || strings.Contains(locLower, "javascript:") ||
					strings.Contains(locLower, "data:") ||
					strings.Contains(locLower, "localhost") ||
					strings.HasSuffix(strings.Split(locLower, "/")[0], ".evil.com") {
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("OIDC - Open Redirect via redirect_uri (%s)", ru.name),
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         authURL,
						Payload:     ru.uri,
						Evidence:    fmt.Sprintf("HTTP %d redirect to: %s", status, location),
						Description: fmt.Sprintf("OIDC authorization endpoint redirects to attacker-controlled URI: %s. This allows authorization code interception and open redirect attacks.", ru.name),
						Remediation: "Whitelist allowed redirect URIs. Do not accept arbitrary redirect_uri values. Validate against exact match or registered URI patterns. Reject URIs with javascript:, data:, or foreign schemes.",
						CWEID:       "CWE-287",
						ModuleID:    "oidc",
					})
				}
			}

			if status == 200 {
				bodyLower := strings.ToLower(body)
				if strings.Contains(bodyLower, ru.uri) || strings.Contains(bodyLower, "attacker.evil.com") {
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("OIDC - redirect_uri Reflected in Response (%s)", ru.name),
						Severity:    models.Medium,
						Confidence:  models.HighConfidence,
						URL:         authURL,
						Payload:     ru.uri,
						Evidence:    "HTTP 200 - redirect_uri value reflected in response body",
						Description: "redirect_uri parameter value is reflected in the response body. This could indicate lack of validation and enables open redirect or XSS if HTML injection is possible.",
						Remediation: "Validate redirect_uri against a whitelist. Do not reflect user input in responses without proper encoding.",
						CWEID:       "CWE-200",
						ModuleID:    "oidc",
					})
				}
			}
		}
	}

	return findings
}

func (m *OIDCModule) checkJWKSExposure(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	jwksPaths := []string{
		"/.well-known/jwks", "/.well-known/jwks.json",
		"/jwks", "/jwks.json", "/oauth/jwks",
		"/oauth2/jwks", "/auth/jwks", "/api/jwks",
		"/connect/jwks", "/certs", "/keys",
		"/signing_keys", "/discovery/keys",
	}

	for _, jp := range jwksPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		jwksURL := strings.TrimRight(target.URL, "/") + jp
		resp, err := m.client.Get(jwksURL)
		if err != nil || resp == nil {
			continue
		}

		status := resp.StatusCode
		body := resp.Body

		if status == 200 {
			var parsed map[string]interface{}
			if err := json.Unmarshal([]byte(body), &parsed); err != nil {
				continue
			}

			if keys, ok := parsed["keys"]; ok {
				if keyArr, ok := keys.([]interface{}); ok && len(keyArr) > 0 {
					var keyKIDs []string
					for _, k := range keyArr {
						if keyMap, ok := k.(map[string]interface{}); ok {
							if kid, hasKID := keyMap["kid"]; hasKID {
								keyKIDs = append(keyKIDs, fmt.Sprintf("%v", kid))
							}
						}
					}

					findings = append(findings, &models.Finding{
						Title:       "OIDC - JWKS Endpoint Exposed Without Auth",
						Severity:    models.Medium,
						Confidence:  models.HighConfidence,
						URL:         jwksURL,
						Evidence:    fmt.Sprintf("HTTP 200 - %d keys found. KIDs: %s", len(keyArr), strings.Join(keyKIDs, ", ")),
						Description: fmt.Sprintf("JWKS endpoint %s is publicly accessible without authentication. Exposes %d public signing keys. This is expected per OIDC spec for key distribution but should be monitored.", jp, len(keyArr)),
						Remediation: "JWKS endpoints are intentionally public for token verification. Ensure only public keys are exposed. Implement rate limiting. Rotate keys and maintain a transition period for key rotation.",
						CWEID:       "CWE-200",
						ModuleID:    "oidc",
					})

					if len(keyArr) > 10 {
						findings = append(findings, &models.Finding{
							Title:       "OIDC - Excessive JWKS Keys Exposed",
							Severity:    models.Low,
							Confidence:  models.MediumConfidence,
							URL:         jwksURL,
							Evidence:    fmt.Sprintf("%d keys in JWKS endpoint", len(keyArr)),
							Description: "JWKS endpoint exposes more than 10 keys. Excessive key exposure increases attack surface and may indicate poor key management practices.",
							Remediation: "Keep only active signing keys in the JWKS set. Rotate keys on a defined schedule. Remove expired or deprecated keys.",
							CWEID:       "CWE-200",
							ModuleID:    "oidc",
						})
					}
				}
			}
		}
	}

	return findings
}

func (m *OIDCModule) checkClaimInjection(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	userinfoPaths := []string{
		"/userinfo", "/oauth/userinfo", "/oauth2/userinfo",
		"/auth/userinfo", "/api/userinfo", "/connect/userinfo",
		"/me", "/profile",
	}

	tokenPaths := []string{
		"/token", "/oauth/token", "/oauth2/token",
		"/auth/token", "/connect/token",
	}

	claimPayloads := []struct {
		name   string
		claims string
	}{
		{
			name:   "Admin Role Injection",
			claims: `{"sub":"test_user","email":"admin@target.com","roles":["admin","super_admin"],"https://target.com/claims/role":"GlobalAdministrator"}`,
		},
		{
			name:   "Email Verification Bypass",
			claims: `{"sub":"test_user","email":"admin@target.com","email_verified":true}`,
		},
		{
			name:   "Extra Claim Overwrite",
			claims: `{"sub":"test_user","name":"Injected Admin","preferred_username":"admin","https://target.com/claims/is_admin":true}`,
		},
		{
			name:   "Custom Namespace Injection",
			claims: `{"sub":"test_user","https://attacker.evil.com/claims/trusted":true,"https://target.com/claims/admin":true}`,
		},
		{
			name:   "Array Injection",
			claims: `{"sub":"test_user","groups":["Domain Admins","Enterprise Admins","Schema Admins"]}`,
		},
	}

	for _, up := range userinfoPaths {
		userinfoURL := strings.TrimRight(target.URL, "/") + up
		req := fanghttp.NewRequest("GET", userinfoURL)
		req.Headers["Content-Type"] = "application/json"

		resp, err := m.client.Do(req)
		if err != nil || resp == nil {
			continue
		}

		status := resp.StatusCode
		body := resp.Body

		if status == 200 {
			var parsedClaims map[string]interface{}
			if err := json.Unmarshal([]byte(body), &parsedClaims); err != nil {
				continue
			}

			if sub, ok := parsedClaims["sub"]; ok && sub != "" {
				findings = append(findings, &models.Finding{
					Title:       "OIDC - UserInfo Endpoint Accessible Without Token",
					Severity:    models.High,
					Confidence:  models.MediumConfidence,
					URL:         userinfoURL,
					Evidence:    fmt.Sprintf("HTTP 200 - Returned claims without Bearer token: sub=%v", sub),
					Description: fmt.Sprintf("UserInfo endpoint %s returns claims without requiring a valid Bearer token. User attributes are exposed to unauthenticated requests.", up),
					Remediation: "Require a valid Bearer access token for all UserInfo endpoint requests. Validate token signature, expiry, and audience.",
					CWEID:       "CWE-287",
					ModuleID:    "oidc",
				})
			}
		}
	}

	for _, tp := range tokenPaths {
		tokenURL := strings.TrimRight(target.URL, "/") + tp

		for _, cp := range claimPayloads {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			req := fanghttp.NewRequest("POST", tokenURL)
			req.Headers["Content-Type"] = "application/json"
			req.Body = fmt.Sprintf(`{
				"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange",
				"subject_token":"test_token",
				"subject_token_type":"urn:ietf:params:oauth:token-type:access_token",
				"requested_claims":%s
			}`, cp.claims)

			resp, err := m.client.Do(req)
			if err != nil || resp == nil {
				continue
			}

			status := resp.StatusCode
			body := resp.Body

			if status == 200 {
				var tokenResp map[string]interface{}
				if err := json.Unmarshal([]byte(body), &tokenResp); err == nil {
					if _, ok := tokenResp["access_token"]; ok {
						findings = append(findings, &models.Finding{
							Title:       fmt.Sprintf("OIDC - Claim Injection Possible (%s)", cp.name),
							Severity:    models.Critical,
							Confidence:  models.MediumConfidence,
							URL:         tokenURL,
							Payload:     cp.claims,
							Evidence:    "HTTP 200 - Token returned with injected claims via token exchange",
							Description: fmt.Sprintf("OIDC token endpoint accepted requested_claims %s without validation. An attacker can inject arbitrary claims to escalate privileges or bypass access controls.", cp.name),
							Remediation: "Validate all requested claims against a whitelist. Restrict token exchange grant type to authorized clients. Do not allow clients to request arbitrary claims without verification.",
							CWEID:       "CWE-287",
							ModuleID:    "oidc",
						})
					}
				}
			}

			if status == 200 {
				if strings.Contains(strings.ToLower(body), "access_token") || strings.Contains(strings.ToLower(body), "id_token") {
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("OIDC - Token Exchange Accepts Claims (%s)", cp.name),
						Severity:    models.High,
						Confidence:  models.LowConfidence,
						URL:         tokenURL,
						Payload:     cp.claims,
						Evidence:    "HTTP 200 - Token endpoint responded to token exchange with claims injection",
						Description: fmt.Sprintf("Token exchange with injected claims %s received a response. Further manual testing needed to confirm claim acceptance.", cp.name),
						Remediation: "Restrict token exchange capabilities. Validate all claims in token exchange requests against a whitelist.",
						CWEID:       "CWE-287",
						ModuleID:    "oidc",
					})
				}
			}
		}
	}

	return findings
}

func containsInsecureAlg(algs []string) bool {
	for _, a := range algs {
		switch a {
		case "none", "HS256", "HS384", "HS512":
			return true
		}
	}
	return false
}

func init() {
	engine.GetRegistry().Register(&OIDCModule{})
}
