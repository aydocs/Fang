package payment

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type PaymentModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *PaymentModule) ID() string   { return "payment" }
func (m *PaymentModule) Name() string { return "Payment Systems & Card Testing Module" }
func (m *PaymentModule) Description() string {
	return "Multi-gateway card validation, digital skimmer detection, bank trojan web inject detection, BIN lookup, and gateway identification"
}
func (m *PaymentModule) Severity() models.Severity { return models.Critical }

func (m *PaymentModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *PaymentModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	resp, err := m.client.Get(target.URL)
	if err != nil {
		return nil, err
	}
	body := resp.Body

	findings = append(findings, m.validateGatewayCard(ctx, target, body)...)
	findings = append(findings, m.checkSkimmer(ctx, target, body)...)
	findings = append(findings, m.checkWebInject(ctx, target, body)...)
	findings = append(findings, m.checkBINEndpoints(ctx, target)...)
	findings = append(findings, m.detectPaymentGateway(ctx, target, body)...)

	return findings, nil
}

func (m *PaymentModule) validateGatewayCard(ctx context.Context, target *models.Target, body string) []*models.Finding {
	var findings []*models.Finding

	gateways := []struct {
		name   string
		paths  []string
		checks []string
	}{
		{name: "Stripe", paths: []string{"/api/stripe/charge", "/stripe/charge", "/charge", "/api/charge", "/payment", "/api/payment"}, checks: []string{"stripe", "Stripe", "pk_live", "sk_live", "tok_", "pi_", "cs_"}},
		{name: "PayPal", paths: []string{"/api/paypal", "/paypal", "/api/payment", "/checkout"}, checks: []string{"paypal", "PayPal", "paypal.com", "PAYPAL"}},
		{name: "Adyen", paths: []string{"/api/adyen", "/adyen", "/checkoutshopper"}, checks: []string{"adyen", "Adyen", "checkoutshopper", "AdyenJS"}},
		{name: "Shopify", paths: []string{"/api/shopify", "/shopify", "/admin/orders"}, checks: []string{"shopify", "ShopifyPay", "myshopify", "shopify.com"}},
		{name: "Braintree", paths: []string{"/api/braintree", "/braintree", "/v1/braintree"}, checks: []string{"braintree", "Braintree", "data-braintree", "BraintreeJS"}},
		{name: "Square", paths: []string{"/api/square", "/square", "/v2/square"}, checks: []string{"square", "SquarePayment", "sq.payment", "squareup"}},
		{name: "Authorize.Net", paths: []string{"/api/authorize", "/authorize", "/api/authnet"}, checks: []string{"authorize", "AuthorizeNet", "acceptjs", "authnet"}},
		{name: "Worldpay", paths: []string{"/api/worldpay", "/worldpay"}, checks: []string{"worldpay", "Worldpay", "wpobject", "worldpayjs"}},
	}

	for _, g := range gateways {
		for _, path := range g.paths {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			fullURL := strings.TrimRight(target.URL, "/") + path
			testPayload := `{"cardNumber":"4111111111111111","expMonth":"12","expYear":"2028","cvv":"123","amount":0,"currency":"USD"}`
			resp, err := m.client.Post(fullURL, testPayload)
			if err != nil {
				continue
			}

			bodyLower := strings.ToLower(resp.Body)
			for _, check := range g.checks {
				if strings.Contains(bodyLower, strings.ToLower(check)) {
					findings = append(findings, m.makeFinding(
						"Payment - Card Validation Endpoint ($0 Auth)",
						models.High, models.HighConfidence,
						fullURL, "card", testPayload,
						fmt.Sprintf("%s gateway charge endpoint responds: matched '%s' (status: %d)", g.name, check, resp.StatusCode),
						"%s gateway card validation endpoint accessible. $0 authorization checks may be possible.",
						"Implement proper authentication on charge endpoints. Use 3D Secure. Monitor for $0 auth probing. Rate limit payment API calls.",
						"CWE-306",
					))
					break
				}
			}

			if resp.StatusCode == 200 && (strings.Contains(bodyLower, "approved") || strings.Contains(bodyLower, "success") || strings.Contains(bodyLower, "charge")) {
				findings = append(findings, m.makeFinding(
					"Payment - Unauthenticated Charge Attempt",
					models.Critical, models.MediumConfidence,
					fullURL, "card", testPayload,
					fmt.Sprintf("%s gateway endpoint accepted $0 auth request (status: %d)", g.name, resp.StatusCode),
					"%s gateway endpoint accepted a $0 authorization without authentication. Real card charging may be possible.",
					"Require authentication for all payment operations. Implement rate limiting and fraud detection. Use idempotency keys.",
					"CWE-306",
				))
			}
		}
	}

	bins := []string{"411111", "555555", "378282", "601111", "353011", "305693", "385200"}
	binPaths := []string{"/api/bin", "/bin-check", "/card-type", "/validate-card", "/binlist", "/api/card-type", "/cc-check"}
	for _, bin := range bins {
		for _, path := range binPaths {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			fullURL := strings.TrimRight(target.URL, "/") + path
			resp, err := m.client.Post(fullURL, fmt.Sprintf(`{"bin":"%s"}`, bin))
			if err != nil {
				continue
			}
			if resp.StatusCode != 200 {
				continue
			}

			bodyLower := strings.ToLower(resp.Body)
			fingerprints := []string{"visa", "mastercard", "amex", "discover", "jcb", "diners", "maestro", "brand", "scheme", "card", "bin", "bank", "issuer", "country", "type", "funding", "prepaid"}
			for _, fp := range fingerprints {
				if strings.Contains(bodyLower, fp) {
					findings = append(findings, m.makeFinding(
						fmt.Sprintf("Payment - BIN Fingerprinting (%s)", bin[:4]+"******"),
						models.High, models.HighConfidence,
						fullURL, "bin", bin,
						fmt.Sprintf("BIN %s returns card metadata (matched: '%s')", bin, fp),
						"BIN lookup endpoint returns card metadata including brand, type, and issuer. Enables BIN attack pre-screening.",
						"Rate limit BIN lookups. Log and monitor BIN queries. Implement anomaly detection on rapid BIN checks.",
						"CWE-200",
					))
					break
				}
			}
		}
	}

	return findings
}

func (m *PaymentModule) checkSkimmer(ctx context.Context, target *models.Target, body string) []*models.Finding {
	var findings []*models.Finding

	if strings.Contains(body, "cc-number") || strings.Contains(body, "cardnumber") ||
		strings.Contains(body, "card-number") || strings.Contains(body, "cardNumber") ||
		strings.Contains(body, "ccname") || strings.Contains(body, "cc_cvv") ||
		strings.Contains(body, "cc-number") {
		findings = append(findings, &models.Finding{
			Title:       "Payment - Credit Card Form Detected",
			Severity:    models.High,
			Confidence:  models.HighConfidence,
			URL:         target.URL,
			Evidence:    "Credit card input fields detected on page",
			Description: "Credit card input form detected. Check for PCI compliance: forms should not store full PAN, CVV, or track data client-side.",
			Remediation: "Use iframe-based payment forms (Stripe Elements, Braintree Drop-in). Never store CVV. Implement PCI DSS SAQ validation.",
			CWEID:       "CWE-312",
			ModuleID:    "payment",
		})
	}

	skimmerPatterns := []string{
		"eval(atob(", "eval(atob)", "document.write(atob",
		"new Function(atob", "setTimeout(atob",
		"setInterval(atob", "requestAnimationFrame(atob",
		"webpackChunk", "jgldkfjg", "skdjfhg",
		"atob('", "atob(\"", "atob(`",
		"btoa(escape", "unescape(btoa",
		"fromCharCode", "\\x62\\x75\\x72",
	}

	for _, pat := range skimmerPatterns {
		if strings.Contains(body, pat) {
			findings = append(findings, &models.Finding{
				Title:       "Payment - Digital Skimmer (MageCart Pattern)",
				Severity:    models.Critical,
				Confidence:  models.MediumConfidence,
				URL:         target.URL,
				Evidence:    fmt.Sprintf("MageCart skimmer pattern: %s", pat),
				Description: "Potential digital card skimmer (MageCart-style) detected. JavaScript may be exfiltrating payment data via obfuscated eval(atob) calls.",
				Remediation: "Review all third-party scripts. Implement CSP with strict connect-src. Use Subresource Integrity (SRI) for all scripts. Monitor for DOM changes.",
				CWEID:       "CWE-506",
				ModuleID:    "payment",
			})
			break
		}
	}

	mageCartPatterns := []string{
		"swiper", "slide", "carousel", "slick",
		"analytics.js", "gtag", "ga('create'",
		"stripe.connect", "braintree.connect",
	}
	for _, pat := range mageCartPatterns {
		if strings.Contains(body, pat) && strings.Contains(body, "src=\"") {
			scripts := m.extractExternalScripts(body)
			for _, s := range scripts {
				if !strings.Contains(s, target.Domain) && !strings.Contains(s, "google") &&
					!strings.Contains(s, "facebook") && !strings.Contains(s, "jquery") &&
					!strings.Contains(s, "stripe.com") && !strings.Contains(s, "braintree") {
					findings = append(findings, &models.Finding{
						Title:       "Payment - Third-Party Script on Payment Page",
						Severity:    models.High,
						Confidence:  models.LowConfidence,
						URL:         target.URL,
						Evidence:    fmt.Sprintf("Third-party script: %s (skimmer pattern: %s)", s, pat),
						Description: "Third-party script loaded on payment page with patterns resembling MageCart skimmers. May be exfiltrating payment data.",
						Remediation: "Audit all third-party scripts. Remove unnecessary scripts from payment pages. Use SRI and strict CSP.",
						CWEID:       "CWE-829",
						ModuleID:    "payment",
					})
				}
			}
		}
	}

	externalScripts := m.extractExternalScripts(body)
	for _, s := range externalScripts {
		if !strings.Contains(s, target.Domain) && !strings.Contains(s, "google") &&
			!strings.Contains(s, "facebook") && !strings.Contains(s, "jquery") &&
			!strings.Contains(s, "stripe.com") && !strings.Contains(s, "braintree") &&
			!strings.Contains(s, "paypal") && !strings.Contains(s, "square") {
			if strings.HasPrefix(s, "//") || strings.HasPrefix(s, "http") {
				findings = append(findings, &models.Finding{
					Title:       "Payment - External Script (Skimmer Risk)",
					Severity:    models.High,
					Confidence:  models.LowConfidence,
					URL:         target.URL,
					Evidence:    fmt.Sprintf("External script loaded: %s", s),
					Description: "External JavaScript loaded on payment page. Could be compromised for digital skimming (MageCart-style attack).",
					Remediation: "Audit all third-party scripts on payment pages. Use SRI hashes. Minimize external dependencies.",
					CWEID:       "CWE-829",
					ModuleID:    "payment",
				})
			}
		}
	}

	return findings
}

func (m *PaymentModule) checkWebInject(ctx context.Context, target *models.Target, body string) []*models.Finding {
	var findings []*models.Finding

	bankPatterns := []string{
		"bank", "banks", "banking",
		"chase", "chase.com", "wellsfargo", "wells fargo",
		"bankofamerica", "bank of america", "bofa",
		"citi", "citibank", "citicards",
		"capitalone", "capital one",
		"usbank", "us bank",
		"pnc", "pncbank",
		"tdbank", "td bank",
		"hsbc", "hsbc.com",
		"barclays", "barclaycard",
		"natwest", "nationwide",
		"lloyds", "lloydsbank",
		"halifax", "halifax.co.uk",
		"santander", "santander.com",
		"deutsche", "deutschebank",
		"commerzbank", "commerz",
		"postbank", "sparkasse",
		"bnpparibas", "bnp paribas",
		"societegenerale", "societe generale",
		"creditagricole", "credit agricole",
		"ing", "ingbank",
		"abnamro", "abn amro",
		"rabobank", "rabo",
		"ubs", "ubs.com",
		"credit-suisse", "creditsuisse",
		"scotiabank", "rbcroyalbank",
		"tdcanadatrust", "bmo",
		"cibc", "nationalbank",
		"mitsubishi", "mufg",
		"sumitomo", "mizuho",
		"anz", "commbank",
		"westpac", "nab",
		"dbs", "ocbc", "uob",
		"standardbank", "absa",
		"firstrand", "nedbank",
	}

	for _, pat := range bankPatterns {
		if strings.Contains(strings.ToLower(body), pat) {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			injectIndicators := []string{
				"src=\"", "src='", "<form", "<input", "action=\"",
				"document.getElementById", "document.getElementsByName",
				"innerHTML", "outerHTML", "insertAdjacentHTML",
				"submit", "onclick", "onchange",
			}

			injectScore := 0
			for _, ind := range injectIndicators {
				if strings.Contains(body, ind) {
					injectScore++
				}
			}

			if injectScore >= 3 {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("Payment - Bank Web Inject Detected (%s)", pat),
					Severity:    models.Critical,
					Confidence:  models.MediumConfidence,
					URL:         target.URL,
					Evidence:    fmt.Sprintf("Bank pattern '%s' found with form injection indicators (score: %d/8)", pat, injectScore),
					Description: "Bank trojan-style web inject detected. Page contains bank branding with form injection characteristics used by ZeuS, SpyEye, Gozi, and other banking trojans.",
					Remediation: "Verify page integrity with SRI. Monitor for unexpected DOM modifications. Implement OTP/2FA for all financial transactions. Use endpoint security.",
					CWEID:       "CWE-506",
					ModuleID:    "payment",
				})
			}
		}
	}

	fakeFormPatterns := []string{
		"disabled=\"disabled\"", "readonly=\"readonly\"",
		"style=\"display:none\"", "style=\"visibility:hidden\"",
		"type=\"hidden\"", "autocomplete=\"off\"",
	}
	fakeFormCount := 0
	for _, pat := range fakeFormPatterns {
		if strings.Contains(body, pat) {
			fakeFormCount++
		}
	}
	if fakeFormCount >= 3 && strings.Contains(strings.ToLower(body), "bank") {
		findings = append(findings, &models.Finding{
			Title:       "Payment - Fake Bank Form Injection",
			Severity:    models.Critical,
			Confidence:  models.LowConfidence,
			URL:         target.URL,
			Evidence:    fmt.Sprintf("Suspicious form patterns detected (count: %d)", fakeFormCount),
			Description: "Potential fake bank form injection detected. Hidden/disabled form fields observed alongside bank-related content. May be phishing or web inject.",
			Remediation: "Verify page authenticity. Implement form integrity checks. Use security toolbar or bank-provided browsing solutions.",
			CWEID:       "CWE-506",
			ModuleID:    "payment",
		})
	}

	return findings
}

func (m *PaymentModule) extractExternalScripts(body string) []string {
	var scripts []string
	idx := 0
	for {
		srcIdx := strings.Index(body[idx:], "src=\"")
		if srcIdx == -1 {
			srcIdx = strings.Index(body[idx:], "src='")
		}
		if srcIdx == -1 {
			break
		}
		start := idx + srcIdx + 5
		end := strings.IndexAny(body[start:], "\"'")
		if end == -1 {
			break
		}
		scripts = append(scripts, body[start:start+end])
		idx = start + end
	}
	return scripts
}

func (m *PaymentModule) checkBINEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	binPaths := []string{"/api/bin", "/bin-check", "/card-type", "/validate-card", "/binlist",
		"/api/card-type", "/cc-check", "/card-check", "/api/binlist", "/v1/bin"}
	for _, p := range binPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := strings.TrimRight(target.URL, "/") + p
		resp, err := m.client.Post(fullURL, `{"bin":"411111"}`)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			for _, check := range []string{"bin", "brand", "scheme", "type", "bank", "country", "card", "issuer", "funding", "prepaid"} {
				if strings.Contains(strings.ToLower(resp.Body), check) {
					findings = append(findings, &models.Finding{
						Title:       "Payment - BIN Lookup Endpoint Exposed",
						Severity:    models.High,
						Confidence:  models.HighConfidence,
						URL:         fullURL,
						Payload:     `{"bin":"411111"}`,
						Evidence:    fmt.Sprintf("BIN lookup endpoint responds with card metadata (matched: '%s')", check),
						Description: "BIN (Bank Identification Number) lookup endpoint exposed. Can be abused for card enumeration and BIN attacks to pre-screen cards.",
						Remediation: "Authenticate BIN lookup endpoints. Implement rate limiting. Log all BIN lookup requests. Monitor for rapid BIN scanning.",
						CWEID:       "CWE-200",
						ModuleID:    "payment",
					})
					break
				}
			}
		}
	}
	return findings
}

func (m *PaymentModule) detectPaymentGateway(ctx context.Context, target *models.Target, body string) []*models.Finding {
	var findings []*models.Finding

	gateways := []struct {
		name   string
		checks []string
	}{
		{name: "Stripe", checks: []string{"stripe", "pk_live", "sk_live", "StripeCheckout", "Stripe.js", "stripe.com", "stripe.network"}},
		{name: "PayPal", checks: []string{"paypal", "paypal.com", " PayPal ", "paypalobjects", "PAYPAL", "paypal_checkout"}},
		{name: "Adyen", checks: []string{"adyen", "Adyen", "checkoutshopper", "adyenjs"}},
		{name: "Shopify Payments", checks: []string{"shopify", "myshopify", "ShopifyPay", "shopify.com"}},
		{name: "Braintree", checks: []string{"braintree", "Braintree", "data-braintree", "braintreejs"}},
		{name: "Square", checks: []string{"square", "SquarePayment", "sq.payment", "squareup.com"}},
		{name: "Authorize.Net", checks: []string{"authorize", "AuthorizeNet", "acceptjs", "authnet"}},
		{name: "Worldpay", checks: []string{"worldpay", "Worldpay", "wpobject", "worldpayjs"}},
		{name: "Mollie", checks: []string{"mollie", "Mollie", "mollie.com"}},
		{name: "Klarna", checks: []string{"klarna", "Klarna", "klarna.com"}},
		{name: "2Checkout", checks: []string{"2checkout", "2co", "twocheckout"}},
		{name: "Paddle", checks: []string{"paddle", "Paddle", "paddlejs"}},
		{name: "Razorpay", checks: []string{"razorpay", "Razorpay", "razorpay.com"}},
		{name: "PayU", checks: []string{"payu", "PayU", "payu.com"}},
		{name: "MercadoPago", checks: []string{"mercadopago", "MercadoPago", "mercadopago.com"}},
		{name: "PagSeguro", checks: []string{"pagseguro", "PagSeguro"}},
	}

	for _, g := range gateways {
		for _, check := range g.checks {
			if strings.Contains(body, check) {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("Payment - %s Gateway Detected", g.name),
					Severity:    models.Medium,
					Confidence:  models.HighConfidence,
					URL:         target.URL,
					Evidence:    fmt.Sprintf("Payment gateway identifier found: %s", check),
					Description: fmt.Sprintf("%s payment gateway detected on page. May expose API keys, webhook endpoints, or client-side tokens.", g.name),
					Remediation: "Ensure payment API keys are not exposed client-side. Use server-side tokenization. Implement PCI DSS compliance.",
					CWEID:       "CWE-200",
					ModuleID:    "payment",
				})
				break
			}
		}
	}

	return findings
}

func (m *PaymentModule) makeFinding(title string, severity models.Severity, confidence models.Confidence, urlStr, param, payload, evidence, description, remediation, cwe string) *models.Finding {
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
		ModuleID:    "payment",
	}
}

func init() {
	engine.GetRegistry().Register(&PaymentModule{})
}
