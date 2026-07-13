package deser

import (
	"context"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type DeserModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *DeserModule) ID() string   { return "deser" }
func (m *DeserModule) Name() string { return "Deserialization Attack Module" }
func (m *DeserModule) Description() string {
	return "Detects insecure deserialization in Java, .NET, Python, PHP, and Node.js"
}
func (m *DeserModule) Severity() models.Severity { return models.Critical }

type deserTest struct {
	Name    string
	Target  string
	Headers map[string]string
	Body    string
	Check   []string
}

func (m *DeserModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *DeserModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	tests := []deserTest{
		{
			Name: "Java-JBoss", Target: "/invoker/JMXInvokerServlet",
			Headers: map[string]string{"Content-Type": "application/x-java-serialized-object"},
			Body:    "ACED0005", Check: []string{"jboss", "JMX", "serialized"},
		},
		{
			Name: "Java-WebLogic", Target: "/wls-wsat/CoordinatorPortType",
			Headers: map[string]string{"Content-Type": "text/xml"},
			Body:    `<soap:Envelope><soap:Body><wls:test/></soap:Body></soap:Envelope>`,
			Check:   []string{"WebLogic", "wls", "BEA"},
		},
		{
			Name: "Java-Jenkins", Target: "/descriptorByName/",
			Check: []string{"Jenkins", "hudson", "jenkins"},
		},
		{
			Name: "Java-Apache-OFBiz", Target: "/webtools/control/main",
			Body:  `<soap:Envelope><soap:Body><test/></soap:Body></soap:Envelope>`,
			Check: []string{"OFBiz", "webtools"},
		},
		{
			Name: "DotNet-ViewState", Target: "/",
			Headers: map[string]string{"X-Requested-With": "XMLHttpRequest"},
			Body:    `__VIEWSTATE=`,
			Check:   []string{"__VIEWSTATE", "__VIEWSTATEGENERATOR"},
		},
		{
			Name: "PHP-Laravel", Target: "/",
			Headers: map[string]string{"Cookie": "laravel_session=test"},
			Check:   []string{"laravel", "Laravel"},
		},
		{
			Name: "Python-Django", Target: "/admin/",
			Headers: map[string]string{"Cookie": "sessionid=test"},
			Check:   []string{"django", "Django", "sessionid"},
		},
		{
			Name: "Python-Pickle", Target: "/",
			Headers: map[string]string{"Content-Type": "application/x-python-serialize"},
			Body:    "cos\nsystem\n(S'echo FNG_DESER'\ntR.",
			Check:   []string{"FNG_DESER"},
		},
		{
			Name: "Java-SpringBoot", Target: "/jolokia/",
			Check: []string{"jolokia", "Spring", "actuator"},
		},
		{
			Name: "NodeJS-serialize", Target: "/",
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    `{"__proto__":{"admin":true}}`,
			Check:   []string{"admin", "__proto__"},
		},
	}

	for _, t := range tests {
		fullURL := strings.TrimRight(target.URL, "/") + t.Target

		headers := t.Headers
		if headers == nil {
			headers = make(map[string]string)
		}
		if _, ok := headers["User-Agent"]; !ok {
			headers["User-Agent"] = "Mozilla/5.0 Fang"
		}

		var resp *fanghttp.Response
		var err error

		if t.Body != "" {
			resp, err = m.client.DoRaw("POST", fullURL, headers, t.Body)
		} else {
			resp, err = m.client.DoRaw("GET", fullURL, headers, "")
		}

		if err != nil {
			continue
		}

		for _, check := range t.Check {
			if strings.Contains(strings.ToLower(resp.Body), strings.ToLower(check)) ||
				strings.Contains(strings.ToLower(resp.Status), strings.ToLower(check)) {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("Deserialization - %s", t.Name),
					Severity:    models.Critical,
					Confidence:  models.HighConfidence,
					URL:         fullURL,
					Evidence:    fmt.Sprintf("Endpoint identified: %s (status: %d)", t.Target, resp.StatusCode),
					Description: fmt.Sprintf("Target exposes %s deserialization endpoint. Potential for insecure deserialization attacks leading to RCE.", t.Name),
					Remediation: "Disable deserialization of untrusted data. Implement allowlist validation. Use integrity checks like HMAC.",
					CWEID:       "CWE-502",
					ModuleID:    "deser",
				})
				break
			}
		}
	}

	return findings, nil
}

func init() {
	engine.GetRegistry().Register(&DeserModule{})
}
