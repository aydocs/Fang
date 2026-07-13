package report

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aydocs/fang/pkg/models"
	"github.com/chromedp/chromedp"
)

type PDFOptions struct {
	Landscape bool
	PaperSize string
	Margin    string
}

func (e *Engine) GeneratePDF(ctx context.Context, result *models.ScanResult, opts *PDFOptions) (string, error) {
	if opts == nil {
		opts = &PDFOptions{
			Landscape: false,
			PaperSize: "A4",
			Margin:    "15mm",
		}
	}

	htmlContent := e.buildHTML(result)

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx,
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)
	defer allocCancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	width, height := 210.0, 297.0
	if opts.Landscape {
		width, height = 297.0, 210.0
	}
	margin := 15.0

	pdfJS := fmt.Sprintf(`(async () => {
		const {data} = await window.printToPDF({
			landscape: %v,
			paperWidth: %f,
			paperHeight: %f,
			marginTop: %f,
			marginBottom: %f,
			marginLeft: %f,
			marginRight: %f,
			printBackground: true,
			displayHeaderFooter: true,
			headerTemplate: '<span style="font-size:8px;color:#666;margin-left:15mm;">FANG Security Report</span>',
			footerTemplate: '<span style="font-size:8px;color:#666;margin-right:15mm;">Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>',
		});
		return data;
	})()`, opts.Landscape, width, height, margin, margin, margin, margin)

	var pdfData string
	if err := chromedp.Run(ctx,
		chromedp.Navigate("about:blank"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			escaped := strings.ReplaceAll(htmlContent, `\`, `\\`)
			escaped = strings.ReplaceAll(escaped, `"`, `\"`)
			escaped = strings.ReplaceAll(escaped, "\n", `\n`)
			return chromedp.Evaluate(fmt.Sprintf(`document.write("%s")`, escaped), nil).Do(ctx)
		}),
		chromedp.WaitReady("body"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			return chromedp.Evaluate(pdfJS, &pdfData).Do(ctx)
		}),
	); err != nil {
		return "", fmt.Errorf("pdf generation: %w", err)
	}

	buf, err := base64.StdEncoding.DecodeString(pdfData)
	if err != nil {
		return "", fmt.Errorf("pdf decode: %w", err)
	}

	sanitized := sanitizeTarget(result.Target)
	ts := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("%s_%s.pdf", sanitized, ts)
	path := filepath.Join(e.config.OutputDir, filename)

	if err := os.MkdirAll(e.config.OutputDir, 0755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, buf, 0644); err != nil {
		return "", err
	}
	return path, nil
}

type ComplianceStandard string

const (
	PCI_DSS    ComplianceStandard = "pci_dss_v4"
	SOC2       ComplianceStandard = "soc2"
	HIPAA      ComplianceStandard = "hipaa"
	ISO27001   ComplianceStandard = "iso_27001"
	NIST_CSF   ComplianceStandard = "nist_csf"
	FEDRAMP    ComplianceStandard = "fedramp"
	GDPR       ComplianceStandard = "gdpr"
	OWASP_ASVS ComplianceStandard = "owasp_asvs"
)

type ComplianceRequirement struct {
	Standard    ComplianceStandard
	ControlID   string
	Title       string
	Description string
	CWEMappings []string
	Severity    models.Severity
	Remediation string
}

var ComplianceMappings = []ComplianceRequirement{
	{PCI_DSS, "4.1", "Use strong cryptography", "Encrypt cardholder data over open/public networks", []string{"CWE-311", "CWE-319"}, models.Critical, "Use TLS 1.2+ for all data transmission"},
	{PCI_DSS, "6.5", "Address common coding vulnerabilities", "Fix SQLi, XSS, and other OWASP Top 10 issues", []string{"CWE-79", "CWE-89", "CWE-22"}, models.Critical, "Implement secure coding practices and SAST scanning"},
	{PCI_DSS, "7.3", "Need-to-know access", "Restrict access to cardholder data by need-to-know", []string{"CWE-285", "CWE-862"}, models.High, "Implement role-based access controls"},
	{PCI_DSS, "8.3", "Secure authentication", "Implement multi-factor authentication for remote access", []string{"CWE-287", "CWE-308"}, models.Critical, "Enable MFA for all administrative access"},
	{PCI_DSS, "10.2", "Audit trails", "Implement automated audit trails for all system components", []string{"CWE-778", "CWE-223"}, models.High, "Enable comprehensive logging and monitoring"},
	{PCI_DSS, "11.3", "Penetration testing", "Perform regular penetration testing", []string{"CWE-0"}, models.Medium, "Schedule quarterly penetration tests and after any significant changes"},
	{PCI_DSS, "12.5", "Security awareness", "Maintain security policies and awareness programs", []string{"CWE-0"}, models.Info, "Document and maintain security policies"},

	{SOC2, "CC1.1", "Control environment", "Establish integrity and ethical values", []string{"CWE-0"}, models.Info, "Document security policies and procedures"},
	{SOC2, "CC2.1", "Communication", "Communicate information about system operation", []string{"CWE-200"}, models.Medium, "Ensure proper information classification and handling"},
	{SOC2, "CC3.1", "Risk assessment", "Identify and assess risks", []string{"CWE-0"}, models.High, "Perform regular risk assessments"},
	{SOC2, "CC4.1", "Monitoring", "Monitor internal control systems", []string{"CWE-778"}, models.High, "Implement continuous monitoring solutions"},
	{SOC2, "CC5.1", "Control activities", "Select and develop control activities", []string{"CWE-285", "CWE-287"}, models.Critical, "Implement access controls and segregation of duties"},
	{SOC2, "CC6.1", "Logical access", "Restrict logical access to system components", []string{"CWE-285", "CWE-862"}, models.Critical, "Implement principle of least privilege"},
	{SOC2, "CC7.1", "System operations", "Manage system operations", []string{"CWE-400"}, models.High, "Implement change management and incident response"},

	{HIPAA, "164.312(a)(1)", "Access control", "Implement technical policies for electronic health information access", []string{"CWE-285", "CWE-862"}, models.Critical, "Implement unique user identification and emergency access procedures"},
	{HIPAA, "164.312(a)(2)(iv)", "Encryption", "Encrypt electronic protected health information", []string{"CWE-311", "CWE-326"}, models.Critical, "Encrypt PHI at rest and in transit"},
	{HIPAA, "164.312(b)", "Audit controls", "Implement audit controls for EPHI access", []string{"CWE-778"}, models.High, "Record and examine access to PHI"},
	{HIPAA, "164.312(c)(1)", "Integrity", "Ensure EPHI integrity", []string{"CWE-345"}, models.High, "Implement mechanisms to authenticate EPHI"},
	{HIPAA, "164.312(d)", "Authentication", "Verify person or entity seeking access to EPHI", []string{"CWE-287"}, models.Critical, "Implement strong authentication mechanisms"},
	{HIPAA, "164.312(e)(1)", "Transmission security", "Guard against unauthorized EPHI access during transmission", []string{"CWE-319", "CWE-311"}, models.Critical, "Use encrypted communication channels for EPHI"},

	{ISO27001, "A.9.1.2", "Access to networks", "Control access to networks and network services", []string{"CWE-285", "CWE-862"}, models.Critical, "Implement network access controls and segmentation"},
	{ISO27001, "A.10.1.1", "Cryptographic controls", "Implement cryptographic controls for information protection", []string{"CWE-311", "CWE-326"}, models.Critical, "Use strong encryption for sensitive data"},
	{ISO27001, "A.12.6.1", "Technical vulnerability management", "Manage technical vulnerabilities", []string{"CWE-0"}, models.High, "Implement vulnerability scanning and patch management"},
	{ISO27001, "A.14.2.1", "Secure development policy", "Establish secure development rules", []string{"CWE-79", "CWE-89"}, models.Critical, "Implement secure SDLC practices"},
	{ISO27001, "A.18.1.4", "Privacy protection", "Ensure privacy and PII protection", []string{"CWE-200"}, models.Critical, "Implement data protection and privacy controls"},
}

func MapFindingsToCompliance(findings []*models.Finding, standard ComplianceStandard) map[string][]*models.Finding {
	result := make(map[string][]*models.Finding)
	for _, req := range ComplianceMappings {
		if req.Standard != standard {
			continue
		}
		for _, f := range findings {
			for _, cwe := range req.CWEMappings {
				if cwe == "CWE-0" || f.CWEID == cwe {
					result[req.ControlID] = append(result[req.ControlID], f)
					break
				}
			}
		}
	}
	return result
}

func GenerateComplianceReport(ctx context.Context, result *models.ScanResult, standards []ComplianceStandard) (string, error) {
	html := `<html><head><style>
		body { font-family: Arial; margin: 20px; color: #333; }
		h1 { color: #1a1a2e; border-bottom: 2px solid #e94560; }
		h2 { color: #16213e; margin-top: 30px; }
		.standard { background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #e94560; }
		.control { background: white; padding: 10px; margin: 5px 0; border: 1px solid #ddd; }
		.control.passed { border-left: 4px solid #2ecc71; }
		.control.failed { border-left: 4px solid #e74c3c; }
		.control.partial { border-left: 4px solid #f39c12; }
		table { width: 100%; border-collapse: collapse; margin: 10px 0; }
		th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
		th { background: #1a1a2e; color: white; }
		.badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; color: white; }
		.badge.critical { background: #e74c3c; }
		.badge.high { background: #e67e22; }
		.badge.medium { background: #f39c12; }
		.badge.info { background: #3498db; }
	</style></head><body>
	<h1>FANG Compliance Report</h1>
	<p>Generated: ` + time.Now().Format(time.RFC3339) + `</p>
	<p>Target: ` + result.Target + `</p>`

	for _, standard := range standards {
		html += `<h2>` + string(standard) + `</h2>`
		mapped := MapFindingsToCompliance(result.Findings, standard)
		passed := 0
		failed := 0
		for _, req := range ComplianceMappings {
			if req.Standard != standard {
				continue
			}
			if _, ok := mapped[req.ControlID]; ok {
				failed++
			} else {
				passed++
			}
		}
		total := passed + failed
		html += fmt.Sprintf(`<p>Compliance: %d/%d controls passed (%.0f%%)</p>`,
			passed, total, float64(passed)/float64(total)*100)

		html += `<table><tr><th>Control</th><th>Title</th><th>Status</th><th>Findings</th></tr>`
		for _, req := range ComplianceMappings {
			if req.Standard != standard {
				continue
			}
			findings := mapped[req.ControlID]
			status := "passed"
			statusClass := "passed"
			count := 0
			if len(findings) > 0 {
				status = "failed"
				statusClass = "failed"
				count = len(findings)
			}
			html += fmt.Sprintf(`<tr class="control %s"><td>%s</td><td>%s</td><td>%s</td><td>%d</td></tr>`,
				statusClass, req.ControlID, req.Title, status, count)
		}
		html += `</table>`
	}

	html += `</body></html>`

	sanitized := sanitizeTarget(result.Target)
	ts := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("compliance_%s_%s.html", sanitized, ts)
	path := filepath.Join(os.Getenv("HOME"), ".fang", "reports", filename)

	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0755)
	if err := os.WriteFile(path, []byte(html), 0644); err != nil {
		return "", err
	}
	return path, nil
}
