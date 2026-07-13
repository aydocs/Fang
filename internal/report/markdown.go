package report

import (
	"fmt"
	"strings"

	"github.com/aydocs/fang/pkg/models"
)

func generateMarkdown(result *models.ScanResult) string {
	var b strings.Builder

	b.WriteString("# Fang Security Report\n\n")
	b.WriteString(fmt.Sprintf("**Target:** %s  \n", result.Target))
	b.WriteString(fmt.Sprintf("**Generated:** %s  \n", result.EndTime.Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("**Duration:** %s  \n\n", result.Duration))

	summaryTable(result, &b)

	b.WriteString("---\n\n")

	for _, f := range result.Findings {
		findingSection(f, &b)
	}

	return b.String()
}

func summaryTable(result *models.ScanResult, b *strings.Builder) {
	b.WriteString("## Summary\n\n")
	b.WriteString("| Severity | Count |\n")
	b.WriteString("|----------|-------|\n")
	b.WriteString(fmt.Sprintf("| %s | %d |\n", severityBadge("CRITICAL"), result.Summary.Critical))
	b.WriteString(fmt.Sprintf("| %s | %d |\n", severityBadge("HIGH"), result.Summary.High))
	b.WriteString(fmt.Sprintf("| %s | %d |\n", severityBadge("MEDIUM"), result.Summary.Medium))
	b.WriteString(fmt.Sprintf("| %s | %d |\n", severityBadge("LOW"), result.Summary.Low))
	b.WriteString(fmt.Sprintf("| %s | %d |\n", severityBadge("INFO"), result.Summary.Info))
	b.WriteString(fmt.Sprintf("| **Total** | **%d** |\n", result.Summary.Total))
	b.WriteString("\n")
}

func severityBadge(s string) string {
	icon := ""
	switch s {
	case "CRITICAL":
		icon = ":red_circle:"
	case "HIGH":
		icon = ":orange_circle:"
	case "MEDIUM":
		icon = ":yellow_circle:"
	case "LOW":
		icon = ":large_blue_circle:"
	case "INFO":
		icon = ":white_circle:"
	}
	return fmt.Sprintf("%s **%s**", icon, s)
}

func findingSection(f *models.Finding, b *strings.Builder) {
	b.WriteString(fmt.Sprintf("## %s\n\n", f.Title))
	b.WriteString(fmt.Sprintf("**Severity:** %s  \n", severityBadge(f.Severity.String())))
	b.WriteString(fmt.Sprintf("**Confidence:** %s  \n", f.Confidence.String()))

	if f.URL != "" {
		b.WriteString(fmt.Sprintf("**URL:** `%s`  \n", f.URL))
	}
	if f.Parameter != "" {
		b.WriteString(fmt.Sprintf("**Parameter:** `%s`  \n", f.Parameter))
	}
	if f.Payload != "" {
		b.WriteString(fmt.Sprintf("**Payload:** `%s`  \n", f.Payload))
	}
	if f.Description != "" {
		b.WriteString(fmt.Sprintf("\n%s  \n", f.Description))
	}
	if f.Evidence != "" {
		b.WriteString(fmt.Sprintf("\n**Evidence:**\n```\n%s\n```\n", f.Evidence))
	}
	if f.Remediation != "" {
		b.WriteString(fmt.Sprintf("\n**Remediation:** %s  \n", f.Remediation))
	}
	if f.CVSS != nil && *f.CVSS > 0 {
		b.WriteString(fmt.Sprintf("\n**CVSS Score:** %.1f  \n", *f.CVSS))
	}
	if f.CWEID != "" {
		b.WriteString(fmt.Sprintf("**CWE:** `%s`  \n", f.CWEID))
	}

	b.WriteString("\n---\n\n")
}
