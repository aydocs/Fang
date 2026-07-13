package report

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"

	"github.com/aydocs/fang/pkg/models"
)

func (e *Engine) buildHTML(result *models.ScanResult) string {
	findingsJSON, _ := json.Marshal(result.Findings)

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Fang Security Report - %s</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6}
.container{max-width:1200px;margin:0 auto;padding:20px}
header{background:linear-gradient(135deg,#161b22,#0d1117);padding:32px;border-radius:12px;margin-bottom:24px;border:1px solid #30363d}
header h1{color:#e94560;font-size:2.2em;margin-bottom:8px}
header .sub{color:#8b949e;font-size:0.95em}
.dashboard{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px}
.stat{background:#161b22;padding:20px;border-radius:8px;text-align:center;border:1px solid #30363d}
.stat .num{font-size:2em;font-weight:700}
.stat .lbl{color:#8b949e;font-size:0.85em;margin-top:4px}
.stat.critical .num{color:#e94560}
.stat.high .num{color:#ff6b6b}
.stat.medium .num{color:#ffd93d}
.stat.low .num{color:#6bcb77}
.stat.info .num{color:#58a6ff}
.bar-group{margin-bottom:24px}
.bar-row{display:flex;align-items:center;margin:6px 0;gap:8px}
.bar-label{width:80px;font-size:0.85em;color:#8b949e}
.bar-track{flex:1;height:20px;background:#21262d;border-radius:10px;overflow:hidden}
.bar-fill{height:100%%;border-radius:10px;transition:width .5s}
.bar-fill.critical{background:#e94560}
.bar-fill.high{background:#ff6b6b}
.bar-fill.medium{background:#ffd93d}
.bar-fill.low{background:#6bcb77}
.bar-fill.info{background:#58a6ff}
.bar-count{width:40px;text-align:right;font-size:0.85em;color:#8b949e}
.controls{margin-bottom:16px;display:flex;gap:8px;flex-wrap:wrap}
.controls input,.controls select{background:#21262d;border:1px solid #30363d;color:#c9d1d9;padding:8px 12px;border-radius:6px;font-size:0.9em}
.controls input{flex:1;min-width:200px}
.controls select{min-width:120px}
.finding{background:#161b22;border-radius:8px;margin-bottom:12px;border:1px solid #30363d;border-left:4px solid #30363d;overflow:hidden}
.finding.critical{border-left-color:#e94560}
.finding.high{border-left-color:#ff6b6b}
.finding.medium{border-left-color:#ffd93d}
.finding.low{border-left-color:#6bcb77}
.finding.info{border-left-color:#58a6ff}
.finding-header{padding:16px;cursor:pointer;display:flex;align-items:center;gap:12px;user-select:none}
.finding-header:hover{background:#1c2128}
.sev-badge{padding:3px 10px;border-radius:4px;font-size:0.75em;font-weight:700;white-space:nowrap}
.sev-badge.CRITICAL,.sev-badge.HIGH{background:#e94560;color:#fff}
.sev-badge.MEDIUM{background:#ffd93d;color:#000}
.sev-badge.LOW{background:#6bcb77;color:#000}
.sev-badge.INFO{background:#58a6ff;color:#fff}
.finding-title{flex:1;font-weight:600}
.finding-url{color:#8b949e;font-size:0.85em;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.arrow{color:#8b949e;transition:transform .2s;font-size:0.9em}
.arrow.open{transform:rotate(90deg)}
.finding-body{padding:0 16px 16px;display:none}
.finding-body.open{display:block}
.finding-body dt{color:#8b949e;font-size:0.85em;margin-top:12px;margin-bottom:4px}
.finding-body dd{margin-left:0}
.finding-body code,.finding-body pre{background:#0d1117;padding:2px 6px;border-radius:4px;font-size:0.9em}
.finding-body pre{padding:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;border:1px solid #30363d;margin-top:4px}
.extra-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;margin-top:8px}
.extra-item{background:#0d1117;padding:8px 12px;border-radius:4px;font-size:0.85em}
.extra-item .k{color:#8b949e}
.no-results{padding:32px;text-align:center;color:#8b949e}
footer{text-align:center;margin-top:32px;padding:16px;color:#8b949e;font-size:0.85em;border-top:1px solid #30363d}
</style>
</head>
<body>
<div class="container">
<header>
<h1>Fang Security Report</h1>
<p class="sub">Forensic Audit Network Guardian v1.0.0</p>
<p class="sub">Target: %s</p>
<p class="sub">Generated: %s | Duration: %s</p>
</header>

<div class="dashboard">
<div class="stat"><div class="num">%d</div><div class="lbl">Total</div></div>
<div class="stat critical"><div class="num">%d</div><div class="lbl">Critical</div></div>
<div class="stat high"><div class="num">%d</div><div class="lbl">High</div></div>
<div class="stat medium"><div class="num">%d</div><div class="lbl">Medium</div></div>
<div class="stat low"><div class="num">%d</div><div class="lbl">Low</div></div>
<div class="stat info"><div class="num">%d</div><div class="lbl">Info</div></div>
</div>

<div class="bar-group">
<div class="bar-row"><span class="bar-label">Critical</span><div class="bar-track"><div class="bar-fill critical" style="width:%.0f%%"></div></div><span class="bar-count">%d</span></div>
<div class="bar-row"><span class="bar-label">High</span><div class="bar-track"><div class="bar-fill high" style="width:%.0f%%"></div></div><span class="bar-count">%d</span></div>
<div class="bar-row"><span class="bar-label">Medium</span><div class="bar-track"><div class="bar-fill medium" style="width:%.0f%%"></div></div><span class="bar-count">%d</span></div>
<div class="bar-row"><span class="bar-label">Low</span><div class="bar-track"><div class="bar-fill low" style="width:%.0f%%"></div></div><span class="bar-count">%d</span></div>
<div class="bar-row"><span class="bar-label">Info</span><div class="bar-track"><div class="bar-fill info" style="width:%.0f%%"></div></div><span class="bar-count">%d</span></div>
</div>

<div class="controls">
<input type="text" id="search" placeholder="Search findings..." oninput="filterFindings()">
<select id="severityFilter" onchange="filterFindings()">
<option value="">All Severities</option>
<option value="CRITICAL">Critical</option>
<option value="HIGH">High</option>
<option value="MEDIUM">Medium</option>
<option value="LOW">Low</option>
<option value="INFO">Info</option>
</select>
</div>

<div id="findingsList">%s</div>

<footer>Generated by Fang Security Scanner v1.0.0</footer>
</div>

<script>
const findings = %s;
function toggle(id){const b=document.getElementById('body-'+id);const a=document.getElementById('arrow-'+id);b.classList.toggle('open');a.classList.toggle('open')}
function filterFindings(){const q=document.getElementById('search').value.toLowerCase();const s=document.getElementById('severityFilter').value;document.querySelectorAll('.finding').forEach(f=>{const t=f.querySelector('.finding-title').textContent.toLowerCase();const u=f.querySelector('.finding-url').textContent.toLowerCase();const sev=f.dataset.severity;const match=t.includes(q)||u.includes(q);const sevMatch=!s||sev===s;f.style.display=match&&sevMatch?'':'none'})}
</script>
</body>
</html>`,
		html.EscapeString(result.Target),
		html.EscapeString(result.Target),
		result.EndTime.Format("2006-01-02 15:04:05"),
		result.Duration,
		result.Summary.Total,
		result.Summary.Critical,
		result.Summary.High,
		result.Summary.Medium,
		result.Summary.Low,
		result.Summary.Info,
		barPct(result.Summary.Critical, result.Summary.Total),
		result.Summary.Critical,
		barPct(result.Summary.High, result.Summary.Total),
		result.Summary.High,
		barPct(result.Summary.Medium, result.Summary.Total),
		result.Summary.Medium,
		barPct(result.Summary.Low, result.Summary.Total),
		result.Summary.Low,
		barPct(result.Summary.Info, result.Summary.Total),
		result.Summary.Info,
		e.buildFindingsHTML(result.Findings),
		findingsJSON,
	)
}

func barPct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}

func (e *Engine) buildFindingsHTML(findings []*models.Finding) string {
	if len(findings) == 0 {
		return `<div class="no-results">No findings detected.</div>`
	}

	var b strings.Builder
	for i, f := range findings {
		sevLower := strings.ToLower(f.Severity.String())
		b.WriteString(fmt.Sprintf(`<div class="finding %s" data-severity="%s">`, sevLower, f.Severity.String()))
		b.WriteString(fmt.Sprintf(`<div class="finding-header" onclick="toggle(%d)">`, i))
		b.WriteString(fmt.Sprintf(`<span class="sev-badge %s">%s</span>`, f.Severity.String(), f.Severity.String()))
		b.WriteString(fmt.Sprintf(`<span class="finding-title">%s</span>`, html.EscapeString(f.Title)))
		if f.URL != "" {
			b.WriteString(fmt.Sprintf(`<span class="finding-url" title="%s">%s</span>`, html.EscapeString(f.URL), html.EscapeString(truncateURL(f.URL, 50))))
		}
		b.WriteString(fmt.Sprintf(`<span class="arrow" id="arrow-%d">&#9654;</span>`, i))
		b.WriteString(`</div>`)
		b.WriteString(fmt.Sprintf(`<div class="finding-body" id="body-%d">`, i))

		if f.URL != "" {
			b.WriteString(`<dt>URL</dt><dd><code>` + html.EscapeString(f.URL) + `</code></dd>`)
		}
		if f.Parameter != "" {
			b.WriteString(`<dt>Parameter</dt><dd><code>` + html.EscapeString(f.Parameter) + `</code></dd>`)
		}
		if f.Payload != "" {
			b.WriteString(`<dt>Payload</dt><dd><code>` + html.EscapeString(f.Payload) + `</code></dd>`)
		}
		if f.Description != "" {
			b.WriteString(`<dt>Description</dt><dd>` + html.EscapeString(f.Description) + `</dd>`)
		}
		if e.config.IncludeEvidence && f.Evidence != "" {
			b.WriteString(`<dt>Evidence</dt><dd><pre>` + html.EscapeString(f.Evidence) + `</pre></dd>`)
		}
		if f.Remediation != "" {
			b.WriteString(`<dt>Remediation</dt><dd>` + html.EscapeString(f.Remediation) + `</dd>`)
		}
		if f.CVSS != nil && *f.CVSS > 0 {
			b.WriteString(`<dt>CVSS Score</dt><dd>` + fmt.Sprintf("%.1f", *f.CVSS) + `</dd>`)
		}
		if f.CWEID != "" {
			b.WriteString(`<dt>CWE</dt><dd><code>` + html.EscapeString(f.CWEID) + `</code></dd>`)
		}
		if f.ModuleID != "" {
			b.WriteString(`<dt>Module</dt><dd>` + html.EscapeString(f.ModuleID) + `</dd>`)
		}
		if len(f.Extra) > 0 {
			b.WriteString(`<dt>Additional Info</dt><dd><div class="extra-grid">`)
			for k, v := range f.Extra {
				b.WriteString(fmt.Sprintf(`<div class="extra-item"><span class="k">%s:</span> %s</div>`, html.EscapeString(k), html.EscapeString(v)))
			}
			b.WriteString(`</div></dd>`)
		}

		b.WriteString(`</div></div>`)
	}
	return b.String()
}

func truncateURL(u string, max int) string {
	if len(u) <= max {
		return u
	}
	return u[:max] + "..."
}
