# Fang Status

> Code name: **ultimate cybersecurity tool**
> Goal: Transform Fang from a 43-module security scanner into a multi-hat (white, black, blue, red, gray) cybersecurity platform with enterprise features, ecosystem, and polish.

---

## Timeline

| Phase | What | Status |
|-------|------|--------|
| 0 | Core hardening | ✅ Done |
| 1 | 27 new modules (40 → 67) | ✅ Done |
| 2 | Enterprise platform (PDF, compliance, RBAC, integrations, workflows) | ✅ Done |
| 3 | Ecosystem (plugins, evasion, SIEM, bug bounty) | ✅ Done |
| 4 | Polish (i18n, distributed engine, contributing/security docs) | ✅ Done |

---

## Modules (67 total)

### Core (40 original − 1 deleted + 1 retained = 40)
0day, browser, central, cloud, cloudkill, cmdi, cors, crlf, dataphantom, deser, devnull, endgame, graphql, headers, idpwn, inject, ldap, lfi, malware, method, nosqli, payment, proto, race, recon, redirect, reverse, shadow, smuggler, spectre, sqli, ssrf, ssti, strike, websocket, xpath, xss, xxe, soap

### Deleted
- **phantasm** — AI/LLM jailbreak module (removed per user request, AI is irrelevant)

### New (27)
adcs, android, arsenal, bluetooth, cicd, docker, evasion, exchange, git, helm, iot, ios, k8s, kerberos, ntlm, npm, oidc, phish, rest, rfid, saml, sbom, sdr, serverless, smb, terraform, vpn, wifi

---

## Enterprise Features

### PDF Report Engine
`internal/report/pdf.go` — Chrome headless (chromedp) HTML → PDF, PrintToPDF, A4/landscape, header/footer. Callable via `engine.Generate("pdf")`.

### Compliance Framework
`internal/report/pdf.go` — 4 standards hardcoded as Go structs with CWE-to-control mappings:
- **PCI DSS v4**: 7 controls (1.2.1, 1.3.1, 1.3.2, 1.4.2, 2.2.2, 3.4, 4.1)
- **SOC 2**: 8 controls (CC1.1-CC7.1)
- **HIPAA**: 6 controls (164.312(a)(1)-164.312(e)(1))
- **ISO 27001**: 5 controls (A.9.1.2-A.18.1.4)

Functions: `MapFindingsToCompliance(finding, standard)` → control IDs, `GenerateComplianceReport(findings, standard)`.

### Multi-Tenant / RBAC
- Tables: `organizations`, `organization_members`, `audit_log`
- Columns: `org_id` on `targets` and `users`
- `RequireRole(userID, orgID, ...roles)` — checks membership + role
- CRUD: `CreateOrganization`, `ListOrganizations`, `DeleteOrganization`, `AddOrgMember`, `RemoveOrgMember`, `ListOrgMembers`, `GetUserOrgRole`
- Audit: `LogAuditEvent`, `QueryAuditLog`

### Jira / GitHub Integration
`internal/integration/`:
- **JiraClient** — CreateIssue, FindIssue, UpdateIssueStatus, AddComment (REST API v2)
- **GitHubClient** — CreateIssue, FindIssue, CloseIssue (REST API v3)
- Config stored at `~/.fang/config/integrations.json`

### Workflow Automation Engine
`internal/workflow/workflow.go`:
- **7 triggers**: scan_complete, finding_found, severity_met, schedule, new_target, target_removed, report_generated
- **7 actions**: webhook, slack_notify, email_notify, jira_issue, github_issue, script_exec, notification
- Goroutine pool (5 workers), JSON persistence

---

## Ecosystem Features

### Plugin System
`internal/plugin/plugin.go` — Manager, Manifest, Plugin, Type constants, YAML manifest loading, Register/Unload/List/Get, PluginEndpoint.

### Evasion Toolkit
`internal/evasion/evasion.go`:
- **Proxy rotation**: round-robin through list
- **20 modern UA pool**: Chrome 120-131, Firefox 120-133, Safari 17.2, Edge 120
- **Adaptive delay**: 500-3000ms random
- **Tor SOCKS5** support
- **TLS fingerprint spoofing** — browser-like cipher-suite/version spoofing via configurable ClientHello (3 profiles)

### SIEM Integration
`internal/integration/siem.go` — SIEMClient with 4 backends:
- **Splunk** — HTTP Event Collector (HEC)
- **ELK** — Elasticsearch _doc API
- **QRadar** — CEF syslog (UDP)
- **Sentinel** — Azure Log Analytics (POST)
- Methods: SendFinding, SendScanResult, SendEvent

### Bug Bounty Automation
`internal/bugbounty/bugbounty.go`:
- **HackerOne**: DraftReport, SubmitReport, ListPrograms (REST API)
- **Bugcrowd**: DraftReport, SubmitReport, ListPrograms (REST API)
- **Intigriti**: DraftReport, SubmitReport, ListPrograms (REST API)
- **YesWeHack**: DraftReport, SubmitReport, ListPrograms (REST API)

---

## Polish Features

### Internationalization (i18n)
`internal/i18n/`:
- `Bundle` with `T(key, lang)` and `Tf(key, lang, args...)`
- `Default` global singleton (auto-init)
- 9 languages: EN, TR, DE, FR, ES, RU, ZH, AR, JA (all translated)
- 36 UI keys: scan_running, scan_completed, scan_failed, target, findings, severity, critical, high, medium, low, info, dashboard, scanner, targets, reports, settings, users, notifications, organizations, integrations, workflows, evasion, login, register, username, password, email, save, cancel, delete, create, edit, search, export, import, language

### Distributed Engine Foundation
`internal/distributed/`:
- `Cluster` with nodes map, `RegisterNode`, `RemoveNode`, `DispatchTask` (round-robin)
- 4 message types: heartbeat, task_assign, task_result, node_status
- TCP transport (`transport.go`): `Server` (controller listener) + `Client` (worker dialer), heartbeat loop, node-status registration, task-result aggregation

### Security Docs
- `CONTRIBUTING.md` — dev setup, module guide, no-comments standard
- `SECURITY.md` — reporting policy, supported versions

---

## Frontend (Wails)

### Pages (14 tabs)
| # | Page | File |
|---|------|------|
| 1 | Dashboard | `Dashboard.tsx` |
| 2 | Targets | `Targets.tsx` |
| 3 | Scanner | `Scanner.tsx` |
| 4 | Scans | `Scans.tsx` |
| 5 | Findings | `Findings.tsx` |
| 6 | Schedules | `Schedules.tsx` |
| 7 | Notifications | `Notifications.tsx` |
| 8 | Settings | `SettingsPage.tsx` |
| 9 | Login | `LoginPage.tsx` |
| 10 | Users | `UserManagement.tsx` |
| 11 | Organizations | `Organizations.tsx` |
| 12 | Integrations | `Integrations.tsx` |
| 13 | Workflows | `Workflows.tsx` |
| 14 | Evasion | `Evasion.tsx` |

### New Pages Feature Summary
- **Organizations**: CRUD, member invite/remove, role selection, audit log viewer
- **Integrations**: Jira (URL/token/project), GitHub (token/owner/repo), Slack (webhook URL), test buttons
- **Workflows**: Create/edit with trigger+action config, enable/disable toggle, test button
- **Evasion**: Proxy rotation toggle, UA rotation toggle, adaptive delay toggle, proxy list editor, delay min/max sliders
- **Settings**: Language selector dropdown (7 languages)

---

## Wails Methods (app.go — 30+ bindings)
`GetDashboardData`, `StartScan`, `StopScan`, `GetScans`, `GetScanDetail`, `GetFindings`, `GetTargets`, `CreateTarget`, `DeleteTarget`, `GetModules`, `GetNotifications`, `CreateSchedule`, `ListSchedules`, `DeleteSchedule`, `CreateUser`, `ListUsers`, `DeleteUser`, `Login`, `Logout`, `GetCurrentUser`, `OpenDirectory`, `ImportData`, `CreateOrg`, `ListOrgs`, `DeleteOrg`, `InviteUser`, `RemoveUser`, `ListOrgMembers`, `GetAuditLog`, `CreateJiraIssue`, `CreateGitHubIssue`, `ConfigureIntegration`, `GetIntegrationConfig`, `CreateWorkflow`, `ListWorkflows`, `DeleteWorkflow`, `ToggleWorkflow`, `TestWorkflow`, `GetPluginDir`, `ListPlugins`, `GetEvasionConfig`, `SaveEvasionConfig`, `ConfigureSIEM`, `GetSIEMConfig`, `SendToSIEM`, `CreateBountyReport`, `SetLanguage`, `GetLanguage`, `GetTranslation`

---

## Infrastructure

### Docker
- Go 1.25-alpine builder, alpine 3.21 runtime
- Two-stage build: compile → copy binary

### CI/CD
`.github/workflows/ci.yml` — 4 jobs:
1. **lint** — go vet, staticcheck
2. **test** — go test ./...
3. **build-frontend** — npm ci + npm run build
4. **build** — go build ./...

### Webpack Bundle Splitting
- `index.js` (~45KB) — app code
- `vendor.js` (~545KB) — node_modules dependencies

### Recon Quick Mode
`modules/recon/recon.go` — `.Quick` in .cfg short-circuits to 30 top ports instead of 1000.

---

## Security Hardening

### Login Rate Limiting
`app.go` — 5 attempts per 30-second sliding window per IP.

### Default Password
Random 24-character alphanumeric on first run (no hardcoded `admin`/`fang123`).

### Input Validation
`OpenDirectory` — rejects paths containing `..` or starting with `/` (no path traversal).
`ImportData` — file basename validated against `^[a-zA-Z0-9._-]+$` + max 255 chars + max 1MB.

---

## Test Results

- **`go vet ./...`** — PASS (0 errors)
- **`go test ./...`** — 58+ packages, 0 FAIL
- **`go build ./...`** — PASS
- **`npm run build`** — PASS (~3.25s, 2 chunks)

---

## Notes

- **Zero comments** in Go, TSX, TS, CSS, HTML source files (preserved: `//go:embed` and string-literal payloads)
- **All text in English** — no Turkish or non-English in source
- **No AI/ML** — Phantasm deleted, AI references removed from ROADMAP.md
- **No aydocs watermark** — user requested then cancelled
- **ROADMAP.md** updated to 7 phases (Phase 0-6), AI layer removed from planning
