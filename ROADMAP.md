# FANG - The Ultimate Cyber Security Platform

## Vision

One tool. All hats. Every attack surface. Community-driven.

Fang will be the single most comprehensive cybersecurity platform ever built - equally indispensable to white, black, blue, red, and gray hat operators worldwide. From reconnaissance to exploitation, from defense to forensics, from cloud to IoT, from mobile to SCADA - Fang covers everything.

---

## Phase 0: Current State (67 Modules, Working Engine)

### What works today
- 41 security modules covering SQLi, XSS, LFI, SSRF, CMDi, SSTI, XXE, NoSQLi, LDAP, XPath, CORS, CRLF, JWT, OAuth, IDOR, GraphQL, gRPC, HTTP/2, WebSocket, Redis, MySQL, PostgreSQL, MongoDB, Kafka, MQTT, S3, Cloud, DNS, Recon, OSINT, Malware, C2 (Shadow), Post-exploitation (Strike), RE (Reverse), Hardware (Spectre), ICS (Ice), Telecom (Carrier), Log4j, Payment, Race conditions, Session attacks, Method smuggling, Parameter pollution, Error analysis, CRLF injection, Open redirect
- Wails2 desktop UI with React/TypeScript frontend
- SQLite database, scheduling, notifications
- Template engine (YAML-based, Nuclei-compatible)
- Report generation (HTML, JSON, Markdown, SARIF)
- Payload encoding/mutation with WAF bypass
- Headless Chrome integration
- Persistent configuration
- User authentication & management

---

## Phase 1: Core Hardening & Pre-existing Bugs (Week 1-2)

### Bug fixes
- [ ] `internal/db/database_test.go`: Fix FOREIGN KEY constraint failures (3 tests broken)
- [ ] `internal/engine/config_test.go`: Fix TestConfigDefaults (defaults mismatch)
- [ ] `internal/moduleutil/helpers_test.go`: Fix ExtractParams bug (only finds 1/3 params)
- [ ] `modules/register_test.go`: Verify all 43 modules register correctly

### Security hardening
- [ ] Input validation on all `app.go` file path parameters (ImportData, DownloadReport, OpenDirectory)
- [ ] Replace hardcoded admin credentials with first-run setup wizard
- [ ] Add rate limiting on login endpoints
- [ ] SQL injection prevention audit (parameterized queries confirmed, double-check edge cases)
- [ ] XSS audit on all frontend rendering paths

### Performance
- [ ] Fix Dockerfile Go version (1.22 -> 1.25+)
- [ ] Reduce bundle size (code-splitting, lazy loading)
- [ ] Optimize slow modules (recon 89s, ldap 17s, idpwn 15s)
- [ ] Add scan timeout cascade (per-module timeout inheritance)

### Testing
- [ ] Increase test coverage to >60%
- [ ] Add integration tests for full scan pipeline
- [ ] Add frontend component tests
- [ ] CI/CD pipeline (GitHub Actions)

---

## Phase 2: Advanced Exploitation Engine (Week 3-6)

### 2.1 Authentication & Session Testing (NEW MODULES)
- [ ] **kerberos** - Kerberos attack suite: AS-REP roasting, Kerberoasting, pass-the-ticket, silver/golden ticket, MS14-068, DKCheck
- [ ] **ntlm** - NTLM relay, pass-the-hash, SMB relay, NTLM capture, responder integration
- [ ] **smb** - SMB enumeration, SMBGhost (CVE-2020-0796), EternalBlue, SMB signing check, SMB relay
- [ ] **oauth** (upgrade) - PKCE bypass, authorization code interception, device code flow abuse, token swap attacks
- [ ] **saml** - XML signature wrapping, assertion injection, replay attacks, ACS endpoint fuzzing
- [ ] **oidc** - OpenID Connect misconfigurations, claim injection, token confusion

### 2.2 Cloud-Native Attack Surface (NEW MODULES)
- [ ] **k8s** - Kubernetes pentest: API server abuse, RBAC enumeration, pod escape, secrets extraction, etcd access, container breakout, image scanning, admission controller bypass
- [ ] **helm** - Helm chart analysis, subchart hijacking, template injection
- [ ] **istio** - Istio security: authz bypass, mTLS stripping, ingress/Egress manipulation
- [ ] **serverless** - AWS Lambda/Azure Functions/GCP Cloud Functions: event injection, env vars extraction, cold start attacks
- [ ] **terraform** - IaC security scanning: state file poisoning, plan manipulation, provider hijacking
- [ ] **docker** - Container security: privilege escalation, mount attacks, capabilities audit, seccomp bypass, AppArmor evasion
- [ ] **cloudtrail** - Cloud audit log analysis, threat hunting across AWS/GCP/Azure

### 2.3 API Security (NEW MODULES)
- [ ] **graphql** (upgrade) - Depth limit bypass, batched queries, persistent queries abuse, alias-based DoS, introspection policy bypass, GraphQL-WAF evasion, subscription hijacking
- [ ] **grpc** (upgrade) - Reflection API abuse, TLS stripping, message size bomb, streaming DoS
- [ ] **rest** - REST API fuzzer: OpenAPI/Swagger import, schema validation bypass, rate-limit brute force, mass assignment, parameter smuggling
- [ ] **soap** - SOAP/XML attacks: XXE via SOAP, WS-Security bypass, SOAPAction spoofing, WSDL scanning
- [ ] **websocket** (upgrade) - WS fuzzing, WS smuggling, WS proxy bypass

### 2.4 Infrastructure & Active Directory (NEW MODULES)
- [ ] **adcs** - Active Directory Certificate Services: ESC1-ESC14 attacks, NTLM relay to CA, certificate theft, DPAPI abuse
- [ ] **exchange** - Microsoft Exchange: ProxyLogon, ProxyShell, ProxyOracle, CVE-2021-26855, mail scraping
- [ ] **vpn** - VPN gateway testing: IKE/IPSEC, WireGuard audit, OpenVPN config leak, Pulse Secure RCE
- [ ] **ldap** (upgrade) - LDAP pass-back attacks, LDAP signing/channel binding check, domain dump

### 2.5 Social Engineering & OSINT (NEW MODULES)
- [ ] **phish** - Phishing campaign automation: template editor, landing page deployer, credential capture, 2FA bypass proxy (evilginx-style), tracker analytics
- [ ] **osint** (upgrade) - Social media scraping, dark web monitoring, telegram/discord/irc crawler, breach data correlation, face recognition (exif metadata), geolocation tracking
- [ ] **pretext** - Pretexting call script generator, vishing automation, SMS phishing (SMiShing)

### 2.6 Wireless & Physical (NEW MODULES)
- [ ] **wifi** - Wi-Fi pentest: WPA3 downgrade, PMKID attack, deauth, evil twin, KRACK, beacon flood, handshake capture/crack
- [ ] **bluetooth** - Bluetooth/BLE: BlueBorne, BLUR attacks, BLE sniffing, BT classic pairing bypass
- [ ] **rfid** - RFID/NFC cloning, MiFare classic crack, desk/ndef injection
- [ ] **sdr** - Software-defined radio: ADS-B intercept, GPS spoofing, GSM capture, key fob replay
- [ ] **iot** - IoT security: MQTT/CoAP/AMQP fuzzing, firmware extraction, UART/jtag detection, OTA update hijack

### 2.7 Mobile Application Security (NEW MODULES)
- [ ] **android** - Android pentest: APK decompile/reverse, Manifest audit, intent hijacking, content provider leakage, webview RCE, Frida script generation, ADB abuse, SSL pinning bypass automation
- [ ] **ios** - iOS pentest: IPA analysis, plist inspection, Keychain audit, URL scheme hijacking, mach-o analysis, LLDB debugging automation

### 2.8 Supply Chain & CI/CD (NEW MODULES)
- [ ] **sbom** - SBOM generation/analysis: SPDX/CycloneDX parsing, dependency confusion, typo-squatting detection, malicious package identification
- [ ] **git** - Git security: .git/config exposure, commit history mining, secret leaking, hooked scanning, GitHub/GitLab/Bitbucket API abuse
- [ ] **npm** - npm/pip/gem/go/maven/nuget audit: registry poisoning, manifest hijacking, run script injection, dependency confusion
- [ ] **cicd** - CI/CD pipeline: GitHub Actions injection, Jenkins RCE, GitLab CI abuse, environment exposure, artifact poisoning

---

## Phase 4: Enterprise Platform (Week 11-14)

### 4.1 Multi-Tenant Architecture
- [ ] Organization/Team/User hierarchy
- [ ] Role-Based Access Control (RBAC): Admin, Pen-tester, Viewer, Auditor, API-only roles
- [ ] Scope management: targets per team, data isolation, audit logging
- [ ] SSO/SAML/OIDC integration for enterprise login

### 4.2 Advanced Reporting
- [ ] **report-pdf** - Professional PDF reports with branding, charts, executive summary
- [ ] **report-docx** - Word document reports for compliance submissions
- [ ] **report-pptx** - Powerpoint presentation generator for executive briefings
- [ ] **report-compliance** - Compliance mapping reports: PCI DSS v4.0, SOC 2, HIPAA, ISO 27001, NIST CSF, FedRAMP, GDPR, OWASP Top 10, CWE Top 25, SANS Top 25
- [ ] **report-timeline** - Attack timeline visualization (graphical attack chain)
- [ ] **report-remediation** - Remediation roadmap with effort estimation

### 4.3 Continuous Monitoring
- [ ] **monitor-realtime** - Real-time attack surface monitoring
- [ ] **monitor-change** - Change detection: new endpoints, modified responses, SSL changes, technology shifts
- [ ] **monitor-sla** - SLA tracking: time-to-detect, time-to-respond metrics
- [ ] **monitor-health** - Scan health monitoring: agent uptime, queue depth, error rates

### 4.4 Collaboration
- [ ] **collab-realtime** - Real-time collaboration (Operational Transform / CRDT based)
- [ ] **collab-comments** - Finding annotations, threaded discussions, @mentions
- [ ] **collab-triage** - Finding triage pipeline: new -> reviewed -> accepted -> fixed -> verified -> closed
- [ ] **collab-ticketing** - Jira/GitHub/GitLab/Trello/Asana integration with bidirectional sync
- [ ] **collab-slack** - Slack/Teams/Discord webhook integration with interactive buttons

### 4.5 Compliance & Governance
- [ ] **compliance-pci** - PCI DSS evidence collection: ASV scan requirements, CDE scope mapping
- [ ] **compliance-soc2** - SOC 2 evidence: Type I/Type II reporting, control mapping
- [ ] **compliance-hipaa** - HIPAA: PHI discovery, BA agreement verification, risk assessment
- [ ] **compliance-iso27001** - ISO 27001: Annex A control mapping, SOA generation
- [ ] **compliance-fedramp** - FedRAMP: continuous monitoring, POA&M management
- [ ] **compliance-gdpr** - GDPR: data discovery, consent audit, DPA generation, ROPA (Record of Processing Activities)
- [ ] **compliance-owa** - OWASP Top 10 + ASVS + WSTG evidence mapping

### 4.6 Workflow Automation
- [ ] **workflow-builder** - Drag-and-drop workflow builder (n8n/Zapier-like) for security automation
- [ ] **workflow-triggers** - Event-driven workflows: scan completes, finding severity changes, new target added
- [ ] **workflow-actions** - Actions: send email, create ticket, run script, trigger webhook, deploy WAF rule
- [ ] **workflow-approval** - Approval workflows for scan execution, report distribution, exceptions

---

## Phase 5: Ecosystem & Community (Week 15-18)

### 5.1 Plugin Marketplace
- [ ] **marketplace** - Plugin store: community modules, premium modules, verified publishers
- [ ] **sdk** - Plugin SDK: Python/Go/Lua scripting API, hot-reloadable modules, sandboxed execution
- [ ] **templates** - Template marketplace (Nuclei-compatible + Fang-enhanced YAML)
- [ ] **payloads** - Community payload packs, WAF bypass techniques, exploit chains

### 5.2 Integrations
- [ ] **burp** - Burp Suite extension integration: bidirectional finding sync, live traffic replay
- [ ] **metasploit** - Metasploit integration: resource script generation, module execution, session management
- [ ] **nuclei** - Nuclei template compatibility + bidirectional sync
- [ ] **maltego** - Maltego transform for OSINT data visualization
- [ ] **theHarvester** - theHarvester integration for email/DNS/subdomain enumeration
- [ ] **siem** - SIEM integration: Splunk/ELK/QRadar/Sentinel event forwarding, CEF/LEEF format
- [ ] **soar** - SOAR platform integration (Splunk SOAR, Palo Alto XSOAR, Swimlane)

### 5.3 C2 & Red Team Infrastructure
- [ ] **c2-panel** - Full C2 dashboard: beacon management, task execution, file transfer, SOCKS proxy, pivoting
- [ ] **c2-profiles** - C2 profiles: HTTP/HTTPS/DNS/ICMP/DoH/Domain Fronting/Slack/Discord/Telegram
- [ ] **c2-payloads** - Payload generation: shellcode loaders, process injection, AMSI/ETW bypass, sandbox evasion
- [ ] **c2-pivot** - Pivot proxy: SOCKS5, reverse port forwarding, chained proxying
- [ ] **c2-kits** - Attack kits: phishing landing pages, credential harvesters, browser-in-the-middle

### 5.4 Bug Bounty Automation
- [ ] **bugbounty-h1** - HackerOne integration: program import, scope sync, report submission (auto-draft)
- [ ] **bugbounty-bc** - Bugcrowd integration: same as above
- [ ] **bugbounty-int** - Intigriti integration: same as above
- [ ] **bugbounty-ywh** - YesWeHack integration: same as above
- [ ] **bugbounty-tracker** - Personal bug bounty tracker: earnings, statistics, performance analytics

### 5.5 Learning & Certification
- [ ] **academy** - Built-in security academy: interactive lessons, CTF challenges, vulnerable labs
- [ ] **cert-prep** - Certification prep: OSCP, OSWE, OSEP, GPEN, GXPN, CISSP, CEH practice exams
- [ ] **ctf** - CTF mode: capture-the-flag automation, challenge solving, writeup generation
- [ ] **lab-gen** - Vulnerable lab generator: auto-deploys DVWA, WebGoat, Juice Shop, VulnHub machines

---

## Phase 6: Polish & Scale (Week 19-24)

### 6.1 UI/UX Overhaul
- [ ] **dashboard-3d** - 3D attack surface visualization (graph-based network topology)
- [ ] **dashboard-globe** - GeoIP attack source mapping on interactive globe
- [ ] **dashboard-realtime** - Real-time scan monitor with live traffic reconstruction
- [ ] **theme-system** - Pro-grade theme system: dark/light/AMOLED/high-contrast, custom themes
- [ ] **i18n** - Internationalization: English, Turkish, Chinese, Russian, Spanish, French, German, Arabic, Japanese
- [ ] **mobile-ui** - PWA mobile app: push notifications, quick scan, dashboard on-the-go
- [ ] **keyboard** - Keyboard-first navigation: Vim-like shortcuts, command palette (Cmd+K)

### 6.2 Performance & Scale
- [ ] **distributed** - Distributed scan engine: controller + workers, Redis queue, NATS messaging
- [ ] **edge** - Edge scanning nodes: global PoPs for low-latency scanning, cloud workers
- [ ] **cluster** - High-availability clustering: leader election, task redistribution, failover
- [ ] **metrics** - Prometheus metrics endpoint + Grafana dashboards
- [ ] **profiling** - CPU/Memory profiling tools, scan cost analysis, optimization suggestions

### 6.3 Anti-Detection & Evasion
- [ ] **evasion-rate** - Adaptive rate limiting: mimics human browsing patterns
- [ ] **evasion-proxy** - Proxy rotation: tor, residential proxies, datacenter proxies, rotating user-agents
- [ ] **evasion-fingerprint** - Browser fingerprint spoofing: canvas/webGL/font/audio fingerprint randomization
- [ ] **evasion-headless** - Headless browser detection bypass: webdriver/navigator.plugins/chrome.runtime spoofing

### 6.4 Compliance & Legal
- [ ] **legal-scope** - Scope enforcement: target validation, authorization checking, auto-ROE generation
- [ ] **legal-consent** - Consent management: authorization document upload, scope acknowledgment
- [ ] **legal-audit** - Audit trail: all actions logged, tamper-proof, exportable for court evidence
- [ ] **legal-nonprofit** - Free tier for non-profits, researchers, students

### 6.5 Open Source Community
- [ ] **docs** - Comprehensive documentation: getting started, module development, API reference
- [ ] **contributing** - Contribution guidelines, code of conduct, maintainer program
- [ ] **roadmap-public** - Public roadmap with voting (GitHub Discussions)
- [ ] **hall-of-fame** - Contributors hall of fame, swag program
- [ ] **github-actions** - Official GitHub Actions for CI/CD integration
- [ ] **vscode** - VS Code extension: inline security hints, scan from IDE
- [ ] **discord** - Discord community server: support, discussion, beta access

---

## Architecture Principles

### All Hat Philosophy
- **White hat**: Responsible disclosure, compliance reports, remediation guides, CVE identification
- **Black hat**: C2 infrastructure, evasion, persistence, anti-forensics, data exfiltration (MODULES ARE EDUCATIONAL)
- **Blue hat**: Continuous monitoring, threat hunting, SIEM integration, IOC management, incident response
- **Red hat**: Advanced TTPs, infrastructure orchestration, team collaboration, OPSEQ, custom payloads
- **Gray hat**: Customizable everything, scripting API, plugin system, automation

### Technical Principles
- **Modular**: Every feature is a plugin. Zero hard dependencies between modules.
- **Extensible**: Plugin SDK for Go, Python, Lua. Hot-loadable. Sandboxed.
- **Offline-first**: Air-gapped environments fully supported.
- **OSS-core**: Core engine is always free. Premium modules are marketplace.
- **Privacy-respecting**: No telemetry. Data stays on-premise. Encryption at rest.
- **Quality**: Zero comments in source. 100% test coverage. No warnings. No panics.

### Technology Stack
- **Backend**: Go 1.25+, Wails3 (when released), SQLite, gRPC (cluster communication)
- **Frontend**: React 19, TypeScript 5.5+, Recharts, Tailwind CSS, PWA
- **Infra**: Docker, Kubernetes, GitHub Actions, Prometheus, Grafana

---

## Current Status (Phase 0) Metrics

- **Modules**: 43 registered and working
- **Go vet**: PASS
- **Go build**: PASS
- **npm build**: PASS (2376 modules, 614.61 kB)
- **Tests passing**: 129 (3 pre-existing failures - db FK, config defaults, ExtractParams)
- **Frontend**: React 18, Vite, Recharts, TanStack Query, Lucide icons
- **Database**: SQLite (modernc.org), migrations, WAL mode
- **Auth**: User management, password auth, config-based sessions

---

## How to Contribute

See `CONTRIBUTING.md` (coming soon).

Join the vision. Build the ultimate security tool. All hats welcome.
