package recon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
	"github.com/miekg/dns"
)

type ReconModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
	dnsCli *dns.Client
}

func (m *ReconModule) ID() string   { return "recon" }
func (m *ReconModule) Name() string { return "Advanced Reconnaissance" }
func (m *ReconModule) Description() string {
	return "Performs subdomain enumeration, DNS recon, certificate transparency, port scanning, technology detection, and WAF detection"
}
func (m *ReconModule) Severity() models.Severity { return models.Info }

func (m *ReconModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	m.dnsCli = &dns.Client{
		Timeout: cfg.Timeout,
	}
	return nil
}

func (m *ReconModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding
	var mu sync.Mutex
	addFindings := func(fs ...*models.Finding) {
		mu.Lock()
		findings = append(findings, fs...)
		mu.Unlock()
	}

	domain := m.extractDomain(target.URL)

	var wg sync.WaitGroup
	sem := make(chan struct{}, m.cfg.Threads)

	wg.Add(1)
	go func() {
		defer wg.Done()
		fs := m.subdomainScan(ctx, domain)
		addFindings(fs...)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		fs := m.dnsRecon(ctx, domain)
		addFindings(fs...)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		fs := m.certStreamScan(ctx, domain)
		addFindings(fs...)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		fs := m.portScan(ctx, target.URL)
		addFindings(fs...)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		fs := m.techDetect(ctx, target.URL)
		addFindings(fs...)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		fs := m.wafDetect(ctx, target.URL)
		addFindings(fs...)
	}()

	_ = sem
	wg.Wait()

	return findings, nil
}

func (m *ReconModule) extractDomain(rawURL string) string {
	rawURL = strings.TrimPrefix(rawURL, "http://")
	rawURL = strings.TrimPrefix(rawURL, "https://")
	rawURL = strings.Split(rawURL, "/")[0]
	rawURL = strings.Split(rawURL, ":")[0]
	return rawURL
}

func (m *ReconModule) subdomainScan(ctx context.Context, domain string) []*models.Finding {
	var findings []*models.Finding

	fs := m.dnsBruteForce(ctx, domain)
	findings = append(findings, fs...)

	fs = m.crtShScan(ctx, domain)
	findings = append(findings, fs...)

	fs = m.permutationEngine(ctx, domain)
	findings = append(findings, fs...)

	return findings
}

var commonSubdomains = []string{
	"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
	"admin", "panel", "cpanel", "api", "dev", "staging", "test", "beta",
	"app", "blog", "forum", "support", "help", "docs", "wiki",
	"shop", "store", "cdn", "static", "assets", "media", "img",
	"portal", "dashboard", "manage", "crm", "erp",
	"intranet", "vpn", "remote", "git", "jenkins", "ci",
	"monitor", "log", "db", "database", "mysql", "redis",
	"webmin", "ldap", "auth", "sso", "proxy",
	"status", "health", "old", "new", "backup",
	"secure", "ssl", "mx", "mail1", "mail2", "mail3",
	"imap", "pop3", "exchange", "owa",
	"sharepoint", "onedrive", "aws", "s3", "azure", "gcp",
	"kubernetes", "k8s", "docker", "search", "chat",
	"calendar", "maps", "jobs", "careers", "download",
	"files", "vpn2", "traefik", "vault", "consul",
	"gitea", "registry", "grafana", "prometheus",
	"jira", "confluence", "bitbucket", "sonar",
	"erp", "hris", "wiki2", "nexus", "harbor",
}

func (m *ReconModule) dnsBruteForce(ctx context.Context, domain string) []*models.Finding {
	var findings []*models.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	for _, sub := range commonSubdomains {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(s string) {
			defer wg.Done()
			defer func() { <-sem }()

			fqdn := s + "." + domain
			mx, ns, ips, err := m.resolveDomain(fqdn)
			if err != nil {
				return
			}

			mu.Lock()
			evidence := fmt.Sprintf("Resolved to %v", ips)
			if len(mx) > 0 {
				evidence += fmt.Sprintf(", MX: %v", mx)
			}
			if len(ns) > 0 {
				evidence += fmt.Sprintf(", NS: %v", ns)
			}
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("Subdomain Found: %s", fqdn),
				Severity:    models.Info,
				Confidence:  models.HighConfidence,
				URL:         fmt.Sprintf("https://%s", fqdn),
				Evidence:    evidence,
				Description: fmt.Sprintf("Active subdomain discovered via DNS brute force: %s", fqdn),
				Remediation: "Remove unnecessary subdomains or restrict access. Ensure all subdomains are properly secured.",
				CWEID:       "CWE-200",
				ModuleID:    "recon",
				Extra: map[string]string{
					"type":   "subdomain",
					"method": "dns_bruteforce",
				},
			})
			mu.Unlock()
		}(sub)
	}
	wg.Wait()

	return findings
}

func (m *ReconModule) resolveDomain(fqdn string) (mx []string, ns []string, ips []string, err error) {
	ips, err = m.lookupIP(fqdn)
	if err != nil {
		return nil, nil, nil, err
	}
	mx, _ = m.lookupMX(fqdn)
	ns, _ = m.lookupNS(fqdn)
	return mx, ns, ips, nil
}

func (m *ReconModule) lookupIP(host string) ([]string, error) {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

func (m *ReconModule) lookupMX(domain string) ([]string, error) {
	mx, err := net.LookupMX(domain)
	if err != nil {
		return nil, err
	}
	var hosts []string
	for _, m := range mx {
		hosts = append(hosts, m.Host)
	}
	return hosts, nil
}

func (m *ReconModule) lookupNS(domain string) ([]string, error) {
	ns, err := net.LookupNS(domain)
	if err != nil {
		return nil, err
	}
	var hosts []string
	for _, n := range ns {
		hosts = append(hosts, n.Host)
	}
	return hosts, nil
}

func (m *ReconModule) crtShScan(ctx context.Context, domain string) []*models.Finding {
	var findings []*models.Finding

	crtURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	resp, err := m.client.Get(crtURL)
	if err != nil {
		return nil
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &entries); err != nil {
		return nil
	}

	seen := make(map[string]bool)
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true

			if strings.HasSuffix(name, "."+domain) || name == domain {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("Subdomain Found (crt.sh): %s", name),
					Severity:    models.Info,
					Confidence:  models.HighConfidence,
					URL:         fmt.Sprintf("https://%s", name),
					Evidence:    "Certificate Transparency log entry from crt.sh",
					Description: fmt.Sprintf("Subdomain discovered via crt.sh certificate transparency logs: %s", name),
					Remediation: "Remove unnecessary subdomains or restrict access.",
					CWEID:       "CWE-200",
					ModuleID:    "recon",
					Extra: map[string]string{
						"type":   "subdomain",
						"method": "crtsh",
					},
				})
			}
		}
	}

	return findings
}

func (m *ReconModule) permutationEngine(ctx context.Context, domain string) []*models.Finding {
	var findings []*models.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 30)

	base := strings.TrimSuffix(domain, "."+m.getTLD(domain))
	tld := m.getTLD(domain)

	prefixes := []string{"", "www", "dev", "test", "stage", "prod", "uat", "qa", "pre"}
	suffixes := []string{"", "-dev", "-test", "-staging", "-prod", "-api", "-backup", "-old", "-new", "-v2", "-v3"}
	altTLDs := []string{"com", "net", "org", "io", "co", "app", "dev", "cloud", "xyz", "tech"}

	perms := make([]string, 0, len(prefixes)*len(suffixes)*2)
	for _, p := range prefixes {
		for _, s := range suffixes {
			if p == "" && s == "" {
				continue
			}
			perms = append(perms, p+base+s+"."+tld)
			if tld != "com" {
				perms = append(perms, p+base+s+".com")
			}
		}
	}

	for _, alt := range altTLDs {
		if alt != tld {
			perms = append(perms, base+"."+alt)
		}
	}

	for _, p := range perms {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(perm string) {
			defer wg.Done()
			defer func() { <-sem }()

			ips, err := m.lookupIP(perm)
			if err != nil {
				return
			}

			mu.Lock()
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("Permutation Found: %s", perm),
				Severity:    models.Info,
				Confidence:  models.MediumConfidence,
				URL:         fmt.Sprintf("https://%s", perm),
				Evidence:    fmt.Sprintf("Resolved to %v", ips),
				Description: fmt.Sprintf("Domain permutation discovered: %s", perm),
				Remediation: "Register lookalike domains or monitor for typo-squatting.",
				CWEID:       "CWE-200",
				ModuleID:    "recon",
				Extra: map[string]string{
					"type":   "subdomain",
					"method": "permutation",
				},
			})
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	return findings
}

func (m *ReconModule) getTLD(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "com"
	}
	return parts[len(parts)-1]
}

func (m *ReconModule) dnsRecon(ctx context.Context, domain string) []*models.Finding {
	var findings []*models.Finding

	ns, _ := net.LookupNS(domain)
	for _, n := range ns {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fs := m.zoneTransfer(ctx, domain, n.Host)
		findings = append(findings, fs...)
	}

	fs := m.spfDmarcScan(ctx, domain)
	findings = append(findings, fs...)

	fs = m.cacheSnoop(ctx, domain)
	findings = append(findings, fs...)

	fs = m.reverseDNS(ctx, domain)
	findings = append(findings, fs...)

	return findings
}

func (m *ReconModule) zoneTransfer(ctx context.Context, domain, nameserver string) []*models.Finding {
	var findings []*models.Finding

	nameserver = strings.TrimSuffix(nameserver, ".")
	transfer := new(dns.Transfer)
	m.zoneTransferQuery(ctx, transfer, domain, nameserver, &findings)

	return findings
}

func (m *ReconModule) zoneTransferQuery(ctx context.Context, transfer *dns.Transfer, domain, nameserver string, findings *[]*models.Finding) {
	mmsg := new(dns.Msg)
	mmsg.SetAxfr(dns.Fqdn(domain))

	ch, err := transfer.In(mmsg, nameserver+":53")
	if err != nil {
		return
	}

	var records []string
	for env := range ch {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if env.Error != nil {
			return
		}
		for _, rr := range env.RR {
			records = append(records, rr.String())
		}
	}

	if len(records) > 0 {
		evidence := strings.Join(records[:min(len(records), 20)], "\n")
		*findings = append(*findings, &models.Finding{
			Title:       "DNS Zone Transfer Successful",
			Severity:    models.Critical,
			Confidence:  models.CriticalConfidence,
			URL:         fmt.Sprintf("dns://%s", domain),
			Evidence:    fmt.Sprintf("Zone transfer from %s returned %d records.\nFirst records:\n%s", nameserver, len(records), evidence),
			Description: fmt.Sprintf("DNS zone transfer (AXFR) is enabled on %s, exposing all DNS records for %s.", nameserver, domain),
			Remediation: "Disable zone transfers on authoritative DNS servers. Restrict to authorized secondary DNS servers only.",
			CWEID:       "CWE-200",
			ModuleID:    "recon",
			Extra: map[string]string{
				"type":   "dnsrecon",
				"method": "zone_transfer",
			},
		})
	}
}

func (m *ReconModule) spfDmarcScan(ctx context.Context, domain string) []*models.Finding {
	var findings []*models.Finding

	txtRecords, err := net.LookupTXT(domain)
	if err == nil {
		for _, txt := range txtRecords {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			if strings.HasPrefix(txt, "v=spf1") {
				hasHardFail := strings.Contains(txt, "-all")
				hasSoftFail := strings.Contains(txt, "~all")
				allMechanism := "none"
				if hasHardFail {
					allMechanism = "-all (hard fail)"
				} else if hasSoftFail {
					allMechanism = "~all (soft fail)"
				}

				severity := models.Info
				if !hasHardFail && !hasSoftFail {
					severity = models.Medium
				}

				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("SPF Record: %s", domain),
					Severity:    severity,
					Confidence:  models.HighConfidence,
					URL:         fmt.Sprintf("dns://%s/TXT", domain),
					Evidence:    txt,
					Description: fmt.Sprintf("SPF record found with %s mechanism. Unauthorized senders %s blocked.", allMechanism, map[bool]string{true: "are", false: "are NOT"}[hasHardFail]),
					Remediation: "Ensure SPF includes '-all' (hard fail) to prevent email spoofing.",
					CWEID:       "CWE-200",
					ModuleID:    "recon",
					Extra: map[string]string{
						"type":   "dnsrecon",
						"method": "spf",
					},
				})
			}
		}
	}

	dmarcDomain := "_dmarc." + domain
	dmarcRecords, err := net.LookupTXT(dmarcDomain)
	if err == nil {
		for _, txt := range dmarcRecords {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			if strings.HasPrefix(txt, "v=DMARC1") {
				hasReject := strings.Contains(txt, "p=reject")
				hasQuarantine := strings.Contains(txt, "p=quarantine")
				hasNone := strings.Contains(txt, "p=none")

				severity := models.Info
				if hasNone {
					severity = models.Medium
				}

				policy := "none"
				if hasReject {
					policy = "reject"
				} else if hasQuarantine {
					policy = "quarantine"
				}

				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("DMARC Record: %s", dmarcDomain),
					Severity:    severity,
					Confidence:  models.HighConfidence,
					URL:         fmt.Sprintf("dns://%s/TXT", dmarcDomain),
					Evidence:    txt,
					Description: fmt.Sprintf("DMARC record found with policy '%s'. Emails failing SPF/DKIM %s.", policy, map[string]string{"reject": "will be rejected", "quarantine": "may be quarantined", "none": "will be delivered"}[policy]),
					Remediation: "Set DMARC policy to 'p=reject' once SPF and DKIM are configured correctly.",
					CWEID:       "CWE-200",
					ModuleID:    "recon",
					Extra: map[string]string{
						"type":   "dnsrecon",
						"method": "dmarc",
					},
				})
			}
		}
	}

	if err != nil {
		findings = append(findings, &models.Finding{
			Title:       "DMARC Record Missing",
			Severity:    models.Medium,
			Confidence:  models.HighConfidence,
			URL:         fmt.Sprintf("dns://%s/TXT", dmarcDomain),
			Evidence:    "No DMARC TXT record found",
			Description: fmt.Sprintf("No DMARC record found for %s. Email spoofing protection is not configured.", dmarcDomain),
			Remediation: fmt.Sprintf("Add a DMARC record (e.g., 'v=DMARC1; p=reject; rua=mailto:dmarc@%s') to prevent email spoofing.", domain),
			CWEID:       "CWE-200",
			ModuleID:    "recon",
			Extra: map[string]string{
				"type":   "dnsrecon",
				"method": "dmarc",
			},
		})
	}

	return findings
}

func (m *ReconModule) cacheSnoop(ctx context.Context, domain string) []*models.Finding {
	return nil
}

func (m *ReconModule) reverseDNS(ctx context.Context, domain string) []*models.Finding {
	var findings []*models.Finding

	ips, err := net.LookupHost(domain)
	if err != nil {
		return nil
	}

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		names, err := net.LookupAddr(ip)
		if err != nil || len(names) == 0 {
			continue
		}

		for _, name := range names {
			name = strings.TrimSuffix(name, ".")
			if name != domain {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("Reverse DNS: %s -> %s", ip, name),
					Severity:    models.Info,
					Confidence:  models.HighConfidence,
					URL:         fmt.Sprintf("https://%s", domain),
					Evidence:    fmt.Sprintf("PTR record: %s resolves to %s", ip, name),
					Description: fmt.Sprintf("Reverse DNS lookup for %s reveals hostname %s which differs from the target domain.", ip, name),
					Remediation: "Ensure PTR records align with forward DNS records for security auditing.",
					CWEID:       "CWE-200",
					ModuleID:    "recon",
					Extra: map[string]string{
						"type":   "dnsrecon",
						"method": "reverse_dns",
					},
				})
			}
		}
	}

	return findings
}

func (m *ReconModule) certStreamScan(ctx context.Context, domain string) []*models.Finding {
	var findings []*models.Finding

	cfg := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", domain+":443", cfg)
	if err != nil {
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}

	cert := certs[0]
	issuerOrg := ""
	if len(cert.Issuer.Organization) > 0 {
		issuerOrg = cert.Issuer.Organization[0]
	}

	findings = append(findings, &models.Finding{
		Title:       "TLS Certificate Information",
		Severity:    models.Info,
		Confidence:  models.HighConfidence,
		URL:         fmt.Sprintf("https://%s", domain),
		Evidence:    fmt.Sprintf("Subject: %s, Issuer: %s, Expires: %s", cert.Subject.CommonName, issuerOrg, cert.NotAfter.Format(time.RFC3339)),
		Description: fmt.Sprintf("TLS certificate for %s issued by %s, valid until %s.", domain, issuerOrg, cert.NotAfter.Format(time.RFC3339)),
		Remediation: "Ensure TLS certificates are valid, properly configured, and renew before expiry.",
		CWEID:       "CWE-200",
		ModuleID:    "recon",
		Extra: map[string]string{
			"type":    "certstream",
			"method":  "tls_certificate",
			"expires": cert.NotAfter.Format(time.RFC3339),
			"issuer":  issuerOrg,
		},
	})

	altNames := getCertAltNames(cert)
	if len(altNames) > 1 {
		var extras []string
		for _, an := range altNames {
			if an != domain {
				extras = append(extras, an)
			}
		}
		if len(extras) > 0 {
			findings = append(findings, &models.Finding{
				Title:       "Certificate SANs/Additional Hostnames",
				Severity:    models.Info,
				Confidence:  models.HighConfidence,
				URL:         fmt.Sprintf("https://%s", domain),
				Evidence:    fmt.Sprintf("Additional hostnames in cert: %s", strings.Join(extras, ", ")),
				Description: fmt.Sprintf("The TLS certificate for %s includes %d additional hostnames which may represent related subdomains.", domain, len(extras)),
				Remediation: "Review all hostnames in TLS certificates to ensure they are intended to be exposed.",
				CWEID:       "CWE-200",
				ModuleID:    "recon",
				Extra: map[string]string{
					"type":   "certstream",
					"method": "san_hostnames",
				},
			})
		}
	}

	return findings
}

func getCertAltNames(cert *x509.Certificate) []string {
	names := []string{cert.Subject.CommonName}
	names = append(names, cert.DNSNames...)
	return names
}

var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 389, 443, 445,
	465, 502, 504, 554, 587, 631, 636, 993, 995, 1025, 1026, 1027, 1028,
	1029, 1110, 1433, 1521, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
	2222, 2375, 2376, 3000, 3001, 3128, 3268, 3269, 3306, 3389, 3690,
	4000, 4040, 4443, 4567, 4643, 4848, 5000, 5001, 5003, 5040, 5060,
	5104, 5222, 5353, 5432, 5433, 5443, 5500, 5522, 5555, 5601, 5631,
	5666, 5672, 5800, 5900, 5901, 5984, 5985, 5986, 6000, 6001, 6002,
	6379, 6443, 6514, 6560, 6666, 6667, 6668, 6669, 6697, 7000, 7001,
	7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009, 7010, 7070, 7071,
	7077, 8000, 8001, 8008, 8009, 8010, 8020, 8030, 8040, 8050, 8060,
	8070, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
	8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099, 8100,
	8181, 8200, 8222, 8243, 8280, 8300, 8400, 8443, 8500, 8530, 8880,
	8888, 8889, 8899, 8983, 9000, 9001, 9002, 9043, 9060, 9080, 9090,
	9091, 9100, 9200, 9292, 9300, 9400, 9418, 9443, 9600, 9700, 9877,
	9898, 9900, 9981, 9999, 10000, 10001, 10080, 10443, 11211, 11371,
	12345, 13579, 16010, 16113, 17000, 17001, 18080, 18081, 18091, 18092,
	19000, 19001, 20000, 27017, 27018, 27019, 28017, 31337, 32768, 32769,
	32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779,
	32780, 32781, 32782, 32783, 32784, 32785, 49152, 49153, 49154, 49155,
	49156, 49157, 49158, 49159, 49160, 49161, 49162, 49163, 49164, 49165,
	49166, 49167, 49168, 49169, 49170, 49171, 49172, 49173, 49174, 49175,
	49176, 49177, 49178, 49179, 49180, 49181, 49182, 49183, 49184, 49185,
	49186, 49187, 49188, 49189, 49190, 49191, 49192, 49193, 49194, 49195,
	49196, 49197, 49198, 49199, 49200, 49201, 50000, 50001, 50002, 50003,
	50010, 50070, 50075, 50090, 60000, 60001,
}

func (m *ReconModule) portScan(ctx context.Context, baseURL string) []*models.Finding {
	var findings []*models.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 100)

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	host := parsed.Hostname()

	ports := commonPorts
	if m.cfg != nil && m.cfg.Quick {
		ports = commonPorts[:30]
	}

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			addr := net.JoinHostPort(host, fmt.Sprintf("%d", p))
			conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
			if err != nil {
				return
			}
			conn.Close()

			service := m.lookupService(p)
			mu.Lock()
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("Open Port: %d/%s", p, service),
				Severity:    models.Info,
				Confidence:  models.HighConfidence,
				URL:         fmt.Sprintf("%s:%d", host, p),
				Evidence:    fmt.Sprintf("Port %d (%s) is open on %s", p, service, host),
				Description: fmt.Sprintf("Open port %d (%s) detected on %s.", p, service, host),
				Remediation: "Close unnecessary ports. Ensure services running on open ports are properly secured and updated.",
				CWEID:       "CWE-200",
				ModuleID:    "recon",
				Extra: map[string]string{
					"type":    "portscan",
					"port":    fmt.Sprintf("%d", p),
					"service": service,
				},
			})
			mu.Unlock()
		}(port)
	}
	wg.Wait()

	return findings
}

func (m *ReconModule) lookupService(port int) string {
	services := map[int]string{
		21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
		80: "HTTP", 81: "HTTP-Alt", 110: "POP3", 111: "RPC", 135: "MSRPC",
		139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
		465: "SMTPS", 502: "Modbus", 554: "RTSP", 587: "SMTP-Submit",
		631: "IPP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
		1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2082: "cPanel",
		2083: "cPanel-SSL", 2375: "Docker", 2376: "Docker-SSL",
		3000: "Gitea/Dev", 3128: "Squid", 3306: "MySQL", 3389: "RDP",
		3690: "SVN", 4000: "HTTP-Alt", 4443: "HTTPS-Alt", 4567: "Sinatra",
		4848: "GlassFish", 5000: "Flask/Dev", 5432: "PostgreSQL",
		5555: "FreeCiv", 5601: "Kibana", 5672: "RabbitMQ", 5800: "VNC-HTTP",
		5900: "VNC", 5901: "VNC-1", 5984: "CouchDB", 5985: "WinRM-HTTP",
		5986: "WinRM-HTTPS", 6379: "Redis", 6443: "Kubernetes-API",
		6667: "IRC", 7001: "WebLogic", 7070: "RTMP", 7077: "Mesos",
		8000: "HTTP-Alt", 8001: "HTTP-Alt", 8080: "HTTP-Proxy",
		8081: "HTTP-Alt", 8443: "HTTPS-Alt", 8530: "Drupal",
		8888: "HTTP-Alt", 9000: "Hadoop/Dev", 9001: "Tor",
		9043: "WebSphere", 9060: "WebSphere", 9090: "Cockpit",
		9091: "Openfire", 9200: "Elasticsearch", 9300: "Elasticsearch",
		9418: "Git", 9443: "HTTPS-Alt", 9600: "F5", 9877: "SAP",
		9999: "HTTP-Alt", 10000: "Webmin", 11211: "Memcached",
		11371: "OpenPGP-HKP", 12345: "NetBus", 13579: "Unknown",
		16010: "HBase", 17000: "HBase", 18080: "HTTP-Alt",
		20000: "Usermin", 27017: "MongoDB", 27018: "MongoDB-Web",
		28017: "MongoDB-Status", 31337: "BackOrifice",
		50000: "SAP", 50070: "HDFS", 50075: "HDFS",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return "unknown"
}

func (m *ReconModule) techDetect(ctx context.Context, targetURL string) []*models.Finding {
	var findings []*models.Finding

	resp, err := m.client.Get(targetURL)
	if err != nil {
		return nil
	}

	body := resp.Body
	headers := resp.Headers
	detected := make(map[string]models.Technology)

	if server := headers.Get("Server"); server != "" {
		detected[server] = models.Technology{Name: server, Type: "Server"}
	}
	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		detected[poweredBy] = models.Technology{Name: poweredBy, Type: "Framework"}
	}

	cmsPatterns := map[string]string{
		"wp-content": "WordPress", "wp-includes": "WordPress",
		"joomla": "Joomla", "drupal": "Drupal",
		"shopify": "Shopify", "magento": "Magento",
		"prestashop": "PrestaShop", "laravel": "Laravel",
		"djangoproject": "Django", "rails": "Ruby on Rails",
		"spring": "Spring", "next": "Next.js",
		"nuxt": "Nuxt.js", "gatsby": "Gatsby",
		"webpack": "Webpack", "vite": "Vite",
		"asp.net": "ASP.NET", "express": "Express.js",
		"flask": "Flask", "fastapi": "FastAPI",
		"symfony": "Symfony", "codeigniter": "CodeIgniter",
		"cakephp": "CakePHP", "yii": "Yii",
	}
	for pattern, name := range cmsPatterns {
		select {
		case <-ctx.Done():
			return findings
		default:
		}
		if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
			detected[pattern] = models.Technology{Name: name, Type: "CMS/Framework"}
		}
	}

	jsPatterns := map[string]string{
		"jquery": "jQuery", "react": "React", "vue": "Vue.js",
		"angular": "Angular", "backbone": "Backbone.js",
		"underscore": "Underscore.js", "lodash": "Lodash",
		"bootstrap": "Bootstrap", "tailwind": "Tailwind CSS",
		"moment": "Moment.js", "axios": "Axios",
		"three": "Three.js", "d3": "D3.js", "chart": "Chart.js",
		"swiper": "Swiper", "select2": "Select2",
		"datatables": "DataTables", "fontawesome": "Font Awesome",
	}
	for pattern, name := range jsPatterns {
		select {
		case <-ctx.Done():
			return findings
		default:
		}
		if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
			detected[pattern] = models.Technology{Name: name, Type: "JavaScript Library"}
		}
	}

	genRe := regexp.MustCompile(`(?i)<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']`)
	if match := genRe.FindStringSubmatch(body); len(match) > 1 {
		detected[match[1]] = models.Technology{Name: match[1], Type: "Generator"}
	}

	cookieTechs := map[string]string{
		"PHPSESSID": "PHP", "JSESSIONID": "Java",
		"ASP.NET_SessionId": "ASP.NET", "connect.sid": "Express.js",
		"_rails_session": "Ruby on Rails", "csrftoken": "Django",
		"laravel_session": "Laravel", "XDEBUG_SESSION": "PHP XDebug",
		"wordpress_logged_in": "WordPress", "wp-settings": "WordPress",
		"CFID": "ColdFusion", "CFTOKEN": "ColdFusion",
	}
	for _, cookie := range resp.Cookies {
		if tech, ok := cookieTechs[cookie.Name]; ok {
			detected[cookie.Name] = models.Technology{Name: tech, Type: "Language/Framework"}
		}
	}

	seen := make(map[string]bool)
	for name, tech := range detected {
		if seen[name] {
			continue
		}
		seen[name] = true
		findings = append(findings, &models.Finding{
			Title:       fmt.Sprintf("Technology Detected: %s (%s)", tech.Name, tech.Type),
			Severity:    models.Info,
			Confidence:  models.HighConfidence,
			URL:         targetURL,
			Evidence:    fmt.Sprintf("%s detected (%s)", tech.Name, tech.Type),
			Description: fmt.Sprintf("Technology detected: %s (%s). This helps identify potential attack surface.", tech.Name, tech.Type),
			Remediation: "Remove unnecessary technology identifiers from HTTP headers and HTML source.",
			CWEID:       "CWE-200",
			ModuleID:    "recon",
			Extra: map[string]string{
				"type": "techdetect",
				"name": tech.Name,
				"kind": tech.Type,
			},
		})
	}

	return findings
}

var wafSignatures = []struct {
	Name    string
	Header  string
	Pattern string
}{
	{"Cloudflare", "cf-ray", "cloudflare"},
	{"Cloudflare", "server", "cloudflare"},
	{"Akamai", "server", "akamai"},
	{"Akamai", "x-akamai-transformed", "akamai"},
	{"AWS WAF", "x-amzn-waf", ""},
	{"AWS CloudFront", "x-amz-cf-id", ""},
	{"Imperva", "x-iinfo", ""},
	{"Incapsula", "x-incap-ses", ""},
	{"Sucuri", "x-sucuri-id", ""},
	{"Sucuri", "server", "sucuri"},
	{"ModSecurity", "server", "mod_security"},
	{"Barracuda", "x-barra", ""},
	{"F5 BIG-IP", "server", "bigip"},
	{"Fortinet", "server", "fortinet"},
	{"Citrix NetScaler", "server", "netscaler"},
	{"Citrix NetScaler", "set-cookie", "ns_af"},
	{"DenyAll", "server", "denyall"},
	{"Radware", "server", "radware"},
	{"Reblaze", "server", "reblaze"},
	{"Wallarm", "x-wallarm", ""},
	{"Varnish", "via", "varnish"},
	{"Nginx", "server", "nginx"},
	{"Apache", "server", "apache"},
	{"Microsoft IIS", "server", "microsoft-iis"},
	{"LiteSpeed", "server", "litespeed"},
}

func (m *ReconModule) wafDetect(ctx context.Context, targetURL string) []*models.Finding {
	var findings []*models.Finding

	resp, err := m.client.Get(targetURL)
	if err != nil {
		return nil
	}

	detected := make(map[string]bool)

	for _, waf := range wafSignatures {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		headerValue := resp.Headers.Get(waf.Header)
		if headerValue != "" {
			if waf.Pattern == "" || strings.Contains(strings.ToLower(headerValue), strings.ToLower(waf.Pattern)) {
				if !detected[waf.Name] {
					detected[waf.Name] = true
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("WAF Detected: %s", waf.Name),
						Severity:    models.Info,
						Confidence:  models.HighConfidence,
						URL:         targetURL,
						Evidence:    fmt.Sprintf("Header %s: %s", waf.Header, headerValue),
						Description: fmt.Sprintf("Web Application Firewall detected: %s", waf.Name),
						Remediation: "Note: WAF may block some scan payloads. Adjust scan intensity accordingly.",
						CWEID:       "CWE-200",
						ModuleID:    "recon",
						Extra: map[string]string{
							"type": "wafdetect",
							"waf":  waf.Name,
						},
					})
				}
			}
		}
	}

	maliciousPayloads := []string{
		"<script>alert(1)</script>",
		"' OR '1'='1",
		"../../../etc/passwd",
		"{{7*7}}",
	}
	for _, payload := range maliciousPayloads {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		testURL := targetURL + "?q=" + url.QueryEscape(payload)
		resp, err := m.client.Get(testURL)
		if err != nil {
			continue
		}

		if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 419 || resp.StatusCode == 501 {
			if !detected["Unknown WAF (Behavioral)"] {
				detected["Unknown WAF (Behavioral)"] = true
				findings = append(findings, &models.Finding{
					Title:       "WAF/IDS Detected (Behavioral)",
					Severity:    models.Info,
					Confidence:  models.MediumConfidence,
					URL:         targetURL,
					Evidence:    fmt.Sprintf("Status %d returned with malicious payload: %s", resp.StatusCode, payload),
					Description: "WAF/IDS detected based on behavioral response to malicious payload.",
					Remediation: "Note: WAF may block some scan payloads.",
					CWEID:       "CWE-200",
					ModuleID:    "recon",
					Extra: map[string]string{
						"type": "wafdetect",
						"waf":  "Unknown (Behavioral)",
					},
				})
			}
		}
	}

	if !detected["Unknown WAF (Behavioral)"] && len(detected) == 0 {
		findings = append(findings, &models.Finding{
			Title:       "No WAF/IDS Detected",
			Severity:    models.Info,
			Confidence:  models.LowConfidence,
			URL:         targetURL,
			Evidence:    "No WAF signatures or behavioral indicators found",
			Description: "No Web Application Firewall detected for the target.",
			Remediation: "Consider implementing a WAF as a security best practice.",
			CWEID:       "CWE-200",
			ModuleID:    "recon",
			Extra: map[string]string{
				"type": "wafdetect",
			},
		})
	}

	return findings
}

func init() {
	engine.GetRegistry().Register(&ReconModule{})
}
