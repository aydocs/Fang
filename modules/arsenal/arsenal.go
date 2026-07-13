package arsenal

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type ArsenalModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *ArsenalModule) ID() string   { return "arsenal" }
func (m *ArsenalModule) Name() string { return "Payload & Method Database" }
func (m *ArsenalModule) Description() string {
	return "Payload database scanning, hash recognition (100+ formats), encoding detection/decoding, payload mutation engine detection"
}
func (m *ArsenalModule) Severity() models.Severity { return models.Medium }

func (m *ArsenalModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

var payloadDBPaths = []string{
	"/payloads", "/payload", "/payloads.txt", "/payloads.json",
	"/wordlist", "/wordlists", "/fuzz", "/fuzzdb", "/fuzzing",
	"/seclists", "/SecLists", "/exploitdb", "/exploits",
	"/rockyou.txt", "/rockyou", "/passwords.txt", "/passwords",
	"/xss-payloads", "/sqli-payloads", "/lfi-payloads",
	"/api/payloads", "/api/fuzz", "/api/wordlist",
}

var hashPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
	Length  int
}{
	{`MD5`, regexp.MustCompile(`^[a-f0-9]{32}$`), 32},
	{`SHA-1`, regexp.MustCompile(`^[a-f0-9]{40}$`), 40},
	{`SHA-256`, regexp.MustCompile(`^[a-f0-9]{64}$`), 64},
	{`SHA-384`, regexp.MustCompile(`^[a-f0-9]{96}$`), 96},
	{`SHA-512`, regexp.MustCompile(`^[a-f0-9]{128}$`), 128},
	{`SHA-224`, regexp.MustCompile(`^[a-f0-9]{56}$`), 56},
	{`bcrypt`, regexp.MustCompile(`^\$2[ayb]\$\d{2}\$[./A-Za-z0-9]{53}$`), 60},
	{`bcrypt`, regexp.MustCompile(`^\$2[ayb]\$\d{2}\$[./A-Za-z0-9]{53}`), 0},
	{`scrypt`, regexp.MustCompile(`^[A-Za-z0-9+/=]{128,}$`), 0},
	{`SHA-512 crypt`, regexp.MustCompile(`^\$6\$\w+\$[./A-Za-z0-9]{86}`), 0},
	{`SHA-256 crypt`, regexp.MustCompile(`^\$5\$\w+\$[./A-Za-z0-9]{43}`), 0},
	{`NTLM`, regexp.MustCompile(`^[a-f0-9]{32}$`), 32},
	{`NTLM (with prefix)`, regexp.MustCompile(`^[a-f0-9]{32}:[a-f0-9]{32}$`), 65},
	{`LM`, regexp.MustCompile(`^[a-f0-9]{32}$`), 32},
	{`MD4`, regexp.MustCompile(`^[a-f0-9]{32}$`), 32},
	{`MD2`, regexp.MustCompile(`^[a-f0-9]{32}$`), 32},
	{`MD4(NTLM)`, regexp.MustCompile(`^[a-f0-9]{32}$`), 32},
	{`Kerberos 5 TGS-REP`, regexp.MustCompile(`^\$krb5tgs\$.*\$`), 0},
	{`Kerberos 5 AS-REP`, regexp.MustCompile(`^\$krb5asrep\$.*\$`), 0},
	{`Kerberos 5 TGT`, regexp.MustCompile(`^\$krb5tgt\$.*\$`), 0},
	{`MySQL 3.x`, regexp.MustCompile(`^[a-f0-9]{16}$`), 16},
	{`MySQL 4.1+`, regexp.MustCompile(`^\*[a-f0-9]{40}$`), 41},
	{`PostgreSQL MD5`, regexp.MustCompile(`^md5[a-f0-9]{32}$`), 35},
	{`Oracle 10g`, regexp.MustCompile(`^[a-f0-9]{40}$`), 40},
	{`Oracle 11g`, regexp.MustCompile(`^S:[a-f0-9]{60}$`), 62},
	{`Oracle 12c`, regexp.MustCompile(`^[a-f0-9]{60}$`), 60},
	{`DES crypt`, regexp.MustCompile(`^[./A-Za-z0-9]{13}$`), 13},
	{`MD5 crypt`, regexp.MustCompile(`^\$1\$\w+\$[./A-Za-z0-9]{22}`), 0},
	{`Apache MD5`, regexp.MustCompile(`^\$apr1\$\w+\$[./A-Za-z0-9]{22}`), 0},
	{`PHPass`, regexp.MustCompile(`^\$P\$\w{31}$`), 34},
	{`PHPass`, regexp.MustCompile(`^\$H\$\w{31}$`), 34},
	{`RIPEMD-128`, regexp.MustCompile(`^[a-f0-9]{32}$`), 32},
	{`RIPEMD-160`, regexp.MustCompile(`^[a-f0-9]{40}$`), 40},
	{`RIPEMD-256`, regexp.MustCompile(`^[a-f0-9]{64}$`), 64},
	{`RIPEMD-320`, regexp.MustCompile(`^[a-f0-9]{80}$`), 80},
	{`Whirlpool`, regexp.MustCompile(`^[a-f0-9]{128}$`), 128},
	{`Tiger-160`, regexp.MustCompile(`^[a-f0-9]{40}$`), 40},
	{`Tiger-192`, regexp.MustCompile(`^[a-f0-9]{48}$`), 48},
	{`GOST R 34.11-94`, regexp.MustCompile(`^[a-f0-9]{64}$`), 64},
	{`GOST R 34.11-2012 (Streebog-256)`, regexp.MustCompile(`^[a-f0-9]{64}$`), 64},
	{`GOST R 34.11-2012 (Streebog-512)`, regexp.MustCompile(`^[a-f0-9]{128}$`), 128},
	{`Snefru-128`, regexp.MustCompile(`^[a-f0-9]{32}$`), 32},
	{`Snefru-256`, regexp.MustCompile(`^[a-f0-9]{64}$`), 64},
	{`CRC-16`, regexp.MustCompile(`^[a-f0-9]{4}$`), 4},
	{`CRC-32`, regexp.MustCompile(`^[a-f0-9]{8}$`), 8},
	{`CRC-64`, regexp.MustCompile(`^[a-f0-9]{16}$`), 16},
	{`Adler-32`, regexp.MustCompile(`^[a-f0-9]{8}$`), 8},
	{`FNV-1 32`, regexp.MustCompile(`^[a-f0-9]{8}$`), 8},
	{`FNV-1 64`, regexp.MustCompile(`^[a-f0-9]{16}$`), 16},
	{`FNV-1a 32`, regexp.MustCompile(`^[a-f0-9]{8}$`), 8},
	{`FNV-1a 64`, regexp.MustCompile(`^[a-f0-9]{16}$`), 16},
	{`SHA-3 224`, regexp.MustCompile(`^[a-f0-9]{56}$`), 56},
	{`SHA-3 256`, regexp.MustCompile(`^[a-f0-9]{64}$`), 64},
	{`SHA-3 384`, regexp.MustCompile(`^[a-f0-9]{96}$`), 96},
	{`SHA-3 512`, regexp.MustCompile(`^[a-f0-9]{128}$`), 128},
	{`BLAKE2b-160`, regexp.MustCompile(`^[a-f0-9]{40}$`), 40},
	{`BLAKE2b-256`, regexp.MustCompile(`^[a-f0-9]{64}$`), 64},
	{`BLAKE2b-384`, regexp.MustCompile(`^[a-f0-9]{96}$`), 96},
	{`BLAKE2b-512`, regexp.MustCompile(`^[a-f0-9]{128}$`), 128},
	{`BLAKE2s-224`, regexp.MustCompile(`^[a-f0-9]{56}$`), 56},
	{`BLAKE2s-256`, regexp.MustCompile(`^[a-f0-9]{64}$`), 64},
	{`BLAKE3`, regexp.MustCompile(`^[a-f0-9]{64}$`), 64},
	{`SM3`, regexp.MustCompile(`^[a-f0-9]{64}$`), 64},
	{`LM`, regexp.MustCompile(`^[A-F0-9]{32}$`), 32},
	{`CRC-32C`, regexp.MustCompile(`^[a-f0-9]{8}$`), 8},
	{`XXH32`, regexp.MustCompile(`^[a-f0-9]{8}$`), 8},
	{`XXH64`, regexp.MustCompile(`^[a-f0-9]{16}$`), 16},
	{`XXH128`, regexp.MustCompile(`^[a-f0-9]{32}$`), 32},
	{`SipHash-2-4`, regexp.MustCompile(`^[a-f0-9]{16}$`), 16},
	{`HMAC-MD5`, regexp.MustCompile(`^[a-f0-9]{32}$`), 32},
	{`HMAC-SHA1`, regexp.MustCompile(`^[a-f0-9]{40}$`), 40},
	{`HMAC-SHA256`, regexp.MustCompile(`^[a-f0-9]{64}$`), 64},
	{`HMAC-SHA384`, regexp.MustCompile(`^[a-f0-9]{96}$`), 96},
	{`HMAC-SHA512`, regexp.MustCompile(`^[a-f0-9]{128}$`), 128},
	{`PBKDF2-HMAC-SHA256`, regexp.MustCompile(`^\$pbkdf2-sha256\$\d+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$`), 0},
	{`PBKDF2-HMAC-SHA512`, regexp.MustCompile(`^\$pbkdf2-sha512\$\d+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$`), 0},
	{`Argon2i`, regexp.MustCompile(`^\$argon2i\$v=\d+\$m=\d+,t=\d+,p=\d+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$`), 0},
	{`Argon2id`, regexp.MustCompile(`^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$`), 0},
	{`Argon2d`, regexp.MustCompile(`^\$argon2d\$v=\d+\$m=\d+,t=\d+,p=\d+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$`), 0},
	{`CRC-16 CCITT`, regexp.MustCompile(`^[a-f0-9]{4}$`), 4},
	{`CRC-16 IBM`, regexp.MustCompile(`^[a-f0-9]{4}$`), 4},
	{`CRC-16 DNP`, regexp.MustCompile(`^[a-f0-9]{4}$`), 4},
	{`CRC-16 Modbus`, regexp.MustCompile(`^[a-f0-9]{4}$`), 4},
	{`CRC-16 USB`, regexp.MustCompile(`^[a-f0-9]{4}$`), 4},
	{`CRC-24`, regexp.MustCompile(`^[a-f0-9]{6}$`), 6},
	{`CRC-32 MPEG2`, regexp.MustCompile(`^[a-f0-9]{8}$`), 8},
	{`CRC-32 BZIP2`, regexp.MustCompile(`^[a-f0-9]{8}$`), 8},
	{`CRC-32 POSIX`, regexp.MustCompile(`^[a-f0-9]{8}$`), 8},
	{`CRC-32Q`, regexp.MustCompile(`^[a-f0-9]{8}$`), 8},
	{`CRC-32 JAMCRC`, regexp.MustCompile(`^[a-f0-9]{8}$`), 8},
	{`CRC-32 XFER`, regexp.MustCompile(`^[a-f0-9]{8}$`), 8},
	{`CRC-64 ECMA`, regexp.MustCompile(`^[a-f0-9]{16}$`), 16},
	{`CRC-64 ISO`, regexp.MustCompile(`^[a-f0-9]{16}$`), 16},
	{`CRC-64 WE`, regexp.MustCompile(`^[a-f0-9]{16}$`), 16},
	{`CRC-64 XZ`, regexp.MustCompile(`^[a-f0-9]{16}$`), 16},
	{`MD5 (HMAC)`, regexp.MustCompile(`^[a-f0-9]{32}$`), 32},
	{`NT (Vista+)`, regexp.MustCompile(`^[a-f0-9]{32}$`), 32},
	{`Domain Cached Credentials`, regexp.MustCompile(`^\$DCC2\$\w+#\w+\$[a-f0-9]{32}$`), 0},
	{`MAC (LM)`, regexp.MustCompile(`^[a-f0-9]{32}$`), 32},
	{`MAC (NTLM)`, regexp.MustCompile(`^[a-f0-9]{32}$`), 32},
	{`SSHA-1`, regexp.MustCompile(`^\{SSHA\}[A-Za-z0-9+/=]{28,}`), 0},
	{`SSHA-256`, regexp.MustCompile(`^\{SSHA256\}[A-Za-z0-9+/=]{44,}`), 0},
	{`SSHA-512`, regexp.MustCompile(`^\{SSHA512\}[A-Za-z0-9+/=]{76,}`), 0},
	{`SMD5`, regexp.MustCompile(`^\{SMD5\}[A-Za-z0-9+/=]{24,}`), 0},
	{`Salted MD5`, regexp.MustCompile(`^\{SALT\}[A-Za-z0-9+/=]{24,}`), 0},
	{`Cisco PIX`, regexp.MustCompile(`^[a-f0-9]{16}$`), 16},
	{`Cisco Type 5`, regexp.MustCompile(`^\$1\$\w+\$[./A-Za-z0-9]{22}`), 0},
	{`Cisco Type 7`, regexp.MustCompile(`^\d{2}[a-f0-9]+$`), 0},
	{`Cisco Type 8`, regexp.MustCompile(`^\$8\$\w+\$[./A-Za-z0-9]{86}`), 0},
	{`Cisco Type 9`, regexp.MustCompile(`^\$9\$\w+\$[./A-Za-z0-9]{86}`), 0},
	{`Juniper IVE`, regexp.MustCompile(`^\$9\$[./A-Za-z0-9]+$`), 0},
	{`Juniper ScreenOS`, regexp.MustCompile(`^[a-f0-9]{6}\.[a-f0-9]{8}\.[a-f0-9]{16}$`), 0},
	{`MSSQL 2000`, regexp.MustCompile(`^0x[a-f0-9]{20}$`), 22},
	{`MSSQL 2005`, regexp.MustCompile(`^0x[a-f0-9]{40}$`), 42},
	{`MSSQL 2012+`, regexp.MustCompile(`^0x[a-f0-9]{60}$`), 62},
	{`Sybase`, regexp.MustCompile(`^0x[a-f0-9]{32}$`), 34},
	{`EPi`, regexp.MustCompile(`^\$episerver\$\*[a-f0-9]+\*[a-f0-9]+$`), 0},
	{`MediaWiki`, regexp.MustCompile(`^\$B\$\w{31}$`), 34},
	{`Django`, regexp.MustCompile(`^pbkdf2_sha256\$\d+\$[A-Za-z0-9]+\$[A-Za-z0-9]+$`), 0},
	{`Django (MD5)`, regexp.MustCompile(`^md5\$[A-Za-z0-9]+\$[a-f0-9]{32}$`), 0},
	{`Drupal 7`, regexp.MustCompile(`^\$S\$\w{52}$`), 55},
	{`Drupal 8+`, regexp.MustCompile(`^\$S\$\w{55}$`), 58},
	{`Joomla 2.5+`, regexp.MustCompile(`^[a-f0-9]{32}:[A-Za-z0-9]{16,32}$`), 0},
	{`vBulletin`, regexp.MustCompile(`^[a-f0-9]{32}`), 32},
	{`SMF (SHA-1)`, regexp.MustCompile(`^[a-f0-9]{40}`), 40},
	{`phpBB3 (MD5)`, regexp.MustCompile(`^\$H\$\w{31}$`), 34},
	{`WordPress (phpass)`, regexp.MustCompile(`^\$P\$\w{31}$`), 34},
	{`osCommerce (md5)`, regexp.MustCompile(`^[a-f0-9]{32}:[A-Za-z0-9]{2}$`), 35},
	{`DES (BSDi)`, regexp.MustCompile(`^_[./A-Za-z0-9]{19}$`), 20},
	{`NSLDAP SHA-1`, regexp.MustCompile(`^\{NSLMD5\}[A-Za-z0-9+/=]{24,}`), 0},
	{`Lotus Notes 5`, regexp.MustCompile(`^\([a-f0-9]{32}\)`), 0},
	{`Lotus Notes 6+`, regexp.MustCompile(`^\([a-f0-9]{40}\)`), 0},
	{`Skype`, regexp.MustCompile(`^\{[a-f0-9]{32}\}$`), 34},
	{`Minecraft`, regexp.MustCompile(`^\$sha\$\w+\$[./A-Za-z0-9]+$`), 0},
	{`LastPass`, regexp.MustCompile(`^[a-f0-9]{32}:[a-f0-9]{32}:[a-f0-9]{32}$`), 98},
	{`Bitcoin (BIP38)`, regexp.MustCompile(`^6P[1-9A-HJ-NP-Za-km-z]{50}$`), 52},
	{`Ethereum (UTC)`, regexp.MustCompile(`^UTC--[0-9TZ-]+--[a-f0-9]{40}$`), 0},
	{`Keepass`, regexp.MustCompile(`^[A-Za-z0-9]{32,}`), 0},
	{`TrueCrypt`, regexp.MustCompile(`^[a-f0-9]{64}$`), 64},
	{`FileVault 2`, regexp.MustCompile(`^[a-f0-9]{128}$`), 128},
	{`BitLocker`, regexp.MustCompile(`^[a-f0-9]{32}-[a-f0-9]{32}-[a-f0-9]{32}-[a-f0-9]{32}-[a-f0-9]{32}$`), 0},
	{`LUKS`, regexp.MustCompile(`^[a-f0-9]{40,}`), 0},
	{`PKZIP`, regexp.MustCompile(`^[a-f0-9]{16}$`), 16},
	{`RAR3-hp`, regexp.MustCompile(`^\$RAR3\$\*[a-f0-9]+\*[a-f0-9]+$`), 0},
	{`RAR5`, regexp.MustCompile(`^\$rar5\$\d+\*[a-f0-9]+$`), 0},
	{`7-Zip`, regexp.MustCompile(`^\$7z\$\d+\*[a-f0-9]+$`), 0},
	{`PDF`, regexp.MustCompile(`^\$pdf\$\d+\*[a-f0-9]+\*[a-f0-9]+$`), 0},
	{`Android FDE (DEK)`, regexp.MustCompile(`^[a-f0-9]{64}$`), 64},
	{`Apple iWork`, regexp.MustCompile(`^[a-f0-9]{32}$`), 32},
	{`iTunes Backup`, regexp.MustCompile(`^[a-f0-9]{40}$`), 40},
	{`DPAPI`, regexp.MustCompile(`^\$DPAPImk\$\d+\$[a-f0-9]+$`), 0},
	{`DPAPI`, regexp.MustCompile(`^\$DPAPI\$\d+\$[a-f0-9]+$`), 0},
}

var jwtPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
var base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
var hexPattern = regexp.MustCompile(`^(0x)?[a-fA-F0-9]+$`)
var binPattern = regexp.MustCompile(`^[01]+$`)
var octalPattern = regexp.MustCompile(`^[0-7]+$`)
var morsePattern = regexp.MustCompile(`^[.\- /]+$`)

func (m *ArsenalModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	dbFindings := m.scanPayloadDB(ctx, target)
	findings = append(findings, dbFindings...)

	select {
	case <-ctx.Done():
		return findings, nil
	default:
	}

	hashFindings := m.scanHashes(ctx, target)
	findings = append(findings, hashFindings...)

	select {
	case <-ctx.Done():
		return findings, nil
	default:
	}

	encodeFindings := m.scanEncoded(ctx, target)
	findings = append(findings, encodeFindings...)

	select {
	case <-ctx.Done():
		return findings, nil
	default:
	}

	decodeFindings := m.scanDecode(ctx, target)
	findings = append(findings, decodeFindings...)

	select {
	case <-ctx.Done():
		return findings, nil
	default:
	}

	mutateFindings := m.scanMutate(ctx, target)
	findings = append(findings, mutateFindings...)

	return findings, nil
}

func (m *ArsenalModule) scanPayloadDB(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding
	base := target.URL
	parsed, err := url.Parse(base)
	if err != nil {
		return nil
	}
	baseURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)

	for _, path := range payloadDBPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		testURL := baseURL + path
		resp, err := m.client.Get(testURL)
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}

		body := strings.ToLower(resp.Body)
		payloadKeywords := []string{"payload", "fuzz", "wordlist", "password", "exploit", "xss", "sqli", "lfi", "injection", "shell"}
		matchedKeywords := []string{}
		for _, kw := range payloadKeywords {
			if strings.Contains(body, kw) {
				matchedKeywords = append(matchedKeywords, kw)
			}
		}

		if len(matchedKeywords) > 0 || strings.HasSuffix(path, ".txt") || strings.HasSuffix(path, ".json") {
			detail := fmt.Sprintf("Accessible payload DB at %s", testURL)
			if len(matchedKeywords) > 0 {
				detail = fmt.Sprintf("Accessible payload DB at %s containing keywords: %s", testURL, strings.Join(matchedKeywords, ", "))
			}
			findings = append(findings, m.makeFinding(
				"Payload Database Found - "+path,
				models.Medium, models.HighConfidence,
				testURL, "", path,
				detail,
				"A payload database or wordlist was found accessible at '%s'.",
				"Remove payload databases from production servers. Restrict access to internal tools only.",
				"CWE-312",
			))
		}
	}

	if len(findings) == 0 {
		return nil
	}
	return findings
}

func (m *ArsenalModule) scanHashes(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	resp, err := m.client.Get(target.URL)
	if err != nil {
		return nil
	}

	body := resp.Body
	lines := strings.Split(body, "\n")
	seen := make(map[string]bool)

	for _, line := range lines {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			continue
		}

		for _, hp := range hashPatterns {
			if hp.Pattern.MatchString(line) {
				if hp.Length > 0 && len(line) != hp.Length {
					continue
				}
				seen[line] = true

				partial := line
				if len(partial) > 40 {
					partial = partial[:40] + "..."
				}

				findings = append(findings, m.makeFinding(
					fmt.Sprintf("Hash Detected - %s", hp.Name),
					models.Info, models.HighConfidence,
					target.URL, "", partial,
					fmt.Sprintf("Hash format '%s' detected in response: %s", hp.Name, partial),
					"Hash value classified as '%s' was found in the response body.",
					"Review if these hashes are meant to be exposed. Use proper hashing algorithms with salts for stored credentials.",
					"CWE-327",
				))

				if strings.Contains(strings.ToLower(body), "hashcat") || strings.Contains(strings.ToLower(body), "john") || strings.Contains(strings.ToLower(body), "crack") {
					findings = append(findings, m.makeFinding(
						"Hash Cracking Attempt Detected",
						models.High, models.MediumConfidence,
						target.URL, "", "hashcat/john/crack reference",
						"References to hash cracking tools (hashcat, john, crack) found alongside hash values",
						"Hash cracking tools or references detected in response content with '%s' hashes.",
						"Remove hash cracking tools and references from production systems.",
						"CWE-312",
					))
					break
				}
				break
			}
		}
	}

	if len(findings) == 0 {
		return nil
	}
	return findings
}

func (m *ArsenalModule) scanEncoded(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	body := ""

	parsed, err := url.Parse(target.URL)
	if err == nil && parsed.RawQuery != "" {
		body += parsed.RawQuery + "\n"
	}
	if parsed != nil && parsed.Fragment != "" {
		body += parsed.Fragment + "\n"
	}

	resp, err := m.client.Get(target.URL)
	if err == nil {
		body += resp.Body
	}

	tokens := m.extractPotentialTokens(body)
	seen := make(map[string]bool)

	for _, token := range tokens {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if seen[token] {
			continue
		}
		seen[token] = true
		trimmed := strings.TrimSpace(token)

		if m.isBase64(trimmed) {
			decoded, decErr := base64.StdEncoding.DecodeString(trimmed)
			if decErr == nil && len(decoded) > 2 {
				findings = append(findings, m.makeFinding(
					"Base64 Encoded Data Found",
					models.Low, models.MediumConfidence,
					target.URL, "", trimmed,
					fmt.Sprintf("Base64 encoded data: %s -> %s", trimmed, string(decoded)),
					"Base64 encoded content was found at '%s'.",
					"Base64 is not encryption. Ensure sensitive data is not exposed in encoded form.",
					"CWE-312",
				))
			}
		}

		if strings.HasPrefix(trimmed, "url=") || strings.HasPrefix(trimmed, "%") {
			decoded, decErr := url.QueryUnescape(trimmed)
			if decErr == nil && decoded != trimmed {
				findings = append(findings, m.makeFinding(
					"URL Encoded Data Found",
					models.Info, models.LowConfidence,
					target.URL, "", trimmed,
					fmt.Sprintf("URL encoded: %s -> %s", trimmed, decoded),
					"URL-encoded content was detected at '%s'.",
					"Ensure URL encoding is not used to obfuscate malicious payloads.",
					"CWE-172",
				))
			}
		}

		if m.isHex(trimmed) {
			decoded, decErr := hex.DecodeString(strings.TrimPrefix(trimmed, "0x"))
			if decErr == nil && len(decoded) > 2 {
				if !m.isLikelyHash(trimmed) {
					findings = append(findings, m.makeFinding(
						"Hex Encoded Data Found",
						models.Low, models.LowConfidence,
						target.URL, "", trimmed,
						fmt.Sprintf("Hex encoded: %s -> %s", trimmed, string(decoded)),
						"Hex-encoded content was detected at '%s'.",
						"Hex encoding obfuscates but does not secure data.",
						"CWE-172",
					))
				}
			}
		}

		if binPattern.MatchString(trimmed) && len(trimmed) > 8 {
			findings = append(findings, m.makeFinding(
				"Binary Encoded Data Found",
				models.Info, models.LowConfidence,
				target.URL, "", trimmed,
				fmt.Sprintf("Binary data: %s", trimmed),
				"Binary-encoded content was detected at '%s'.",
				"Binary encoding may indicate obfuscated content.",
				"CWE-172",
			))
		}

		if octalPattern.MatchString(trimmed) && len(trimmed) > 6 {
			findings = append(findings, m.makeFinding(
				"Octal Encoded Data Found",
				models.Info, models.LowConfidence,
				target.URL, "", trimmed,
				fmt.Sprintf("Octal data: %s", trimmed),
				"Octal-encoded content was detected at '%s'.",
				"Octal encoding may indicate obfuscated content.",
				"CWE-172",
			))
		}

		if morsePattern.MatchString(trimmed) && strings.Contains(trimmed, ".") && strings.Contains(trimmed, "-") {
			findings = append(findings, m.makeFinding(
				"Morse Code Detected",
				models.Low, models.LowConfidence,
				target.URL, "", trimmed,
				fmt.Sprintf("Morse code pattern: %s", trimmed),
				"Morse code pattern detected in response at '%s'.",
				"Morse code may indicate data exfiltration or hidden content.",
				"CWE-172",
			))
		}

		if jwtPattern.MatchString(trimmed) {
			parts := strings.Split(trimmed, ".")
			if len(parts) == 3 {
				headerJSON, hErr := base64.RawURLEncoding.DecodeString(parts[0])
				payloadJSON, pErr := base64.RawURLEncoding.DecodeString(parts[1])
				if hErr == nil && pErr == nil {
					var hdr, pld map[string]interface{}
					if json.Unmarshal(headerJSON, &hdr) == nil && json.Unmarshal(payloadJSON, &pld) == nil {
						findings = append(findings, m.makeFinding(
							"JWT Token Detected",
							models.Medium, models.HighConfidence,
							target.URL, "", trimmed,
							fmt.Sprintf("JWT header: %s, payload: %s", string(headerJSON), string(payloadJSON)),
							"A JSON Web Token (JWT) was detected in the response at '%s'.",
							"Ensure JWT tokens are not exposed in responses. Use short expiration times and proper signing.",
							"CWE-312",
						))
					}
				}
			}
		}
	}

	if len(findings) == 0 {
		return nil
	}
	return findings
}

func (m *ArsenalModule) scanDecode(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	resp, err := m.client.Get(target.URL)
	if err != nil {
		return nil
	}

	body := resp.Body
	tokens := m.extractPotentialTokens(body)

	for _, token := range tokens {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		trimmed := strings.TrimSpace(token)
		if len(trimmed) < 4 {
			continue
		}

		autoDetected := m.autoDetectAndDecode(trimmed)
		if autoDetected != "" {
			findings = append(findings, m.makeFinding(
				"Auto-Decoded Content",
				models.Low, models.MediumConfidence,
				target.URL, "", trimmed,
				fmt.Sprintf("Auto-detected encoding and decoded: %s -> %s", trimmed, autoDetected),
				"Encoded content was automatically detected and decoded at '%s'.",
				"Encoded data may be used to hide malicious intent. Review decoded content.",
				"CWE-172",
			))
		}
	}

	if len(findings) == 0 {
		return nil
	}
	return findings
}

func (m *ArsenalModule) scanMutate(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	resp, err := m.client.Get(target.URL)
	if err != nil {
		return nil
	}

	body := strings.ToLower(resp.Body)

	mutationIndicators := []string{
		"ffuf", "wfuzz", "gobuster", "dirbuster", "burp intruder",
		"fuzzing", "fuzz dict", "payload mixer", "payload combin",
		"mutator", "mutation", "polyglot", "polyglot",
		"param miner", "paramspider", "x8", "arjun",
		"pattern generator", "pattern mutat", "template inject",
		"request bender", "request generator", "scanner",
		"gredis", "grendel", "pepper", "razzer",
	}

	matched := []string{}
	for _, ind := range mutationIndicators {
		if strings.Contains(body, ind) {
			matched = append(matched, ind)
		}
	}

	if len(matched) > 0 {
		findings = append(findings, m.makeFinding(
			"Payload Mutation Engine Detected",
			models.Medium, models.MediumConfidence,
			target.URL, "", strings.Join(matched, ", "),
			fmt.Sprintf("Payload mutation/fuzzing engine references found: %s", strings.Join(matched, ", ")),
			"References to payload mutation or fuzzing engines detected in '%s'.",
			"Remove fuzzing tools and payload generators from production systems.",
			"CWE-312",
		))
	}

	parsed, err := url.Parse(target.URL)
	if err == nil && parsed.RawQuery != "" {
		params, _ := url.ParseQuery(parsed.RawQuery)
		for key, vals := range params {
			for _, val := range vals {
				if strings.Contains(strings.ToLower(val), "FUZZ") ||
					strings.Contains(val, "§") ||
					strings.Contains(val, "{{") ||
					strings.Contains(val, "$$") {
					findings = append(findings, m.makeFinding(
						"Fuzz/Payload Placeholder Detected",
						models.Info, models.MediumConfidence,
						target.URL, key, val,
						fmt.Sprintf("Parameter '%s' contains fuzzing placeholder: %s", key, val),
						"A fuzzing or payload placeholder pattern was found in parameter '%s' at '%s'.",
						"Fuzzing placeholders in parameters may reflect automated scanning tools.",
						"CWE-312",
					))
					break
				}
			}
		}
	}

	if len(findings) == 0 {
		return nil
	}
	return findings
}

func (m *ArsenalModule) extractPotentialTokens(body string) []string {
	var tokens []string

	potential := strings.FieldsFunc(body, func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ',' || r == ';' || r == '|'
	})

	for _, p := range potential {
		p = strings.TrimSpace(p)
		if len(p) >= 4 && len(p) <= 4096 {
			tokens = append(tokens, p)
		}
	}
	return tokens
}

func (m *ArsenalModule) isBase64(s string) bool {
	if len(s) < 4 {
		return false
	}
	return base64Pattern.MatchString(s) && len(s)%4 == 0
}

func (m *ArsenalModule) isHex(s string) bool {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return hexPattern.MatchString(s) && len(s) >= 4
}

func (m *ArsenalModule) isLikelyHash(s string) bool {
	hashLengths := []int{16, 32, 40, 48, 56, 64, 96, 128}
	for _, l := range hashLengths {
		if len(s) == l && hexPattern.MatchString(s) {
			return true
		}
	}
	return strings.HasPrefix(s, "$")
}

func (m *ArsenalModule) autoDetectAndDecode(s string) string {
	if dec, err := base64.StdEncoding.DecodeString(s); err == nil {
		d := string(dec)
		if strings.Contains(d, " ") || strings.Contains(d, "/") || strings.Contains(d, ":") || strings.Contains(d, ".") {
			return d
		}
	}
	if dec, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		d := string(dec)
		if strings.Contains(d, " ") || strings.Contains(d, "/") || strings.Contains(d, ":") {
			return d
		}
	}
	if dec, err := url.QueryUnescape(s); err == nil && dec != s {
		if strings.Contains(dec, " ") || strings.Contains(dec, "/") || strings.Contains(dec, "=") {
			return dec
		}
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		if dec, err := hex.DecodeString(s[2:]); err == nil {
			d := string(dec)
			if strings.Contains(d, " ") || strings.Contains(d, "/") || strings.Contains(d, ":") {
				return d
			}
		}
	}
	if hexPattern.MatchString(s) && len(s)%2 == 0 && len(s) >= 8 {
		if dec, err := hex.DecodeString(s); err == nil {
			d := string(dec)
			if strings.Contains(d, " ") || strings.Contains(d, "/") || strings.Contains(d, ":") || strings.Contains(d, ".") {
				return d
			}
		}
	}

	return ""
}

func (m *ArsenalModule) makeFinding(title string, severity models.Severity, confidence models.Confidence, urlStr, param, payload, evidence, description, remediation, cwe string) *models.Finding {
	return &models.Finding{
		Title:       title,
		Severity:    severity,
		Confidence:  confidence,
		URL:         urlStr,
		Parameter:   param,
		Payload:     payload,
		Evidence:    evidence,
		Description: fmt.Sprintf(description, param),
		Remediation: remediation,
		CWEID:       cwe,
		ModuleID:    "arsenal",
	}
}

func init() {
	engine.GetRegistry().Register(&ArsenalModule{})
}
