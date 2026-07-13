package models

func CWEToOWASP(cweID string) string {
	switch cweID {
	case "CWE-20":
		return "A1:2021 - Input Validation"
	case "CWE-22":
		return "A1:2021 - Path Traversal"
	case "CWE-23":
		return "A1:2021 - Path Traversal"
	case "CWE-35":
		return "A1:2021 - Path Traversal"
	case "CWE-36":
		return "A1:2021 - Path Traversal"
	case "CWE-73":
		return "A1:2021 - Input Validation"
	case "CWE-74":
		return "A1:2021 - Injection"
	case "CWE-77":
		return "A1:2021 - Command Injection"
	case "CWE-78":
		return "A1:2021 - OS Command Injection"
	case "CWE-79":
		return "A3:2021 - Cross-Site Scripting"
	case "CWE-89":
		return "A1:2021 - SQL Injection"
	case "CWE-90":
		return "A1:2021 - LDAP Injection"
	case "CWE-91":
		return "A1:2021 - XPath Injection"
	case "CWE-93":
		return "A1:2021 - CRLF Injection"
	case "CWE-94":
		return "A1:2021 - Code Injection"
	case "CWE-95":
		return "A1:2021 - Code Injection"
	case "CWE-98":
		return "A1:2021 - Remote File Inclusion"
	case "CWE-113":
		return "A1:2021 - HTTP Response Splitting"
	case "CWE-119":
		return "A6:2021 - Buffer Overflow"
	case "CWE-120":
		return "A6:2021 - Buffer Overflow"
	case "CWE-134":
		return "A1:2021 - Format String Injection"
	case "CWE-200":
		return "A4:2021 - Information Disclosure"
	case "CWE-201":
		return "A4:2021 - Information Disclosure"
	case "CWE-203":
		return "A4:2021 - Information Disclosure"
	case "CWE-209":
		return "A4:2021 - Information Disclosure"
	case "CWE-250":
		return "A7:2021 - Privilege Escalation"
	case "CWE-269":
		return "A7:2021 - Privilege Escalation"
	case "CWE-285":
		return "A7:2021 - Improper Authorization"
	case "CWE-287":
		return "A7:2021 - Authentication Bypass"
	case "CWE-289":
		return "A7:2021 - Authentication Bypass"
	case "CWE-290":
		return "A7:2021 - Authentication Bypass"
	case "CWE-295":
		return "A6:2021 - Improper Certificate Validation"
	case "CWE-306":
		return "A7:2021 - Missing Authentication"
	case "CWE-307":
		return "A7:2021 - Brute Force"
	case "CWE-319":
		return "A2:2021 - Cleartext Transmission"
	case "CWE-326":
		return "A2:2021 - Weak Cryptographic Algorithm"
	case "CWE-327":
		return "A2:2021 - Weak Cryptographic Algorithm"
	case "CWE-328":
		return "A2:2021 - Weak Hash Algorithm"
	case "CWE-330":
		return "A2:2021 - Weak Randomness"
	case "CWE-345":
		return "A8:2021 - Insufficient Integrity Verification"
	case "CWE-346":
		return "A8:2021 - Origin Validation"
	case "CWE-352":
		return "A1:2021 - Cross-Site Request Forgery"
	case "CWE-362":
		return "A8:2021 - Race Condition (TOCTOU)"
	case "CWE-367":
		return "A8:2021 - Race Condition (TOCTOU)"
	case "CWE-377":
		return "A8:2021 - Insecure Temporary File"
	case "CWE-379":
		return "A8:2021 - Insecure Directory"
	case "CWE-400":
		return "A6:2021 - Resource Exhaustion (DoS)"
	case "CWE-401":
		return "A6:2021 - Memory Leak"
	case "CWE-404":
		return "A6:2021 - Resource Exhaustion"
	case "CWE-415":
		return "A6:2021 - Double Free"
	case "CWE-416":
		return "A6:2021 - Use After Free"
	case "CWE-434":
		return "A1:2021 - Unrestricted File Upload"
	case "CWE-441":
		return "A8:2021 - Unintended Proxy/Intermediary"
	case "CWE-444":
		return "A1:2021 - HTTP Request Smuggling"
	case "CWE-451":
		return "A8:2021 - Information Exposure"
	case "CWE-470":
		return "A1:2021 - Unsafe Reflection"
	case "CWE-476":
		return "A6:2021 - NULL Pointer Dereference"
	case "CWE-489":
		return "A5:2021 - Debug Backdoor"
	case "CWE-502":
		return "A1:2021 - Deserialization Attack"
	case "CWE-506":
		return "A8:2021 - Embedded Malicious Code"
	case "CWE-509":
		return "A8:2021 - Backdoor"
	case "CWE-521":
		return "A7:2021 - Weak Authentication"
	case "CWE-522":
		return "A7:2021 - Insufficiently Protected Credentials"
	case "CWE-523":
		return "A7:2021 - Insecure Credential Transport"
	case "CWE-525":
		return "A4:2021 - Browser Cache Weakness"
	case "CWE-532":
		return "A4:2021 - Information Leak via Log"
	case "CWE-538":
		return "A4:2021 - File/Directory Information Leak"
	case "CWE-540":
		return "A4:2021 - Source Code Information Leak"
	case "CWE-548":
		return "A4:2021 - Directory Listing"
	case "CWE-552":
		return "A4:2021 - Files/Directories Accessible"
	case "CWE-601":
		return "A1:2021 - Open Redirect"
	case "CWE-602":
		return "A1:2021 - Client-Side Enforcement"
	case "CWE-610":
		return "A8:2021 - Externally-Controlled Reference"
	case "CWE-611":
		return "A1:2021 - XML External Entity (XXE)"
	case "CWE-613":
		return "A7:2021 - Insufficient Session Expiration"
	case "CWE-614":
		return "A2:2021 - Sensitive Cookie in Clear Text"
	case "CWE-620":
		return "A7:2021 - Unverified Password Change"
	case "CWE-639":
		return "A1:2021 - Insecure Direct Object Reference"
	case "CWE-640":
		return "A7:2021 - Weak Password Recovery"
	case "CWE-641":
		return "A1:2021 - Information Leak"
	case "CWE-643":
		return "A1:2021 - XPath Injection"
	case "CWE-652":
		return "A1:2021 - XQuery Injection"
	case "CWE-693":
		return "A6:2021 - Protection Mechanism Failure"
	case "CWE-697":
		return "A6:2021 - Insufficient Validation"
	case "CWE-703":
		return "A6:2021 - Improper Error Handling"
	case "CWE-706":
		return "A6:2021 - Improper Name Resolution"
	case "CWE-732":
		return "A5:2021 - Incorrect Permission Assignment"
	case "CWE-749":
		return "A5:2021 - Exposed Dangerous Method"
	case "CWE-754":
		return "A6:2021 - Improper Exception Handling"
	case "CWE-759":
		return "A2:2021 - Use of One-Way Hash"
	case "CWE-760":
		return "A2:2021 - Predictable Salt"
	case "CWE-770":
		return "A6:2021 - Resource Allocation DoS"
	case "CWE-776":
		return "A6:2021 - XML Entity Expansion (Billion Laughs)"
	case "CWE-784":
		return "A6:2021 - Reliance on Cookies Without Validation"
	case "CWE-798":
		return "A5:2021 - Hardcoded Credentials"
	case "CWE-807":
		return "A7:2021 - Reliance on Untrusted Inputs"
	case "CWE-829":
		return "A8:2021 - Inclusion from Untrusted Source"
	case "CWE-830":
		return "A8:2021 - Inclusion of Web Functionality"
	case "CWE-838":
		return "A1:2021 - Output Encoding"
	case "CWE-840":
		return "A1:2021 - Business Logic Flaw"
	case "CWE-862":
		return "A7:2021 - Missing Authorization"
	case "CWE-863":
		return "A7:2021 - Incorrect Authorization"
	case "CWE-864":
		return "A7:2021 - Authorization Bypass"
	case "CWE-865":
		return "A1:2021 - Logic Error"
	case "CWE-916":
		return "A2:2021 - Weak Password Hash"
	case "CWE-917":
		return "A1:2021 - Expression Language Injection"
	case "CWE-918":
		return "A1:2021 - Server-Side Request Forgery"
	case "CWE-940":
		return "A1:2021 - Injection"
	case "CWE-941":
		return "A1:2021 - Composite Injection"
	case "CWE-943":
		return "A1:2021 - NoSQL Injection"
	case "CWE-1021":
		return "A8:2021 - Improper Restriction of Rendered UI"
	case "CWE-1104":
		return "A6:2021 - Use of Unmaintained Third-Party"
	case "CWE-1321":
		return "A1:2021 - Prototype Pollution"
	case "CWE-1333":
		return "A6:2021 - Inefficient Regular Expression"
	case "CWE-1336":
		return "A1:2021 - SSTI / Expression Injection"
	default:
		return "A6:2021 - Security Misconfiguration"
	}
}

func CWEToCVSS(cweID string) float64 {
	switch cweID {
	case "CWE-20":
		return 6.1
	case "CWE-22":
		return 7.5
	case "CWE-23":
		return 7.5
	case "CWE-35":
		return 7.5
	case "CWE-36":
		return 5.3
	case "CWE-73":
		return 5.3
	case "CWE-74":
		return 8.6
	case "CWE-77":
		return 9.8
	case "CWE-78":
		return 9.8
	case "CWE-79":
		return 6.1
	case "CWE-89":
		return 9.8
	case "CWE-90":
		return 8.6
	case "CWE-91":
		return 8.6
	case "CWE-93":
		return 6.1
	case "CWE-94":
		return 9.8
	case "CWE-95":
		return 9.8
	case "CWE-98":
		return 8.6
	case "CWE-113":
		return 6.5
	case "CWE-119":
		return 9.8
	case "CWE-120":
		return 9.8
	case "CWE-134":
		return 8.6
	case "CWE-200":
		return 5.3
	case "CWE-201":
		return 5.3
	case "CWE-203":
		return 3.7
	case "CWE-209":
		return 5.3
	case "CWE-250":
		return 8.8
	case "CWE-269":
		return 8.8
	case "CWE-285":
		return 8.1
	case "CWE-287":
		return 9.8
	case "CWE-289":
		return 9.8
	case "CWE-290":
		return 7.5
	case "CWE-295":
		return 7.4
	case "CWE-306":
		return 8.6
	case "CWE-307":
		return 5.3
	case "CWE-319":
		return 5.9
	case "CWE-326":
		return 7.5
	case "CWE-327":
		return 7.5
	case "CWE-328":
		return 5.9
	case "CWE-330":
		return 7.5
	case "CWE-345":
		return 5.3
	case "CWE-346":
		return 6.1
	case "CWE-352":
		return 8.8
	case "CWE-362":
		return 7.4
	case "CWE-367":
		return 7.4
	case "CWE-377":
		return 3.3
	case "CWE-379":
		return 5.5
	case "CWE-400":
		return 7.5
	case "CWE-401":
		return 5.9
	case "CWE-404":
		return 5.9
	case "CWE-415":
		return 9.8
	case "CWE-416":
		return 9.8
	case "CWE-434":
		return 8.1
	case "CWE-441":
		return 6.5
	case "CWE-444":
		return 8.6
	case "CWE-451":
		return 5.3
	case "CWE-470":
		return 8.6
	case "CWE-476":
		return 7.5
	case "CWE-489":
		return 9.8
	case "CWE-502":
		return 9.8
	case "CWE-506":
		return 9.8
	case "CWE-509":
		return 9.8
	case "CWE-521":
		return 7.5
	case "CWE-522":
		return 7.5
	case "CWE-523":
		return 5.9
	case "CWE-525":
		return 3.7
	case "CWE-532":
		return 5.5
	case "CWE-538":
		return 5.3
	case "CWE-540":
		return 5.3
	case "CWE-548":
		return 5.3
	case "CWE-552":
		return 7.5
	case "CWE-601":
		return 6.1
	case "CWE-602":
		return 7.4
	case "CWE-610":
		return 6.1
	case "CWE-611":
		return 9.8
	case "CWE-613":
		return 7.5
	case "CWE-614":
		return 5.9
	case "CWE-620":
		return 7.5
	case "CWE-639":
		return 7.5
	case "CWE-640":
		return 5.3
	case "CWE-641":
		return 3.7
	case "CWE-643":
		return 8.6
	case "CWE-652":
		return 8.6
	case "CWE-693":
		return 7.5
	case "CWE-697":
		return 5.3
	case "CWE-703":
		return 5.3
	case "CWE-706":
		return 5.3
	case "CWE-732":
		return 8.1
	case "CWE-749":
		return 8.1
	case "CWE-754":
		return 5.3
	case "CWE-759":
		return 5.9
	case "CWE-760":
		return 5.9
	case "CWE-770":
		return 7.5
	case "CWE-776":
		return 7.5
	case "CWE-784":
		return 5.3
	case "CWE-798":
		return 9.8
	case "CWE-807":
		return 5.3
	case "CWE-829":
		return 8.8
	case "CWE-830":
		return 5.3
	case "CWE-838":
		return 5.3
	case "CWE-840":
		return 6.5
	case "CWE-862":
		return 8.1
	case "CWE-863":
		return 8.1
	case "CWE-864":
		return 8.1
	case "CWE-865":
		return 6.5
	case "CWE-916":
		return 7.5
	case "CWE-917":
		return 9.8
	case "CWE-918":
		return 9.8
	case "CWE-940":
		return 8.6
	case "CWE-941":
		return 8.6
	case "CWE-943":
		return 8.6
	case "CWE-1021":
		return 4.3
	case "CWE-1104":
		return 7.5
	case "CWE-1321":
		return 9.8
	case "CWE-1333":
		return 7.5
	case "CWE-1336":
		return 9.8
	default:
		return 5.0
	}
}

func EnrichFinding(f *Finding) {
	if f.OWASPCategory == "" {
		f.OWASPCategory = CWEToOWASP(f.CWEID)
	}
	if f.CVSS == nil {
		v := CWEToCVSS(f.CWEID)
		f.CVSS = &v
	}
}
