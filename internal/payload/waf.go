package payload

import (
	"fmt"
	"net/http"
	"strings"
	"unicode"
)

type WAFBypass struct {
	name     string
	patterns []string
	evasions []string
}

var wafProfiles = map[string]*WAFBypass{
	"cloudflare": {
		name: "Cloudflare",
		patterns: []string{
			"__cfduid",
			"cf-ray",
			"Cf-Cache-Status",
			"cloudflare",
			"CloudFlare",
		},
		evasions: []string{
			"comment_injection",
			"unicode_escape",
			"scientific_notation",
			"overlong_utf8",
			"mixed_case",
			"wildcard_sql",
		},
	},
	"akamai": {
		name: "Akamai",
		patterns: []string{
			"akamai",
			"akamaighost",
			"AkamaiGHost",
			"X-Akamai-Request-ID",
		},
		evasions: []string{
			"case_permutation",
			"param_pollution",
			"null_byte",
			"content_type_variation",
		},
	},
	"aws_waf": {
		name: "AWS WAF",
		patterns: []string{
			"x-amz-request-id",
			"x-amz-id-2",
			"aws",
			"awselb",
		},
		evasions: []string{
			"inline_sql_comment",
			"concat_function",
			"char_function",
			"alt_comparison",
			"boolean_blind",
		},
	},
	"modsec": {
		name: "ModSecurity",
		patterns: []string{
			"ModSecurity",
			"mod_security",
			"NOZONE",
			"Apache/.*mod_security",
		},
		evasions: []string{
			"chunked_encoding",
			"multipart_boundary",
			"param_pollution",
			"null_byte_variation",
			"content_type_manipulation",
			"path_normalization",
		},
	},
	"f5_bigip": {
		name: "F5 BIG-IP",
		patterns: []string{
			"BigIP",
			"BIG-IP",
			"X-Content-Type-Options",
			"X-F5",
		},
		evasions: []string{
			"path_semicolon",
			"double_url_encode",
			"dotdot_semicolon",
			"range_request",
			"method_override",
		},
	},
}

func GetBypassStrategy(waf string) []string {
	waf = strings.ToLower(waf)
	for name, profile := range wafProfiles {
		if strings.Contains(strings.ToLower(name), waf) || strings.Contains(waf, strings.ToLower(name)) {
			return profile.evasions
		}
	}
	if bp, ok := wafProfiles[waf]; ok {
		return bp.evasions
	}
	return nil
}

func DetectWAF(resp *http.Response) string {
	if resp == nil || resp.Header == nil {
		return ""
	}

	for name, profile := range wafProfiles {
		for _, pattern := range profile.patterns {
			lowerPattern := strings.ToLower(pattern)
			for key, values := range resp.Header {
				if strings.Contains(strings.ToLower(key), lowerPattern) {
					return name
				}
				for _, v := range values {
					if strings.Contains(strings.ToLower(v), lowerPattern) {
						return name
					}
				}
			}
		}
	}

	return ""
}

func ApplyEvasiveEncoding(input string, evasion string) string {
	switch evasion {
	case "comment_injection":
		chars := strings.Split(input, "")
		return strings.Join(chars, "<!-- -->")
	case "unicode_escape":
		var result strings.Builder
		for _, r := range input {
			result.WriteString(fmt.Sprintf("\\u%04X", r))
		}
		return result.String()
	case "mixed_case", "case_permutation":
		var result strings.Builder
		for i, r := range input {
			if i%2 == 0 {
				result.WriteRune(unicode.ToUpper(r))
			} else {
				result.WriteRune(unicode.ToLower(r))
			}
		}
		return result.String()
	case "inline_sql_comment":
		return strings.ReplaceAll(input, " ", "/**/")
	case "double_url_encode":
		enc := &URLEncoder{}
		first := enc.Encode(input)
		return enc.Encode(first)
	case "null_byte":
		return input + "\x00"
	case "null_byte_variation":
		return input + "%00"
	case "dotdot_semicolon":
		return strings.ReplaceAll(input, "../", "..;/")
	case "path_semicolon":
		if strings.Contains(input, "/") {
			parts := strings.SplitN(input, "/", 2)
			if len(parts) == 2 {
				return parts[0] + "/;/" + parts[1]
			}
		}
		return input
	case "param_pollution":
		return input + "&" + input
	case "overlong_utf8":
		var result strings.Builder
		for _, r := range input {
			if r < 128 {
				result.Write([]byte{0xC0 | byte(r>>6), 0x80 | byte(r&0x3F)})
			} else {
				result.WriteRune(r)
			}
		}
		return result.String()
	case "scientific_notation":
		if len(input) > 0 && input[0] >= '0' && input[0] <= '9' {
			return input
		}
		return input
	case "wildcard_sql":
		return strings.ReplaceAll(input, " ", "/**/")
	case "concat_function":
		if strings.Contains(strings.ToUpper(input), "SELECT") || strings.Contains(strings.ToUpper(input), "UNION") {
			return input
		}
		return input
	case "char_function":
		return input
	case "alt_comparison":
		return strings.NewReplacer("=", "<>", "!=", "<>", "LIKE", "SIMILAR TO").Replace(input)
	case "boolean_blind":
		return input
	case "chunked_encoding":
		return input
	case "multipart_boundary":
		return input
	case "content_type_manipulation":
		return input
	case "content_type_variation":
		return input
	case "path_normalization":
		return strings.ReplaceAll(input, "//", "/")
	case "range_request":
		return input
	case "method_override":
		return input
	default:
		return input
	}
}
