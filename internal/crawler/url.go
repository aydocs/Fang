package crawler

import (
	"net/url"
	"strings"
)

func NormalizeURL(raw string, base string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}

	if base != "" && !u.IsAbs() {
		b, err := url.Parse(base)
		if err == nil {
			u = b.ResolveReference(u)
		}
	}

	if !u.IsAbs() {
		return raw
	}

	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""

	if u.Scheme == "http" && u.Port() == "80" {
		u.Host = strings.TrimSuffix(u.Host, ":80")
	}
	if u.Scheme == "https" && u.Port() == "443" {
		u.Host = strings.TrimSuffix(u.Host, ":443")
	}

	u.RawQuery = sortQuery(u.RawQuery)

	normalized := u.String()
	normalized = strings.TrimRight(normalized, "/")

	return normalized
}

func ResolveURL(href, base string) string {
	u, err := url.Parse(href)
	if err != nil {
		return href
	}

	if u.IsAbs() {
		return href
	}

	b, err := url.Parse(base)
	if err != nil {
		return href
	}

	return b.ResolveReference(u).String()
}

func IsSameDomain(url1, url2 string) bool {
	d1 := ExtractDomain(url1)
	d2 := ExtractDomain(url2)
	return d1 != "" && d1 == d2
}

func ExtractDomain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if !u.IsAbs() {
		return ""
	}
	return u.Hostname()
}

func IsValidURL(raw string) bool {
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "javascript:") ||
		strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "tel:") ||
		strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "blob:") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if !u.IsAbs() {
		return true
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

func sortQuery(query string) string {
	if query == "" {
		return ""
	}
	params := strings.Split(query, "&")
	sortStrings(params)
	return strings.Join(params, "&")
}

func sortStrings(s []string) {
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if s[i] > s[j] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}
