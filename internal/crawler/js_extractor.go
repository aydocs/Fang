package crawler

import (
	"regexp"
	"strings"
)

var (
	fetchPattern  = regexp.MustCompile(`fetch\s*\(\s*['"]([^'"]+)['"]`)
	axiosPattern  = regexp.MustCompile(`axios\.(get|post|put|delete|patch|head|options)\s*\(\s*['"]([^'"]+)['"]`)
	jqueryPattern = regexp.MustCompile(`\$\s*\.\s*(get|post|ajax)\s*\(\s*['"]([^'"]+)['"]`)
	xhrPattern    = regexp.MustCompile(`XMLHttpRequest|new\s+XMLHttpRequest`)
	wsPattern     = regexp.MustCompile(`new\s+WebSocket\s*\(\s*['"]([^'"]+)['"]`)
	apiPattern    = regexp.MustCompile(`['"](/api/[^'"]+)['"]|['"](/v[0-9]+/[^'"]+)['"]|['"](/rest/[^'"]+)['"]`)
	swaggerPath   = regexp.MustCompile(`/swagger|/api/docs|/openapi\.json|/swagger\.json`)
	graphqlPath   = regexp.MustCompile(`/graphql|/graphiql|/playground|/altair`)
)

func ExtractJSEndpoints(body string) []string {
	var endpoints []string
	seen := make(map[string]bool)

	matches := fetchPattern.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if len(m) > 1 && !seen[m[1]] {
			seen[m[1]] = true
			endpoints = append(endpoints, m[1])
		}
	}

	matches = axiosPattern.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if len(m) > 2 && !seen[m[2]] {
			seen[m[2]] = true
			endpoints = append(endpoints, m[2])
		}
	}

	matches = jqueryPattern.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if len(m) > 2 && !seen[m[2]] {
			seen[m[2]] = true
			endpoints = append(endpoints, m[2])
		}
	}

	if xhrPattern.MatchString(body) {
		endpoints = append(endpoints, "XMLHttpRequest")
	}

	matches = wsPattern.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if len(m) > 1 && !seen[m[1]] {
			seen[m[1]] = true
			endpoints = append(endpoints, m[1])
		}
	}

	matches = apiPattern.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		for _, group := range m[1:] {
			if group != "" && !seen[group] {
				seen[group] = true
				endpoints = append(endpoints, group)
			}
		}
	}

	return endpoints
}

func ExtractAPIPatterns(body string) []string {
	var patterns []string
	seen := make(map[string]bool)

	bodyLower := strings.ToLower(body)

	if swaggerPath.MatchString(bodyLower) {
		patterns = append(patterns, "swagger/openapi")
	}

	if graphqlPath.MatchString(bodyLower) {
		patterns = append(patterns, "graphql")
	}

	matches := apiPattern.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		for _, group := range m[1:] {
			if group != "" && !seen[group] {
				seen[group] = true
				patterns = append(patterns, group)
			}
		}
	}

	apiKeywords := []string{"/api/", "/rest/", "/v1/", "/v2/", "/v3/", "/graphql",
		"/swagger", "/openapi", "/endpoint", "/service"}

	for _, kw := range apiKeywords {
		if strings.Contains(bodyLower, kw) {
			if !seen[kw] {
				seen[kw] = true
				patterns = append(patterns, kw)
			}
		}
	}

	return patterns
}
