package crawler

import (
	"strings"
)

type RobotsParser struct {
	sitemaps []string
	disallow []string
	allow    []string
}

func ParseRobots(body string) *RobotsParser {
	rp := &RobotsParser{}
	currentAgent := ""

	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			continue
		}

		field := strings.TrimSpace(line[:colonIdx])
		value := strings.TrimSpace(line[colonIdx+1:])

		switch strings.ToLower(field) {
		case "user-agent":
			currentAgent = strings.ToLower(value)
		case "disallow":
			if currentAgent == "*" || currentAgent == "" {
				value = strings.TrimSpace(value)
				if value != "" {
					rp.disallow = append(rp.disallow, value)
				}
			}
		case "allow":
			if currentAgent == "*" || currentAgent == "" {
				value = strings.TrimSpace(value)
				if value != "" {
					rp.allow = append(rp.allow, value)
				}
			}
		case "sitemap":
			rp.sitemaps = append(rp.sitemaps, value)
		}
	}

	return rp
}

func (r *RobotsParser) IsAllowed(path string) bool {
	if len(r.disallow) == 0 && len(r.allow) == 0 {
		return true
	}

	u := extractPath(path)

	for _, a := range r.allow {
		if a == "/" || strings.HasPrefix(u, a) {
			return true
		}
	}

	for _, d := range r.disallow {
		if d == "/" {
			return len(r.allow) > 0
		}
		if strings.HasPrefix(u, d) {
			return false
		}
	}

	return true
}

func (r *RobotsParser) Sitemaps() []string {
	return r.sitemaps
}

func extractPath(rawURL string) string {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return rawURL
	}

	u := rawURL
	slashIdx := strings.Index(u[8:], "/")
	if slashIdx == -1 {
		return "/"
	}
	return u[8+slashIdx:]
}
