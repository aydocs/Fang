package templateengine

import (
	"regexp"
	"strings"

	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/templates"
)

type Engine struct {
	Client    *fanghttp.Client
	Templates []*templates.Template
}

func NewEngine(client *fanghttp.Client) *Engine {
	return &Engine{
		Client:    client,
		Templates: make([]*templates.Template, 0),
	}
}

func (e *Engine) LoadDirectory(dir string) error {
	tmpls, err := templates.LoadTemplates(dir)
	if err != nil {
		return err
	}
	e.Templates = append(e.Templates, tmpls...)
	return nil
}

func (e *Engine) Execute(target string) []templates.MatchResult {
	var results []templates.MatchResult

	for _, tmpl := range e.Templates {
		for _, req := range tmpl.Requests {
			for _, path := range req.Path {
				url := strings.ReplaceAll(path, "{{BaseURL}}", target)
				url = strings.ReplaceAll(url, "{{interactsh-url}}", "oob.fang.example")
				url = strings.ReplaceAll(url, "{{Host}}", strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://"))

				method := req.Method
				if method == "" {
					method = "GET"
				}

				httpResp, err := e.Client.DoRaw(method, url, req.Headers, req.Body)
				if err != nil {
					continue
				}

				for _, matcher := range req.Matchers {
					matched := matchResponse(matcher, httpResp)
					if matched {
						extracted := make(map[string]string)
						for _, ext := range req.Extractors {
							vals := extractData(ext, httpResp)
							if ext.Name != "" && len(vals) > 0 {
								extracted[ext.Name] = strings.Join(vals, ", ")
							}
						}

						results = append(results, templates.MatchResult{
							TemplateID:   tmpl.ID,
							TemplateName: tmpl.Info.Name,
							Severity:     tmpl.Info.Severity,
							Matched:      true,
							URL:          url,
							MatcherName:  matcher.Type,
							Extracted:    extracted,
						})
					}
				}
			}
		}

		for _, raw := range tmpl.Raw {
			for _, rawStr := range raw.Raw {
				rawStr = strings.ReplaceAll(rawStr, "{{BaseURL}}", target)
				rawStr = strings.ReplaceAll(rawStr, "{{interactsh-url}}", "oob.fang.example")
				rawStr = strings.ReplaceAll(rawStr, "{{Host}}", strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://"))

				parts := strings.SplitN(rawStr, "\n", 2)
				if len(parts) < 1 {
					continue
				}

				requestLine := strings.TrimSpace(parts[0])
				reqParts := strings.SplitN(requestLine, " ", 3)
				if len(reqParts) < 2 {
					continue
				}

				method := reqParts[0]
				rawPath := reqParts[1]
				if !strings.HasPrefix(rawPath, "http") {
					rawPath = target + rawPath
				}

				var headers map[string]string
				var body string
				if len(parts) > 1 {
					rest := parts[1]
					sections := strings.SplitN(rest, "\n\n", 2)
					headerLines := strings.Split(sections[0], "\n")
					headers = make(map[string]string)
					for _, h := range headerLines {
						h = strings.TrimSpace(h)
						if h == "" {
							continue
						}
						kv := strings.SplitN(h, ":", 2)
						if len(kv) == 2 {
							headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
						}
					}
					if len(sections) > 1 {
						body = strings.TrimSpace(sections[1])
					}
				}

				httpResp, err := e.Client.DoRaw(method, rawPath, headers, body)
				if err != nil {
					continue
				}

				for _, matcher := range raw.Matchers {
					matched := matchResponse(matcher, httpResp)
					if matched {
						results = append(results, templates.MatchResult{
							TemplateID:   tmpl.ID,
							TemplateName: tmpl.Info.Name,
							Severity:     tmpl.Info.Severity,
							Matched:      true,
							URL:          rawPath,
							MatcherName:  matcher.Type,
						})
					}
				}
			}
		}
	}

	if results == nil {
		return make([]templates.MatchResult, 0)
	}
	return results
}

func matchResponse(m templates.Matcher, resp *fanghttp.Response) bool {
	part := strings.ToLower(m.Part)
	if part == "" {
		part = "body"
	}

	var data string
	switch part {
	case "header":
		data = ""
		for k, v := range resp.Headers {
			data += k + ": " + strings.Join(v, ", ") + "\n"
		}
	case "all":
		data = resp.Body
		for k, v := range resp.Headers {
			data += "\n" + k + ": " + strings.Join(v, ", ")
		}
	default:
		data = resp.Body
	}

	switch m.Type {
	case "word":
		if len(m.Words) == 0 {
			return false
		}
		isOr := strings.ToLower(m.Condition) == "or"
		for _, word := range m.Words {
			found := strings.Contains(data, word)
			if isOr && found {
				return true
			}
			if !isOr && !found {
				return false
			}
		}
		return !isOr

	case "regex":
		if len(m.Regex) == 0 {
			return false
		}
		isOr := strings.ToLower(m.Condition) == "or"
		for _, pattern := range m.Regex {
			matched, err := regexp.MatchString(pattern, data)
			if err != nil {
				continue
			}
			if isOr && matched {
				return true
			}
			if !isOr && !matched {
				return false
			}
		}
		return !isOr

	case "status":
		if len(m.Status) == 0 {
			return false
		}
		for _, s := range m.Status {
			if resp.StatusCode == s {
				return true
			}
		}
		return false

	case "size":
		if len(m.Size) == 0 {
			return false
		}
		bodyLen := len(resp.Body)
		for _, s := range m.Size {
			if bodyLen == s {
				return true
			}
		}
		return false
	}

	return false
}

func extractData(e templates.Extractor, resp *fanghttp.Response) []string {
	var results []string

	switch e.Type {
	case "regex":
		for _, pattern := range e.Regex {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			matches := re.FindAllString(resp.Body, -1)
			results = append(results, matches...)
		}
	case "json":
		for _, jp := range e.JSON {
			val := extractJSONPath(resp.Body, jp)
			if val != "" {
				results = append(results, val)
			}
		}
	}

	return results
}

func extractJSONPath(body, path string) string {
	path = strings.TrimPrefix(path, "$.")
	keys := strings.Split(path, ".")
	current := body
	for _, key := range keys {
		pattern := `"` + regexp.QuoteMeta(key) + `"\s*:\s*"`
		re := regexp.MustCompile(pattern)
		loc := re.FindStringIndex(current)
		if loc == nil {
			pattern = `"` + regexp.QuoteMeta(key) + `"\s*:\s*(\d+)`
			re = regexp.MustCompile(pattern)
			match := re.FindStringSubmatch(current)
			if len(match) > 1 {
				return match[1]
			}
			return ""
		}
		start := loc[1]
		end := strings.IndexByte(current[start:], '"')
		if end < 0 {
			return ""
		}
		current = current[start : start+end]
	}
	return current
}
