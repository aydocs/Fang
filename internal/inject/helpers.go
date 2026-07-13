package inject

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/aydocs/fang/pkg/models"
)

var CandidateParams = []string{
	"id", "user", "search", "q", "page", "cat", "item", "product",
	"article", "news", "sort", "order", "filter", "type", "name",
	"url", "redirect", "return", "next", "file", "path", "host",
	"to", "site", "image", "img", "lang", "email", "token",
}

func TargetParams(target *models.Target) []string {
	if target == nil {
		return CandidateParams
	}
	parsed, err := url.Parse(target.URL)
	if err != nil {
		return CandidateParams
	}
	q := parsed.Query()
	if len(q) > 0 {
		names := make([]string, 0, len(q))
		for k := range q {
			names = append(names, k)
		}
		return names
	}
	return CandidateParams
}

func BuildTestURL(rawURL, param, value string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := parsed.Query()
	q.Set(param, value)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func TrimParamValue(v string, max int) string {
	v = strings.ReplaceAll(v, "\r", "")
	v = strings.ReplaceAll(v, "\n", "")
	if len(v) <= max {
		return v
	}
	return fmt.Sprintf("%s...(%d chars)", v[:max], len(v))
}
