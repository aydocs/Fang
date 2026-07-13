package crawler

import (
	"net/url"
	"regexp"
	"strings"
)

type Filter struct {
	includePatterns []*regexp.Regexp
	excludePatterns []*regexp.Regexp
	fileExtensions  map[string]bool
}

var defaultExcludedExtensions = map[string]bool{
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
	".svg": true, ".ico": true, ".css": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".mp4": true, ".mp3": true, ".avi": true, ".mov": true,
	".pdf": true, ".zip": true, ".tar": true, ".gz": true,
}

func NewFilter() *Filter {
	exts := make(map[string]bool)
	for k, v := range defaultExcludedExtensions {
		exts[k] = v
	}
	return &Filter{
		fileExtensions: exts,
	}
}

func (f *Filter) AddIncludePattern(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	f.includePatterns = append(f.includePatterns, re)
	return nil
}

func (f *Filter) AddExcludePattern(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	f.excludePatterns = append(f.excludePatterns, re)
	return nil
}

func (f *Filter) ShouldCrawl(raw string) bool {
	if !IsValidURL(raw) {
		return false
	}

	if f.IsStaticFile(raw) {
		return false
	}

	if len(f.includePatterns) > 0 {
		matched := false
		for _, re := range f.includePatterns {
			if re.MatchString(raw) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	for _, re := range f.excludePatterns {
		if re.MatchString(raw) {
			return false
		}
	}

	return true
}

func (f *Filter) IsStaticFile(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	ext := strings.ToLower(extensionFromPath(u.Path))
	return f.fileExtensions[ext]
}

func extensionFromPath(path string) string {
	idx := strings.LastIndex(path, ".")
	if idx == -1 {
		return ""
	}
	rest := path[idx:]
	if qIdx := strings.Index(rest, "?"); qIdx != -1 {
		rest = rest[:qIdx]
	}
	return rest
}
