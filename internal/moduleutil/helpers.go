package moduleutil

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

func BuildURL(base, path string) string {
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
}

func HasMarker(body, marker string) bool {
	return strings.Contains(body, marker)
}

func ExtractParams(body string) []string {
	var params []string
	n := strings.Index(body, "?")
	if n == -1 {
		return params
	}
	queryStr := body[n+1:]
	end := strings.IndexAny(queryStr, " \"'<>\n\t")
	if end != -1 {
		queryStr = queryStr[:end]
	}
	for _, pair := range strings.Split(queryStr, "&") {
		if kv := strings.SplitN(pair, "=", 2); len(kv) == 2 && kv[0] != "" {
			params = append(params, kv[0])
		}
	}
	return params
}

func CheckReflection(client *fanghttp.Client, urlStr, param, payload string) bool {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	q := parsed.Query()
	q.Set(param, payload)
	parsed.RawQuery = q.Encode()
	resp, err := client.Get(parsed.String())
	if err != nil {
		return false
	}
	return strings.Contains(resp.Body, payload)
}

func CheckTimeDelay(client *fanghttp.Client, urlStr string, delay time.Duration) bool {
	start := time.Now()
	client.Get(urlStr)
	return time.Since(start) >= delay
}

func ExtractJSFiles(body, baseURL string) []string {
	var files []string
	patterns := []string{`src="`, `src='`, `href="`, `href='`}
	for _, pat := range patterns {
		idx := 0
		for {
			n := strings.Index(body[idx:], pat)
			if n == -1 {
				break
			}
			start := idx + n + len(pat)
			end := strings.IndexAny(body[start:], "\"'")
			if end == -1 {
				break
			}
			f := body[start : start+end]
			if strings.HasSuffix(f, ".js") || strings.HasSuffix(f, ".mjs") {
				files = append(files, NormalizeURL(baseURL, f))
			}
			idx = start + end
		}
	}
	return files
}

func ExtractForms(body string) []*models.Form {
	var forms []*models.Form
	idx := 0
	for {
		n := strings.Index(strings.ToLower(body[idx:]), "<form")
		if n == -1 {
			break
		}
		start := idx + n
		end := strings.Index(body[start:], "</form>")
		if end == -1 {
			break
		}
		formHTML := body[start : start+end+7]
		f := &models.Form{}
		if aIdx := strings.Index(strings.ToLower(formHTML), "action=\""); aIdx != -1 {
			aStart := aIdx + 8
			aEnd := strings.IndexAny(formHTML[aStart:], "\"'")
			if aEnd != -1 {
				f.Action = formHTML[aStart : aStart+aEnd]
			}
		}
		if mIdx := strings.Index(strings.ToLower(formHTML), "method=\""); mIdx != -1 {
			mStart := mIdx + 8
			mEnd := strings.IndexAny(formHTML[mStart:], "\"'")
			if mEnd != -1 {
				f.Method = strings.ToUpper(formHTML[mStart : mStart+mEnd])
			}
		}
		inputIdx := 0
		for {
			in := strings.Index(strings.ToLower(formHTML[inputIdx:]), "<input")
			if in == -1 {
				break
			}
			inStart := inputIdx + in
			inEnd := strings.IndexAny(formHTML[inStart:], ">")
			if inEnd == -1 {
				break
			}
			inputTag := formHTML[inStart : inStart+inEnd]
			input := &models.FormInput{}
			if nameIdx := strings.Index(strings.ToLower(inputTag), "name=\""); nameIdx != -1 {
				nStart := nameIdx + 6
				nEnd := strings.IndexAny(inputTag[nStart:], "\"'")
				if nEnd != -1 {
					input.Name = inputTag[nStart : nStart+nEnd]
				}
			}
			if tIdx := strings.Index(strings.ToLower(inputTag), "type=\""); tIdx != -1 {
				tStart := tIdx + 6
				tEnd := strings.IndexAny(inputTag[tStart:], "\"'")
				if tEnd != -1 {
					input.Type = inputTag[tStart : tStart+tEnd]
				}
			}
			f.Inputs = append(f.Inputs, input)
			inputIdx = inStart + inEnd
		}
		forms = append(forms, f)
		idx = start + end + 7
	}
	return forms
}

func UniqueID(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("FNG%s%s", prefix, "deadbeefdeadbeef")
	}
	return fmt.Sprintf("FNG%s%s", prefix, hex.EncodeToString(b))
}

func NormalizeURL(base, ref string) string {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	if strings.HasPrefix(ref, "//") {
		return "https:" + ref
	}
	if strings.HasPrefix(ref, "/") {
		parts := strings.SplitN(base, "/", 4)
		if len(parts) >= 3 {
			return parts[0] + "//" + parts[2] + ref
		}
	}
	lastSlash := strings.LastIndex(base, "/")
	if lastSlash > 8 {
		return base[:lastSlash+1] + ref
	}
	return base + "/" + ref
}

func Truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func ContainsAny(s string, patterns []string) bool {
	lower := strings.ToLower(s)
	for _, p := range patterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}
