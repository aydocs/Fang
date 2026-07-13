package crawler

import (
	"strings"

	"golang.org/x/net/html"

	"github.com/aydocs/fang/pkg/models"
)

func ParseLinks(body, baseURL string) []string {
	var links []string
	seen := make(map[string]bool)

	z := html.NewTokenizer(strings.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}

		name, hasAttr := z.TagName()
		tag := strings.ToLower(string(name))

		if tag == "a" || tag == "link" || tag == "img" || tag == "script" || tag == "iframe" {
			attrName := "href"
			if tag == "img" || tag == "script" || tag == "iframe" {
				attrName = "src"
			}
			if tag == "link" {
				attrName = "href"
			}

			var val string
			for hasAttr {
				var key, v []byte
				key, v, hasAttr = z.TagAttr()
				if strings.ToLower(string(key)) == attrName {
					val = string(v)
				}
			}

			if val == "" {
				continue
			}

			resolved := ResolveURL(val, baseURL)
			normalized := NormalizeURL(resolved, "")

			if normalized != "" && !seen[normalized] {
				seen[normalized] = true
				links = append(links, normalized)
			}
		}
	}

	return links
}

func ParseForms(body string) []*models.Form {
	var forms []*models.Form

	z := html.NewTokenizer(strings.NewReader(body))
	var currentForm *models.Form
	inForm := false

	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}

		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			tag := strings.ToLower(string(name))

			switch tag {
			case "form":
				form := &models.Form{
					Method: "GET",
					Action: "",
				}
				for hasAttr {
					var key, val []byte
					key, val, hasAttr = z.TagAttr()
					switch strings.ToLower(string(key)) {
					case "action":
						form.Action = string(val)
					case "method":
						form.Method = strings.ToUpper(string(val))
					}
				}
				currentForm = form
				inForm = true

			case "input":
				input := &models.FormInput{}
				var inputType string
				for hasAttr {
					var key, val []byte
					key, val, hasAttr = z.TagAttr()
					switch strings.ToLower(string(key)) {
					case "type":
						inputType = strings.ToLower(string(val))
						input.Type = inputType
					case "name":
						input.Name = string(val)
					case "value":
						input.Value = string(val)
					case "required":
						input.Required = true
					}
				}
				if input.Name != "" || inputType != "" {
					if inForm && currentForm != nil {
						currentForm.Inputs = append(currentForm.Inputs, input)
					}
				}

			case "textarea":
				input := &models.FormInput{Type: "textarea"}
				for hasAttr {
					var key, val []byte
					key, val, hasAttr = z.TagAttr()
					switch strings.ToLower(string(key)) {
					case "name":
						input.Name = string(val)
					case "required":
						input.Required = true
					}
				}
				if inForm && currentForm != nil {
					currentForm.Inputs = append(currentForm.Inputs, input)
				}

			case "select":
				input := &models.FormInput{Type: "select"}
				for hasAttr {
					var key, val []byte
					key, val, hasAttr = z.TagAttr()
					switch strings.ToLower(string(key)) {
					case "name":
						input.Name = string(val)
					case "required":
						input.Required = true
					}
				}
				if inForm && currentForm != nil {
					currentForm.Inputs = append(currentForm.Inputs, input)
				}

			case "button":
				input := &models.FormInput{Type: "button"}
				for hasAttr {
					var key, val []byte
					key, val, hasAttr = z.TagAttr()
					switch strings.ToLower(string(key)) {
					case "name":
						input.Name = string(val)
					case "type":
						input.Type = strings.ToLower(string(val))
					}
				}
				if inForm && currentForm != nil {
					currentForm.Inputs = append(currentForm.Inputs, input)
				}
			}

		case html.EndTagToken:
			nameBytes, _ := z.TagName()
			name := strings.ToLower(string(nameBytes))
			if name == "form" && inForm && currentForm != nil {
				forms = append(forms, currentForm)
				currentForm = nil
				inForm = false
			}
		}
	}

	return forms
}

func ParseScripts(body string) []string {
	var scripts []string
	seen := make(map[string]bool)

	z := html.NewTokenizer(strings.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}

		name, hasAttr := z.TagName()
		if strings.ToLower(string(name)) != "script" {
			continue
		}

		var src string
		for hasAttr {
			var key, val []byte
			key, val, hasAttr = z.TagAttr()
			if strings.ToLower(string(key)) == "src" {
				src = string(val)
			}
		}

		if src != "" && !seen[src] {
			seen[src] = true
			scripts = append(scripts, src)
		}
	}

	return scripts
}

func ParseComments(body string) []string {
	var comments []string

	z := html.NewTokenizer(strings.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt == html.CommentToken {
			text := strings.TrimSpace(string(z.Text()))
			if text != "" {
				comments = append(comments, text)
			}
		}
	}

	return comments
}

func ParseMetaRedirect(body string) string {
	z := html.NewTokenizer(strings.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}

		name, hasAttr := z.TagName()
		if strings.ToLower(string(name)) != "meta" {
			continue
		}

		var httpEquiv, content string
		for hasAttr {
			var key, val []byte
			key, val, hasAttr = z.TagAttr()
			switch strings.ToLower(string(key)) {
			case "http-equiv":
				httpEquiv = strings.ToLower(string(val))
			case "content":
				content = string(val)
			}
		}

		if httpEquiv == "refresh" && content != "" {
			idx := strings.LastIndex(content, "url=")
			if idx != -1 {
				urlStr := strings.TrimSpace(content[idx+4:])
				return urlStr
			}
		}
	}

	return ""
}
