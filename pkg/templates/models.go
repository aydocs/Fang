package templates

type Template struct {
	ID       string       `yaml:"id"`
	Info     Info         `yaml:"info"`
	Requests []Request    `yaml:"requests"`
	Raw      []RawRequest `yaml:"raw,omitempty"`
}

type Info struct {
	Name        string `yaml:"name"`
	Author      string `yaml:"author"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
	Remediation string `yaml:"remediation"`
	Tags        string `yaml:"tags"`
	Reference   string `yaml:"reference,omitempty"`
}

type Request struct {
	Method     string            `yaml:"method"`
	Path       []string          `yaml:"path"`
	Headers    map[string]string `yaml:"headers,omitempty"`
	Body       string            `yaml:"body,omitempty"`
	Matchers   []Matcher         `yaml:"matchers"`
	Extractors []Extractor       `yaml:"extractors,omitempty"`
}

type RawRequest struct {
	Raw      []string  `yaml:"raw"`
	Matchers []Matcher `yaml:"matchers"`
}

type Matcher struct {
	Type      string   `yaml:"type"`
	Words     []string `yaml:"words,omitempty"`
	Regex     []string `yaml:"regex,omitempty"`
	Status    []int    `yaml:"status,omitempty"`
	Size      []int    `yaml:"size,omitempty"`
	Condition string   `yaml:"condition,omitempty"`
	Part      string   `yaml:"part,omitempty"`
}

type Extractor struct {
	Type  string   `yaml:"type"`
	Name  string   `yaml:"name"`
	Regex []string `yaml:"regex,omitempty"`
	JSON  []string `yaml:"json,omitempty"`
}

type MatchResult struct {
	TemplateID   string
	TemplateName string
	Severity     string
	Matched      bool
	URL          string
	MatcherName  string
	Extracted    map[string]string
}
