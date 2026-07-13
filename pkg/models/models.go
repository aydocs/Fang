package models

import "time"

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "INFO"
	case Low:
		return "LOW"
	case Medium:
		return "MEDIUM"
	case High:
		return "HIGH"
	case Critical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) Color() string {
	switch s {
	case Critical:
		return "red"
	case High:
		return "red"
	case Medium:
		return "yellow"
	case Low:
		return "cyan"
	case Info:
		return "white"
	default:
		return "white"
	}
}

type Confidence int

const (
	Tentative Confidence = iota
	LowConfidence
	MediumConfidence
	HighConfidence
	CriticalConfidence
)

func (c Confidence) String() string {
	switch c {
	case Tentative:
		return "TENTATIVE"
	case LowConfidence:
		return "LOW"
	case MediumConfidence:
		return "MEDIUM"
	case HighConfidence:
		return "HIGH"
	case CriticalConfidence:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

type Finding struct {
	Title         string            `json:"title"`
	Severity      Severity          `json:"severity"`
	Confidence    Confidence        `json:"confidence"`
	URL           string            `json:"url"`
	Parameter     string            `json:"parameter,omitempty"`
	Payload       string            `json:"payload,omitempty"`
	Evidence      string            `json:"evidence,omitempty"`
	Description   string            `json:"description"`
	Remediation   string            `json:"remediation"`
	CWEID         string            `json:"cwe_id,omitempty"`
	OWASPCategory string            `json:"owasp_category,omitempty"`
	CVSS          *float64          `json:"cvss,omitempty"`
	ModuleID      string            `json:"module_id,omitempty"`
	Request       string            `json:"request,omitempty"`
	Response      string            `json:"response,omitempty"`
	Extra         map[string]string `json:"extra,omitempty"`
}

type ScanResult struct {
	Target    string            `json:"target"`
	StartTime time.Time         `json:"start_time"`
	EndTime   time.Time         `json:"end_time"`
	Duration  string            `json:"duration"`
	Findings  []*Finding        `json:"findings"`
	Summary   Summary           `json:"summary"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type Technology struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Type    string `json:"type"`
}

type Target struct {
	URL          string
	Domain       string
	Method       string
	Headers      map[string]string
	Cookies      []*Cookie
	Params       []*Parameter
	Technologies []Technology
	ContentType  string
	CrawlResult  *CrawlResult
}

type Parameter struct {
	Name      string
	Value     string
	Type      ParamType
	Location  ParamLocation
	Required  bool
	Sensitive bool
}

type ParamType int

const (
	ParamString ParamType = iota
	ParamInt
	ParamBool
	ParamJSON
	ParamXML
	ParamFile
	ParamEmail
	ParamPhone
	ParamDate
)

type ParamLocation int

const (
	ParamQuery ParamLocation = iota
	ParamForm
	ParamHeader
	ParamCookie
	ParamPath
	ParamJSONBody
	ParamXMLBody
	ParamMultipart
)

type Cookie struct {
	Name     string
	Value    string
	Secure   bool
	HttpOnly bool
	SameSite string
	Domain   string
	Path     string
}

type Payload struct {
	Value     string
	Encoded   string
	Type      string
	Context   string
	WAFBypass bool
	Params    []string
	Headers   map[string]string
	Cookies   map[string]string
}

type Verification struct {
	Confirmed  bool
	Confidence Confidence
	Evidence   string
	Method     string
	Attempts   int
	Duration   time.Duration
}

type CrawlResult struct {
	URLs         []string
	Forms        []*Form
	Scripts      []string
	Stylesheets  []string
	APIs         []string
	Cookies      []*Cookie
	Technologies []Technology
	Body         string
	StatusCode   int
	Headers      map[string]string
}

type Form struct {
	Action string
	Method string
	Inputs []*FormInput
}

type FormInput struct {
	Name     string
	Type     string
	Value    string
	Required bool
}

type ModuleResult struct {
	ModuleID   string
	ModuleName string
	Findings   []*Finding
	Error      error
	Duration   time.Duration
}

func (s *Summary) Add(f *Finding) {
	s.Total++
	switch f.Severity {
	case Critical:
		s.Critical++
	case High:
		s.High++
	case Medium:
		s.Medium++
	case Low:
		s.Low++
	case Info:
		s.Info++
	}
}

func NewFinding(title string, severity Severity) *Finding {
	return &Finding{
		Title:      title,
		Severity:   severity,
		Confidence: HighConfidence,
	}
}
