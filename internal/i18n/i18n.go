package i18n

import "fmt"

type Lang string

const (
	EN Lang = "en"
	TR Lang = "tr"
	DE Lang = "de"
	FR Lang = "fr"
	ES Lang = "es"
	RU Lang = "ru"
	ZH Lang = "zh"
	AR Lang = "ar"
	JA Lang = "ja"
)

type Bundle struct {
	current Lang
	strings map[Lang]map[string]string
}

func New() *Bundle {
	return &Bundle{
		current: EN,
		strings: make(map[Lang]map[string]string),
	}
}

func (b *Bundle) SetLang(l Lang) {
	b.current = l
}

func (b *Bundle) GetLang() Lang {
	return b.current
}

func (b *Bundle) Register(l Lang, strings map[string]string) {
	b.strings[l] = strings
}

func (b *Bundle) T(key string) string {
	if m, ok := b.strings[b.current]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	if m, ok := b.strings[EN]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	return key
}

func (b *Bundle) Tf(key string, args ...interface{}) string {
	t := b.T(key)
	if len(args) > 0 {
		return fmt.Sprintf(t, args...)
	}
	return t
}

var Default *Bundle

func init() {
	Default = New()
	Default.SetLang(EN)
}
