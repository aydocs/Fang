package payload

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf16"
)

type Encoder interface {
	Name() string
	Encode(input string) string
}

type URLEncoder struct{}

func (e *URLEncoder) Name() string { return "url" }
func (e *URLEncoder) Encode(input string) string {
	var result strings.Builder
	for _, b := range []byte(input) {
		result.WriteString(fmt.Sprintf("%%%02X", b))
	}
	return result.String()
}

type DoubleURLEncoder struct{}

func (e *DoubleURLEncoder) Name() string { return "double_url" }
func (e *DoubleURLEncoder) Encode(input string) string {
	enc := &URLEncoder{}
	first := enc.Encode(input)
	return enc.Encode(first)
}

type Base64Encoder struct{}

func (e *Base64Encoder) Name() string { return "base64" }
func (e *Base64Encoder) Encode(input string) string {
	return base64.StdEncoding.EncodeToString([]byte(input))
}

type UnicodeEncoder struct{}

func (e *UnicodeEncoder) Name() string { return "unicode" }
func (e *UnicodeEncoder) Encode(input string) string {
	var result strings.Builder
	for _, r := range input {
		result.WriteString(fmt.Sprintf("\\u%04X", r))
	}
	return result.String()
}

type HexEncoder struct{}

func (e *HexEncoder) Name() string { return "hex" }
func (e *HexEncoder) Encode(input string) string {
	return hex.EncodeToString([]byte(input))
}

type HTMLEntityEncoder struct{}

func (e *HTMLEntityEncoder) Name() string { return "html_entity" }
func (e *HTMLEntityEncoder) Encode(input string) string {
	var result strings.Builder
	for _, r := range input {
		result.WriteString(fmt.Sprintf("&#x%X;", r))
	}
	return result.String()
}

type UTF16Encoder struct{}

func (e *UTF16Encoder) Name() string { return "utf16" }
func (e *UTF16Encoder) Encode(input string) string {
	runes := []rune(input)
	encoded := utf16.Encode(runes)
	result := []byte{0xFF, 0xFE}
	for _, r := range encoded {
		result = append(result, byte(r), byte(r>>8))
	}
	return string(result)
}

type NullByteEncoder struct{}

func (e *NullByteEncoder) Name() string { return "null_byte" }
func (e *NullByteEncoder) Encode(input string) string {
	var result strings.Builder
	result.WriteString(input)
	result.WriteByte(0)
	return result.String()
}

type TabNewlineEncoder struct{}

func (e *TabNewlineEncoder) Name() string { return "tab_newline" }
func (e *TabNewlineEncoder) Encode(input string) string {
	return strings.NewReplacer(
		" ", "\t",
		"\t", "\n",
	).Replace(input)
}

type CaseEncoder struct {
	mu  sync.Mutex
	rng *rand.Rand
}

func (e *CaseEncoder) Name() string { return "case" }
func (e *CaseEncoder) Encode(input string) string {
	e.mu.Lock()
	if e.rng == nil {
		e.rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	rng := e.rng
	e.mu.Unlock()

	var result strings.Builder
	for _, r := range input {
		if unicode.IsLetter(r) {
			if rng.Intn(2) == 0 {
				result.WriteRune(unicode.ToLower(r))
			} else {
				result.WriteRune(unicode.ToUpper(r))
			}
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

type CommentEncoder struct{}

func (e *CommentEncoder) Name() string { return "comment" }
func (e *CommentEncoder) Encode(input string) string {
	chars := strings.Split(input, "")
	return strings.Join(chars, "<!-- -->")
}

var DefaultEncoders = []Encoder{
	&URLEncoder{},
	&DoubleURLEncoder{},
	&Base64Encoder{},
	&UnicodeEncoder{},
	&HexEncoder{},
	&HTMLEntityEncoder{},
	&UTF16Encoder{},
	&NullByteEncoder{},
	&TabNewlineEncoder{},
	&CaseEncoder{},
	&CommentEncoder{},
}
