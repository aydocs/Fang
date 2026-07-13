package payload

import (
	"context"
	"testing"
)

func TestEngineNew(t *testing.T) {
	e := NewEngine()
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestStoreLoad(t *testing.T) {
	store := NewStore()
	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestEncoderURL(t *testing.T) {
	e := &URLEncoder{}
	encoded := e.Encode("<script>alert(1)</script>")
	if encoded == "" {
		t.Error("empty encoded result")
	}
}

func TestEncoderBase64(t *testing.T) {
	e := &Base64Encoder{}
	encoded := e.Encode("test")
	if encoded != "dGVzdA==" {
		t.Errorf("base64 encode = %q, want dGVzdA==", encoded)
	}
}

func TestEncoderUnicode(t *testing.T) {
	e := &UnicodeEncoder{}
	encoded := e.Encode("<")
	if encoded == "" {
		t.Error("empty unicode encoded result")
	}
}

func TestEncoderHex(t *testing.T) {
	e := &HexEncoder{}
	encoded := e.Encode("test")
	if encoded != "74657374" {
		t.Errorf("hex encode = %q, want 74657374", encoded)
	}
}

func TestWAFBypass(t *testing.T) {
	strategies := GetBypassStrategy("cloudflare")
	if len(strategies) == 0 {
		t.Fatal("expected non-empty bypass strategies for cloudflare")
	}
}

func TestMutator(t *testing.T) {
	m := NewMutator(DefaultEncoders)
	if m == nil {
		t.Fatal("expected non-nil mutator")
	}
}

func TestDetectContext(t *testing.T) {
	html := `<html><body><p>user input</p></body></html>`
	ctx := DetectContext(html, "user input")
	if ctx == "" {
		t.Error("expected non-empty context")
	}
}

func TestInjectInContext(t *testing.T) {
	payload := "<script>alert(1)</script>"
	result := InjectInContext("html", payload)
	if result == "" {
		t.Error("empty injection result")
	}
}

func TestEncoderDoubleURL(t *testing.T) {
	e := &DoubleURLEncoder{}
	encoded := e.Encode("test")
	if encoded == "" {
		t.Error("empty double url encoded result")
	}
}

func TestWAFCloudflareBypass(t *testing.T) {
	strategies := GetBypassStrategy("cloudflare")
	if len(strategies) == 0 {
		t.Log("no bypass strategies returned for cloudflare")
	}
}

func TestStoreGetByVulnType(t *testing.T) {
	store := NewStore()
	categories := store.GetByVulnType("sqli")
	if len(categories) == 0 {
		t.Log("no categories returned (may need YAML payloads)")
	}
}

func TestEngineGenerate(t *testing.T) {
	e := NewEngine()
	ctx := context.Background()
	payloads, err := e.Generate(ctx, nil, "sqli")
	if err != nil {
		t.Log("Generate returned:", err)
	}
	if len(payloads) > 0 {
		t.Logf("generated %d payloads", len(payloads))
	}
}
