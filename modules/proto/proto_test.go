package proto

import (
	"context"
	"testing"

	"github.com/aydocs/fang/internal/engine"
	"github.com/aydocs/fang/pkg/models"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestProtoModuleID(t *testing.T) {
	m := &ProtoModule{}
	if m.ID() != "proto" {
		t.Errorf("ID = %q, want proto", m.ID())
	}
}

func TestProtoModuleSeverity(t *testing.T) {
	m := &ProtoModule{}
	if m.Severity() != models.High {
		t.Errorf("Severity = %d, want High", m.Severity())
	}
}

func TestProtoModuleInit(t *testing.T) {
	m := &ProtoModule{}
	err := m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestProtoScanGraceful(t *testing.T) {
	m := &ProtoModule{}
	m.Init(context.Background(), engine.NewConfig(engine.WithTimeout(5)))
	_, err := m.Scan(context.Background(), &models.Target{URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Logf("Scan error (expected): %v", err)
	}
}

func TestFieldMaskMarshal(t *testing.T) {
	fm := &fieldMask{paths: []string{"*", "spec.*", "metadata.name"}}
	data := fm.marshal()
	if len(data) == 0 {
		t.Fatal("marshal returned empty data")
	}
	var expectedFields int
	for len(data) > 0 {
		_, _, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]
		_, n = protowire.ConsumeBytes(data)
		if n < 0 {
			break
		}
		data = data[n:]
		expectedFields++
	}
	if expectedFields != 3 {
		t.Errorf("Expected 3 fields, got %d", expectedFields)
	}
}

func TestFieldMaskEmpty(t *testing.T) {
	fm := &fieldMask{paths: nil}
	data := fm.marshal()
	if len(data) != 0 {
		t.Errorf("Expected empty marshal for nil paths, got %d bytes", len(data))
	}
}
