package main

import (
	"os"
	"path/filepath"
	"testing"

	"bannerfp/internal/jsonx"
	"bannerfp/internal/model"
)

func loadExample(t *testing.T, name string) ([]model.Item, bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var items []model.Item
	lenient, err := jsonx.UnmarshalLenient(data, &items)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return items, lenient
}

func TestDefaultExampleExercisesLenientPath(t *testing.T) {
	items, lenient := loadExample(t, "input.json")
	if !lenient {
		t.Fatal("examples/input.json must exercise the lenient path")
	}
	if len(items) != 20 {
		t.Fatalf("items = %d, want 20", len(items))
	}
	if got := items[15].Banner; got != "\u0016\u0003\u0001\u0000\u00a5\u0001\u0000\u0000\u00a1" {
		t.Fatalf("TLS banner = %q", got)
	}
}

func TestValidExampleUsesStrictPath(t *testing.T) {
	items, lenient := loadExample(t, "input_valid.json")
	if lenient {
		t.Fatal("examples/input_valid.json must parse strictly")
	}
	if len(items) != 20 {
		t.Fatalf("items = %d, want 20", len(items))
	}
	if got := items[15].Banner; got != "\u0016\u0003\u0001\u0000\u00a5\u0001\u0000\u0000\u00a1" {
		t.Fatalf("TLS banner = %q", got)
	}
}
