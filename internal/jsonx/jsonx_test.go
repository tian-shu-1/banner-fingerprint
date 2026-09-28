package jsonx

import "testing"

func TestStrictValidJSONIsNotRewritten(t *testing.T) {
	var value []map[string]string
	lenient, err := UnmarshalLenient([]byte(`[{"banner":"C:\\x00 literal"}]`), &value)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if lenient {
		t.Fatal("valid JSON must use the strict path")
	}
	if value[0]["banner"] != `C:\x00 literal` {
		t.Fatalf("banner = %q, want literal backslash-x text", value[0]["banner"])
	}
}

func TestLenientHexEscapes(t *testing.T) {
	var value []map[string]string
	lenient, err := UnmarshalLenient([]byte(`[{"banner":"J\x00\x00\x00\n8.0.32\x00"}]`), &value)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !lenient {
		t.Fatal("invalid \\xNN escapes must use the lenient path")
	}
	if value[0]["banner"] != "J\x00\x00\x00\n8.0.32\x00" {
		t.Fatalf("banner = %q", value[0]["banner"])
	}
}

func TestLenientTLSBytes(t *testing.T) {
	var value []map[string]string
	lenient, err := UnmarshalLenient([]byte(`[{"banner":"\x16\x03\x01\xa5"}]`), &value)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !lenient {
		t.Fatal("expected lenient path")
	}
	if value[0]["banner"] != "\u0016\u0003\u0001\u00a5" {
		t.Fatalf("banner = %q", value[0]["banner"])
	}
}

func TestLenientRawControlByte(t *testing.T) {
	var value []map[string]string
	lenient, err := UnmarshalLenient([]byte("[{\"banner\":\"A\nB\"}]"), &value)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !lenient {
		t.Fatal("raw control byte must use the lenient path")
	}
	if value[0]["banner"] != "A\nB" {
		t.Fatalf("banner = %q", value[0]["banner"])
	}
}
