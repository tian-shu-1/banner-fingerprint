// Package jsonx contains a compatibility parser for scan exports that contain
// non-standard \xNN escapes. Valid JSON is always parsed strictly and is never
// rewritten; the compatibility path is only attempted after a strict failure.
package jsonx

import (
	"encoding/json"
	"fmt"
)

const hexDigits = "0123456789abcdef"

// UnmarshalLenient first tries encoding/json. If that fails it normalizes
// invalid \xNN escapes and unescaped control bytes, then tries once more.
// The returned bool reports whether the compatibility path was used.
func UnmarshalLenient(data []byte, v any) (bool, error) {
	if err := json.Unmarshal(data, v); err == nil {
		return false, nil
	} else {
		strictErr := err
		if lenientErr := json.Unmarshal(NormalizeEscapes(data), v); lenientErr == nil {
			return true, nil
		} else {
			return true, fmt.Errorf("strict JSON parse failed: %v; lenient parse failed: %v", strictErr, lenientErr)
		}
	}
}

// NormalizeEscapes rewrites invalid JSON string escapes into valid ones.
//
// The task input uses \x00 and \x16\x03\x01. Those are not valid JSON escapes.
// We map \xHH to the Unicode code point U+00HH. The rule engine therefore sees
// a rune string, and binary-head rules must use the same \xHH convention.
// Escaped backslashes such as "\\x00" are preserved as literal text.
func NormalizeEscapes(data []byte) []byte {
	out := make([]byte, 0, len(data)+16)
	inString := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if !inString {
			out = append(out, c)
			if c == '"' {
				inString = true
			}
			continue
		}

		switch c {
		case '"':
			out = append(out, c)
			inString = false
		case '\\':
			if i+1 >= len(data) {
				out = append(out, c)
				continue
			}
			next := data[i+1]
			if (next == 'x' || next == 'X') && i+3 < len(data) && isHex(data[i+2]) && isHex(data[i+3]) {
				out = append(out, '\\', 'u', '0', '0', data[i+2], data[i+3])
				i += 3
				continue
			}
			if next == 'u' && i+5 < len(data) && allHex(data[i+2:i+6]) {
				out = append(out, data[i:i+6]...)
				i += 5
				continue
			}
			if isSimpleEscape(next) {
				out = append(out, c, next)
				i++
				continue
			}
			out = append(out, '\\', '\\')
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '\t':
			out = append(out, '\\', 't')
		default:
			if c < 0x20 {
				out = append(out, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0x0f])
			} else {
				out = append(out, c)
			}
		}
	}
	return out
}

func isSimpleEscape(c byte) bool {
	switch c {
	case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
		return true
	default:
		return false
	}
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func allHex(b []byte) bool {
	for _, c := range b {
		if !isHex(c) {
			return false
		}
	}
	return true
}
