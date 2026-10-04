// Package canonjson implements the canonical JSON encoding used to bind the
// signed verification receipt to the attestation evidence.
//
// The output is byte-identical to canonicalize() in the TypeScript client
// (adverserial-webui src/lib/confidential/verification.ts):
//
//   - object keys sorted ascending (bytewise; JS sorts by UTF-16 code unit,
//     which coincides for the ASCII keys this protocol uses),
//   - no whitespace anywhere,
//   - strings escaped exactly like JSON.stringify: only '"', '\' and control
//     characters < 0x20 are escaped (short forms \b \t \n \f \r, otherwise
//     lowercase \u00xx). Non-ASCII, DEL (0x7f), U+2028/U+2029 and '<', '>',
//     '&' are emitted raw — unlike Go's encoding/json default.
//
// Numbers: integers are emitted in plain decimal. Integral float64 values
// (which is what every JSON number becomes after a JSON.parse-style round
// trip) are emitted without a decimal point, matching JSON.stringify.
// Non-integral floats use shortest round-trip form with a JS-style exponent
// (no zero-padding, explicit sign). The attestation protocol itself only
// carries integers; float support exists so digests survive a JSON round trip.
package canonjson

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// String returns the canonical encoding of v.
// Supported types: nil, bool, string, int, int64, float64, []any,
// map[string]any. Anything else is an error.
func String(v any) (string, error) {
	var b strings.Builder
	if err := writeValue(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

// Digest returns "sha256:<base64url-no-padding>" over the UTF-8 canonical
// encoding of v — the exact construction of sha256(canonicalize(x)) in the
// TypeScript client.
func Digest(v any) (string, error) {
	s, err := String(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func writeValue(b *strings.Builder, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeString(b, t)
	case int:
		b.WriteString(strconv.Itoa(t))
	case int64:
		b.WriteString(strconv.FormatInt(t, 10))
	case float64:
		return writeFloat(b, t)
	case []any:
		b.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeValue(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := writeValue(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("canonjson: unsupported type %T", v)
	}
	return nil
}

func writeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

func writeFloat(b *strings.Builder, f float64) error {
	// ECMA-262 Number-to-String: plain decimal for 1e-6 <= |f| < 1e21,
	// exponential otherwise. JSON.stringify(-0) is "0".
	switch {
	case math.IsNaN(f) || math.IsInf(f, 0):
		return fmt.Errorf("canonjson: non-finite float")
	case f == 0:
		b.WriteString("0")
	case math.Abs(f) >= 1e-6 && math.Abs(f) < 1e21:
		b.WriteString(strconv.FormatFloat(f, 'f', -1, 64))
	default:
		// Shortest round-trip with JS-style exponent: Go emits "1e-07",
		// JSON.stringify emits "1e-7"; Go emits "1e+21", JS "1e+21".
		s := strconv.FormatFloat(f, 'e', -1, 64)
		if i := strings.IndexByte(s, 'e'); i >= 0 {
			mantissa, exp := s[:i], s[i+1:]
			sign := ""
			if exp[0] == '+' || exp[0] == '-' {
				sign, exp = string(exp[0]), exp[1:]
			}
			exp = strings.TrimLeft(exp, "0")
			if exp == "" {
				exp = "0"
			}
			s = mantissa + "e" + sign + exp
		}
		b.WriteString(s)
	}
	return nil
}
