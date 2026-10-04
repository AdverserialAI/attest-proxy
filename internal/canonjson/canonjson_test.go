package canonjson

import (
	"encoding/base64"
	"strings"
	"testing"
)

// The fixture below is canonicalized and hashed by the TypeScript
// canonicalize()/sha256() pair from
// adverserial-webui src/lib/confidential/verification.ts, reimplemented in
// Node verbatim:
//
//	const canonicalize = (value) => {
//	  if (value === null || typeof value !== "object") return JSON.stringify(value);
//	  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
//	  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(",")}}`;
//	};
//	crypto.createHash("sha256").update(canonicalize(fixture), "utf8").digest("base64url")
//
// It deliberately exercises: key sorting at two depths, empty object/array,
// null, booleans, integers, a string containing non-ASCII (é), HTML metachars
// (<>&), a quote, and U+2028 — all emitted raw by JSON.stringify but escaped
// by Go's encoding/json defaults.
var canonicalFixture = map[string]any{
	"alpha":  "héllo <>& \"quote\" \u2028sep",
	"z_last": []any{1, "two", nil, true, map[string]any{"b": 2, "a": 1}},
	"num":    42,
	"neg":    -7,
	"nested": map[string]any{"k2": []any{}, "k1": map[string]any{}},
	"dev":    true,
	"ref":    nil,
}

// Produced by the Node reimplementation of the TS client (see above).
const (
	wantCanonicalB64 = "eyJhbHBoYSI6ImjDqWxsbyA8PiYgXCJxdW90ZVwiIOKAqHNlcCIsImRldiI6dHJ1ZSwibmVnIjotNywibmVzdGVkIjp7ImsxIjp7fSwiazIiOltdfSwibnVtIjo0MiwicmVmIjpudWxsLCJ6X2xhc3QiOlsxLCJ0d28iLG51bGwsdHJ1ZSx7ImEiOjEsImIiOjJ9XX0="
	wantDigest       = "sha256:1mKIEeUwRHV8oq766icqSY6A6QMdHXwqSaAXSM5enLs"
)

func TestCanonicalMatchesTypeScript(t *testing.T) {
	got, err := String(canonicalFixture)
	if err != nil {
		t.Fatalf("String: %v", err)
	}
	want, err := base64.StdEncoding.DecodeString(wantCanonicalB64)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if got != string(want) {
		t.Fatalf("canonical mismatch:\n got %q\nwant %q", got, string(want))
	}
}

func TestDigestMatchesTypeScript(t *testing.T) {
	got, err := Digest(canonicalFixture)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if got != wantDigest {
		t.Fatalf("digest mismatch: got %q want %q", got, wantDigest)
	}
}

// String escaping probes, each verified against JSON.stringify in Node.
func TestStringEscaping(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", `""`},
		{"\x01", `"\u0001"`},
		{"\x1f", `"\u001f"`},
		{"\x7f", "\"\x7f\""},     // DEL is raw in JSON.stringify
		{"\u2028", "\"\u2028\""}, // raw, unlike encoding/json
		{"\u2029", "\"\u2029\""}, // raw, unlike encoding/json
		{"<>&", `"<>&"`},         // raw, unlike encoding/json
		{"héllo", `"héllo"`},     // raw UTF-8
		{"a\"b\\c\nd\te", `"a\"b\\c\nd\te"`},
	}
	for _, c := range cases {
		got, err := String(c.in)
		if err != nil {
			t.Fatalf("String(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("String(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestNumbers(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{0, "0"},
		{int64(1759999999), "1759999999"},
		{float64(1), "1"},     // JSON round trip turns 1 into float64(1)
		{float64(-7), "-7"},   //
		{float64(0.5), "0.5"}, // shortest round trip, like JSON.stringify
		{float64(1e21), "1e+21"},
		{float64(1e-7), "1e-7"},
		{float64(1e-6), "0.000001"}, // JS switches to plain notation at 1e-6
		{float64(-0.0), "0"},        // JSON.stringify(-0) === "0"
	}
	for _, c := range cases {
		got, err := String(c.in)
		if err != nil {
			t.Fatalf("String(%v): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("String(%v) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestUnsupportedType(t *testing.T) {
	if _, err := String(make(chan int)); err == nil {
		t.Fatal("expected error for unsupported type")
	}
	if _, err := String(map[string]any{"f": 1.5 + 0.5i}); err == nil {
		t.Fatal("expected error for nested unsupported type")
	}
}

func TestDigestSurvivesJSONRoundTrip(t *testing.T) {
	// A verifier digests the evidence after JSON.parse, where every number is
	// a float64. The digest over the round-tripped shape must match.
	orig := map[string]any{"version": 1, "n": int64(300)}
	roundTripped := map[string]any{"version": float64(1), "n": float64(300)}
	d1, err := Digest(orig)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := Digest(roundTripped)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatalf("round-trip digest mismatch: %s vs %s", d1, d2)
	}
	if !strings.HasPrefix(d1, "sha256:") {
		t.Fatalf("digest missing prefix: %s", d1)
	}
}
