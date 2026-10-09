package meter

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func decodePayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// TestBuildStartRoundTrip: the start event signs verifiably and carries the
// dispatch-precondition contract (typ, jti, request_id, model, 10-minute
// window, zero counts).
func TestBuildStartRoundTrip(t *testing.T) {
	s, err := NewTestSigner()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	token, claims, err := BuildStart(s, "res-9", "req-9", "lordx64/cyberglm", "https://api.adverserial.ai", "https://billing.adverserial.ai", now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Type != "adverserial-confidential-start/v1" {
		t.Errorf("typ = %q", claims.Type)
	}
	if claims.Expires-claims.IssuedAt != 600 {
		t.Errorf("exp-iat = %d, want 600", claims.Expires-claims.IssuedAt)
	}
	if claims.InputTokens != 0 || claims.CachedTokens != 0 || claims.OutputTokens != 0 {
		t.Errorf("start event must carry zero counts: %+v", claims)
	}
	parts := strings.Split(token, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	pub := s.private.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("start event signature does not verify")
	}
	got := decodePayload(t, token)
	for k, want := range map[string]string{
		"iss": "https://api.adverserial.ai", "aud": "https://billing.adverserial.ai",
		"typ": "adverserial-confidential-start/v1", "jti": "res-9",
		"request_id": "req-9", "model": "lordx64/cyberglm",
	} {
		if got[k] != want {
			t.Errorf("claims[%s] = %v, want %s", k, got[k], want)
		}
	}
}

func readOnlyRecord(t *testing.T, dir string) map[string]any {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("outbox records = %d, want 1", len(entries))
	}
	b, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	return decodePayload(t, strings.TrimSpace(string(b)))
}

func TestTerminalSettlementObservedCounts(t *testing.T) {
	s, err := NewTestSigner()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// A failing poster keeps the durable record in place for inspection.
	p := &poster{err: errors.New("hold record")}
	ts := NewTerminalSettlement(s, "iss", "aud", Outbox{Dir: dir, Poster: p}, "res-1", "req-1", "lordx64/cyberglm", nil)
	ts.Observe(11, 7, 2)
	ts.Settle()
	got := readOnlyRecord(t, dir)
	if got["typ"] != "adverserial-confidential-meter/v1" {
		t.Errorf("typ = %v", got["typ"])
	}
	if got["jti"] != "res-1" || got["request_id"] != "req-1" || got["model"] != "lordx64/cyberglm" {
		t.Errorf("identity = %v/%v/%v", got["jti"], got["request_id"], got["model"])
	}
	if got["input_tokens"] != float64(11) || got["cached_tokens"] != float64(7) || got["output_tokens"] != float64(2) {
		t.Errorf("counts = %v/%v/%v, want 11/7/2", got["input_tokens"], got["cached_tokens"], got["output_tokens"])
	}
}

// TestTerminalSettlementZerosWithoutObservation: a request that ends before
// any usage was observed still settles, with all-zero counts.
func TestTerminalSettlementZerosWithoutObservation(t *testing.T) {
	s, err := NewTestSigner()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := &poster{err: errors.New("hold record")}
	ts := NewTerminalSettlement(s, "iss", "aud", Outbox{Dir: dir, Poster: p}, "res-1", "req-1", "lordx64/cyberglm", nil)
	ts.Settle()
	got := readOnlyRecord(t, dir)
	if got["input_tokens"] != float64(0) || got["cached_tokens"] != float64(0) || got["output_tokens"] != float64(0) {
		t.Errorf("counts = %v/%v/%v, want zeros", got["input_tokens"], got["cached_tokens"], got["output_tokens"])
	}
}

// TestTerminalSettlementSettlesOnce: repeated Settle calls enqueue exactly
// one record, carrying the counts observed before the first Settle.
func TestTerminalSettlementSettlesOnce(t *testing.T) {
	s, err := NewTestSigner()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := &poster{err: errors.New("hold record")}
	ts := NewTerminalSettlement(s, "iss", "aud", Outbox{Dir: dir, Poster: p}, "res-1", "req-1", "lordx64/cyberglm", nil)
	ts.Observe(11, 7, 2)
	ts.Settle()
	ts.Observe(99, 99, 99)
	ts.Settle()
	ts.Settle()
	got := readOnlyRecord(t, dir)
	if got["input_tokens"] != float64(11) || got["output_tokens"] != float64(2) {
		t.Errorf("later Settle calls changed the record: %v/%v", got["input_tokens"], got["output_tokens"])
	}
}

// TestTerminalSettlementNilSafe: non-confidential requests carry no handle;
// terminal paths call Observe/Settle unconditionally.
func TestTerminalSettlementNilSafe(t *testing.T) {
	var ts *TerminalSettlement
	ts.Observe(1, 2, 3)
	ts.Settle()
}
