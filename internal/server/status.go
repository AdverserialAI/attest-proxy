package server

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/adverserial/attest-proxy/internal/attestation"
	"github.com/adverserial/attest-proxy/internal/buildinfo"
	"github.com/adverserial/attest-proxy/internal/canonjson"
)

const (
	statuszPath        = "/statusz"
	meterJWKSPath      = "/.well-known/adverserial-meter-jwks.json"
	keyAttestationPath = "/.well-known/adverserial-key-attestation"

	// KeyAttestationDomain prefixes the statement bytes before hashing into
	// the TDX report_data, so a key-attestation quote can never be confused
	// with a nonce-bound /attestation quote (whose report_data is a SHA-256
	// followed by 32 zero bytes).
	KeyAttestationDomain = "adverserial-key-attestation-v1\n"

	// keyAttestationTTL bounds quote generation on this unauthenticated
	// route to one per minute per serving certificate.
	keyAttestationTTL = 60 * time.Second

	maxInferenceStatusBytes = 8 << 10
	maxInferenceStatusField = 200
)

// inferenceStatusFields is the whitelist copied from INFERENCE_STATUS_FILE.
var inferenceStatusFields = []string{"ladder_id", "rung", "phase", "attempt", "started_at", "updated_at", "detail"}

func getOnly(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// meterJWK returns the public meter JWK, or nil when this process has no
// meter key (non-confidential mode).
func (s *Server) meterJWK() map[string]any {
	if s.meterSigner == nil {
		return nil
	}
	out := map[string]any{}
	for k, v := range s.meterSigner.PublicJWK() {
		out[k] = v
	}
	return out
}

// handleMeterJWKS publishes the meter verification key as a JWK set. The key
// is only as trustworthy as the channel it was fetched over; billing must pin
// it after checking the key attestation, not on first sight.
func (s *Server) handleMeterJWKS(w http.ResponseWriter, r *http.Request) {
	if !getOnly(w, r) {
		return
	}
	keys := []any{}
	if jwk := s.meterJWK(); jwk != nil {
		keys = append(keys, jwk)
	}
	writeJSON(w, map[string]any{"keys": keys})
}

// handleStatusz reports coarse process state for operators and monitors. It
// carries public key identifiers and counters only: no secrets, no request
// data, nothing derived from a prompt or completion.
func (s *Server) handleStatusz(w http.ResponseWriter, r *http.Request) {
	if !getOnly(w, r) {
		return
	}
	out := map[string]any{
		"version":                buildinfo.Version,
		"started_at":             s.started.Format(time.RFC3339),
		"keys_origin":            s.keysOrigin,
		"receipt_kid":            s.signer.KeyID(),
		"meter_kid":              nil,
		"meter_jwk_thumbprint":   nil,
		"ehbp_public_key_sha256": nil,
		"upstream_ready":         nil,
		"ingress": map[string]any{
			"in_use": len(s.ingressSlots),
			"max":    cap(s.ingressSlots),
		},
	}
	if s.meterSigner != nil {
		out["meter_kid"] = s.meterSigner.KeyID()
		out["meter_jwk_thumbprint"] = s.meterSigner.Thumbprint()
	}
	if s.ehbp != nil {
		out["ehbp_public_key_sha256"] = s.ehbpPublicKeySHA256()
	}
	if s.upstreamReady != nil {
		out["upstream_ready"] = s.upstreamReady()
	}
	if status := readInferenceStatus(s.cfg.InferenceStatusFile); status != nil {
		out["inference"] = status
	}
	writeJSON(w, out)
}

// readInferenceStatus returns the whitelisted, sanitized fields of the model
// runtime's progress file, or nil when it is unset, unreadable, oversized, or
// not a JSON object. The file is written by another container, so nothing in
// it is trusted: only known keys are copied and every value is reduced to a
// short string over a fixed alphabet.
func readInferenceStatus(path string) map[string]any {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxInferenceStatusBytes+1))
	if err != nil || len(raw) > maxInferenceStatusBytes {
		return nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	out := map[string]any{}
	for _, field := range inferenceStatusFields {
		value, ok := doc[field]
		if !ok {
			continue
		}
		if strings.TrimSpace(string(value)) == "null" {
			continue
		}
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			text = string(value) // numbers, booleans, nested JSON: literal text
		}
		out[field] = sanitizeStatusValue(text)
	}
	return out
}

func sanitizeStatusValue(v string) string {
	var b strings.Builder
	n := 0
	for _, r := range v {
		if n == maxInferenceStatusField {
			break
		}
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			strings.ContainsRune(" _.:,=/+-", r):
			b.WriteRune(r)
		default:
			b.WriteByte('?')
		}
		n++
	}
	return b.String()
}

// keyAttestationCache holds the most recent key attestation. Quotes are
// expensive and this route takes no nonce, so one result is reused for
// keyAttestationTTL; gen serializes generation so a burst produces one quote.
type keyAttestationCache struct {
	mu      sync.Mutex
	gen     sync.Mutex
	body    []byte
	spki    string
	expires time.Time
}

func (c *keyAttestationCache) get(spki string, now time.Time) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.body != nil && c.spki == spki && now.Before(c.expires) {
		return c.body
	}
	return nil
}

// keyAttestationStatement is the canonical JSON statement bound into the
// quote: every public key this enclave answers for, and where the private
// halves came from.
func (s *Server) keyAttestationStatement(tlsSPKI string, now time.Time) (string, error) {
	statement := map[string]any{
		"type":                   "adverserial-key-attestation/v1",
		"issued_at":              now.UTC().Format(time.RFC3339),
		"proxy_version":          buildinfo.Version,
		"keys_origin":            s.keysOrigin,
		"receipt_pubkey_jwk":     s.signer.PublicJWK(),
		"meter_pubkey_jwk":       nil,
		"ehbp_public_key":        nil,
		"ehbp_public_key_sha256": nil,
		"tls_spki_sha256":        tlsSPKI,
	}
	if jwk := s.meterJWK(); jwk != nil {
		statement["meter_pubkey_jwk"] = jwk
	}
	if s.ehbp != nil {
		statement["ehbp_public_key"] = base64.RawURLEncoding.EncodeToString(s.ehbp.MarshalPublicKey())
		statement["ehbp_public_key_sha256"] = s.ehbpPublicKeySHA256()
	}
	if s.cfg.DevMode {
		statement["dev"] = true
	}
	return canonjson.String(statement)
}

// KeyAttestationReportData is the 64-byte TDX report_data of a key
// attestation: SHA-512(KeyAttestationDomain || statement).
func KeyAttestationReportData(statement string) [64]byte {
	h := sha512.New()
	h.Write([]byte(KeyAttestationDomain))
	h.Write([]byte(statement))
	var out [64]byte
	copy(out[:], h.Sum(nil))
	return out
}

// handleKeyAttestation binds the receipt, meter, EHBP, and TLS public keys
// to a TDX quote. It is additive: /attestation and its report_data format
// are unchanged. /attestation already binds the TLS, receipt, and EHBP keys
// per nonce; this route adds the meter key and the keys_origin claim, and
// gives billing a quote it can check before pinning the meter JWK.
func (s *Server) handleKeyAttestation(w http.ResponseWriter, r *http.Request) {
	if !getOnly(w, r) {
		return
	}
	tlsSPKI := attestation.SPKIHash(s.holder.Leaf())
	if body := s.keyAttestation.get(tlsSPKI, s.now()); body != nil {
		writeKeyAttestation(w, body)
		return
	}
	// One generation at a time. Callers arriving meanwhile are shed rather
	// than queued, so a flood cannot pile goroutines onto the guest agent.
	if !s.keyAttestation.gen.TryLock() {
		w.Header().Set("Retry-After", "2")
		writeError(w, http.StatusServiceUnavailable, "key attestation is being generated; retry shortly")
		return
	}
	defer s.keyAttestation.gen.Unlock()
	now := s.now()
	if body := s.keyAttestation.get(tlsSPKI, now); body != nil {
		writeKeyAttestation(w, body)
		return
	}
	statement, err := s.keyAttestationStatement(tlsSPKI, now)
	if err != nil {
		s.logger.Error("key attestation statement failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "key attestation unavailable")
		return
	}
	select {
	case quoteSem <- struct{}{}:
		defer func() { <-quoteSem }()
	default:
		w.Header().Set("Retry-After", "2")
		writeError(w, http.StatusServiceUnavailable, "attestation is busy; retry shortly")
		return
	}
	// Detached from the request: a client that disconnects must not cancel a
	// quote other callers will reuse.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	quote, err := s.quotes.Quote(ctx, KeyAttestationReportData(statement))
	if err != nil {
		s.logger.Error("key attestation quote failed", "error", err.Error())
		writeError(w, http.StatusBadGateway, "attestation quote unavailable")
		return
	}
	body, err := json.Marshal(map[string]any{
		"statement": statement,
		"quote":     quote.QuoteHex,
		"event_log": quote.EventLog,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key attestation unavailable")
		return
	}
	c := &s.keyAttestation
	c.mu.Lock()
	c.body, c.spki, c.expires = body, tlsSPKI, now.Add(keyAttestationTTL)
	c.mu.Unlock()
	writeKeyAttestation(w, body)
}

func writeKeyAttestation(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}
