// Package attestation builds the public evidence object and talks to the
// dstack guest agent for TDX quotes.
package attestation

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"time"

	"github.com/adverserial/attest-proxy/internal/canonjson"
)

// Workload identifies the measured workload running inside the CVM.
type Workload struct {
	PolicyID      string
	ModelID       string
	ProxyVersion  string
	ComposeDigest string // sha256 of the dstack compose configuration
	ModelDigest   string // sha256 of the model artifact
}

// EvidenceInput carries everything needed to build one evidence object.
type EvidenceInput struct {
	Nonce     string // client nonce, base64url, echoed verbatim
	IssuedAt  time.Time
	ExpiresAt time.Time
	QuoteHex  string
	// EventLog is the RTMR replay material returned with the quote. It enables
	// a verifier to tie the signed TDX quote to the measured workload.
	EventLog      any
	TLSSPKISHA256 string // "sha256:<base64url>" of the TLS certificate SPKI
	// TLSSPKIDER is the public DER SubjectPublicKeyInfo, included so an
	// independent verifier can recompute the quote report_data binding.
	TLSSPKIDER []byte
	// EHBP is the public receiver key for encrypted HTTP request and response
	// bodies. When present it is bound into the fresh TDX quote alongside TLS
	// and receipt keys, so a verifier can reject a substituted HPKE receiver.
	EHBP       map[string]any
	ReceiptJWK map[string]any
	// AttestationStateDigest is a stable identity of the currently attested
	// runtime state. Per-request receipts cite this exact value.
	AttestationStateDigest string
	Workload               Workload
	GPU                    GPUEvidence // zero value → gpu_evidence: null
	Dev                    bool
}

// ReportData builds the 64-byte TDX report_data field for the quote request.
//
// Byte order (protocol-fixed, must stay in sync with the published spec):
//
//	report_data[0:32]  = SHA-256("adverserial-attestation-v2\\x00" || nonce_raw || tls_spki_der || receipt_spki_der || ehbp_receiver_pubkey)
//	report_data[32:64] = zero padding
//
// where nonce_raw is the base64url-decoded client nonce, tls_spki_der is the
// DER-encoded PKIX SubjectPublicKeyInfo of the in-enclave TLS public key, and
// receipt_spki_der is the same encoding of the receipt-signing public key;
// ehbp_receiver_pubkey is the raw X25519 public key used for encrypted bodies.
// This binds hardware evidence to the exact TLS key terminating the client's
// connection, receipt key, and encrypted-body receiver key (WP-4).
func ReportData(nonceRaw, tlsSPKIDER, receiptSPKIDER []byte, ehbpPublicKeys ...[]byte) [64]byte {
	var ehbpPublicKey []byte
	if len(ehbpPublicKeys) > 0 {
		ehbpPublicKey = ehbpPublicKeys[0]
	}
	h := sha256.New()
	// Domain separation is necessary because v2 binds an additional receiver
	// key. It also prevents a v1 quote from being misinterpreted as v2 proof.
	h.Write([]byte("adverserial-attestation-v2\x00"))
	h.Write(nonceRaw)
	h.Write(tlsSPKIDER)
	h.Write(receiptSPKIDER)
	h.Write(ehbpPublicKey)
	var out [64]byte
	copy(out[:32], h.Sum(nil))
	return out
}

// SPKIHash returns "sha256:<base64url-no-padding>" over the certificate's
// DER-encoded SubjectPublicKeyInfo — the same value a client computes from
// the TLS peer certificate during channel binding.
func SPKIHash(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

// BuildEvidence assembles the public attestation evidence object. Key and
// value types are restricted to what canonjson supports so the receipt's
// evidence_sha256 claim can be reproduced byte-for-byte by the client after
// a JSON round trip.
func BuildEvidence(in EvidenceInput) map[string]any {
	workload := map[string]any{
		"policy_id":      in.Workload.PolicyID,
		"model_id":       in.Workload.ModelID,
		"proxy_version":  in.Workload.ProxyVersion,
		"compose_digest": in.Workload.ComposeDigest,
		"model_digest":   in.Workload.ModelDigest,
	}
	ev := map[string]any{
		"version":                  1,
		"nonce":                    in.Nonce,
		"issued_at":                in.IssuedAt.UTC().Format(time.RFC3339),
		"expires_at":               in.ExpiresAt.UTC().Format(time.RFC3339),
		"tdx_quote":                in.QuoteHex,
		"tdx_event_log":            in.EventLog,
		"tls_spki_sha256":          in.TLSSPKISHA256,
		"tls_spki_der":             base64.RawURLEncoding.EncodeToString(in.TLSSPKIDER),
		"receipt_pubkey_jwk":       in.ReceiptJWK,
		"attestation_state_digest": in.AttestationStateDigest,
		"workload":                 workload,
		// NVIDIA GPU evidence: the cached NRAS EAT bundle produced by the
		// collector sidecar (GPU_EVIDENCE_FILE), or null when absent.
		"gpu_evidence":     nil,
		"gpu_evidence_ref": nil,
	}
	if in.EHBP != nil {
		ev["ehbp"] = in.EHBP
	}
	if in.GPU.Bundle != nil {
		ev["gpu_evidence"] = in.GPU.Bundle
		ev["gpu_evidence_ref"] = "nras-eat-bundle"
		if in.GPU.FreshAt != "" {
			ev["gpu_evidence_fresh_at"] = in.GPU.FreshAt
		}
		if in.GPU.Stale {
			// Serving stale GPU evidence is deliberate (availability), but
			// the client must see it and fail its freshness policy.
			ev["gpu_evidence_stale"] = true
		}
	}
	if in.Dev {
		// Synthetic evidence for local development. A verifier must reject
		// any evidence carrying this flag in production policy.
		ev["dev"] = true
	}
	return ev
}

// AttestationStateDigest identifies the proxy's current attestation state:
// workload identity, TLS SPKI, receipt key, and GPU evidence freshness. WP-7
// per-request receipts cite it as attestation_binding.evidence_digest, so a
// client can tell under which attestation epoch a receipt was minted — the
// digest changes on cert/key rotation, policy or digest changes, and GPU
// evidence freshness flips. It is deliberately NOT a per-request evidence
// digest (no nonce, no quote): per-request freshness comes from the TDX
// quote at /attestation, per-request binding from the receipt hashes.
//
// The routine GPU evidence refresh timestamp (fresh_at) is deliberately
// excluded: it rotates on every collector round (default 300s) and would roll
// the attestation epoch under clients holding cached proofs. Epoch changes
// remain signaled by gpu_evidence_present / gpu_evidence_stale transitions.
func AttestationStateDigest(w Workload, runtimeDigest, tlsSPKIHash, receiptKID, ehbpPublicKeySHA256 string, gpu GPUEvidence) (string, error) {
	state := map[string]any{
		"compose_digest":         w.ComposeDigest,
		"model_digest":           w.ModelDigest,
		"model_id":               w.ModelID,
		"policy_id":              w.PolicyID,
		"proxy_version":          w.ProxyVersion,
		"runtime_digest":         runtimeDigest,
		"tls_spki_sha256":        tlsSPKIHash,
		"receipt_kid":            receiptKID,
		"ehbp_public_key_sha256": ehbpPublicKeySHA256,
		"gpu_evidence_present":   gpu.Bundle != nil,
		"gpu_evidence_stale":     gpu.Stale,
	}
	return canonjson.Digest(state)
}
