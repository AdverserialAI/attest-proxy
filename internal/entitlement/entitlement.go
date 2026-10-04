// Package entitlement validates the bounded, single-use authorization tokens
// issued by billing for confidential inference. A client API key must never
// cross the CVM boundary; this package accepts only a billing-signed JWS.
package entitlement

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var canonicalModelID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}/[a-z0-9][a-z0-9._-]{0,127}$`)
var fingerprint = regexp.MustCompile(`^sha256:[A-Za-z0-9_-]{43}$`)

// Claims is the exact v1 entitlement contract. It deliberately contains no
// user identity, platform API key, prompt, completion, or billing balance.
type Claims struct {
	Issuer          string `json:"iss"`
	Audience        string `json:"aud"`
	Type            string `json:"typ"`
	ID              string `json:"jti"`
	Model           string `json:"model"`
	MaxInputTokens  int    `json:"max_input_tokens"`
	MaxOutputTokens int    `json:"max_output_tokens"`
	MaxRequests     int    `json:"max_requests"`
	Confirmation    struct {
		TLSSPKISHA256 string `json:"tls_spki_sha256"`
	} `json:"cnf"`
	IssuedAt int64 `json:"iat"`
	Expires  int64 `json:"exp"`
}

// Validator has only public billing keys and validates a request locally.
// It must not perform a network lookup on the inference prompt path.
type Validator struct {
	Keys     map[string]ed25519.PublicKey
	Issuer   string
	Audience string
	Now      func() time.Time // test hook
}

// ParseJWKS reads a compact Ed25519 JWK set. Any unexpected key type or an
// empty/duplicate key set is a configuration error.
func ParseJWKS(raw string) (map[string]ed25519.PublicKey, error) {
	var doc struct {
		Keys []struct {
			KTY string `json:"kty"`
			CRV string `json:"crv"`
			KID string `json:"kid"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, fmt.Errorf("decode entitlement JWKS: %w", err)
	}
	out := make(map[string]ed25519.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.KTY != "OKP" || k.CRV != "Ed25519" || k.KID == "" || k.X == "" {
			return nil, fmt.Errorf("entitlement JWKS contains an unsupported key")
		}
		if _, exists := out[k.KID]; exists {
			return nil, fmt.Errorf("entitlement JWKS contains duplicate kid %q", k.KID)
		}
		b, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("entitlement JWKS contains an invalid Ed25519 key")
		}
		out[k.KID] = ed25519.PublicKey(b)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("entitlement JWKS is empty")
	}
	return out, nil
}

// Validate verifies the compact JWS, its v1 contract, the channel-binding
// fingerprint, and all request bounds. expectedSPKI must be obtained from the
// currently active in-enclave TLS certificate, never from client input.
func (v Validator) Validate(token, requestedModel, expectedSPKI string, requestByteUpperBound, requestedOutput int) (Claims, error) {
	var zero Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return zero, fmt.Errorf("invalid entitlement encoding")
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &header) != nil || header.Algorithm != "EdDSA" || header.KeyID == "" {
		return zero, fmt.Errorf("invalid entitlement header")
	}
	key := v.Keys[header.KeyID]
	if len(key) != ed25519.PublicKeySize {
		return zero, fmt.Errorf("unknown entitlement signing key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return zero, fmt.Errorf("invalid entitlement signature")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(pb, &zero) != nil {
		return Claims{}, fmt.Errorf("invalid entitlement claims")
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if zero.Issuer != v.Issuer || zero.Audience != v.Audience || zero.Type != "adverserial-confidential-entitlement/v1" {
		return Claims{}, fmt.Errorf("unexpected entitlement authority")
	}
	if zero.IssuedAt > now.Unix()+60 || zero.Expires <= now.Unix() || zero.Expires <= zero.IssuedAt {
		return Claims{}, fmt.Errorf("expired or not-yet-valid entitlement")
	}
	if zero.ID == "" || !canonicalModelID.MatchString(zero.Model) || zero.Model != requestedModel || zero.MaxRequests != 1 || zero.MaxInputTokens < 1 || zero.MaxOutputTokens < 1 {
		return Claims{}, fmt.Errorf("malformed or mismatched entitlement")
	}
	if !fingerprint.MatchString(expectedSPKI) || zero.Confirmation.TLSSPKISHA256 != expectedSPKI {
		return Claims{}, fmt.Errorf("entitlement TLS channel binding mismatch")
	}
	if requestByteUpperBound < 1 || requestByteUpperBound > zero.MaxInputTokens || requestedOutput < 1 || requestedOutput > zero.MaxOutputTokens {
		return Claims{}, fmt.Errorf("request exceeds entitlement bounds")
	}
	return zero, nil
}

// IDHash returns a filesystem-safe opaque identifier. The actual entitlement
// ID is never used as a path or emitted in logs.
func IDHash(id string) string {
	sum := sha256.Sum256([]byte(id))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
