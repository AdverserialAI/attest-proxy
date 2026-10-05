// Package receipt mints and parses the compact ES256 JWS verification
// receipts defined by the Adverserial confidential-inference protocol.
package receipt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"

	"github.com/adverserial/attest-proxy/internal/canonjson"
)

// Signer holds the in-enclave receipt-signing key (ECDSA P-256).
//
// TODO(v1): generate or unwrap this key via the dstack KMS (/GetKey) and seal
// it to the expected RTMR policy instead of generating ephemeral key material
// at process start.
type Signer struct {
	key *ecdsa.PrivateKey
	kid string
	jwk map[string]any
	der []byte
}

// NewSigner generates a fresh P-256 keypair in process memory.
func NewSigner() (*Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate receipt key: %w", err)
	}
	return NewSignerFromKey(key)
}

// NewSignerFromSeed deterministically derives a P-256 signer from a sealed
// 32-byte base64url seed. The seed must only be supplied through the CVM's
// sealed environment. This makes the receipt public key stable across normal
// restarts and lets the public policy pin it before inference is activated.
func NewSignerFromSeed(encoded string) (*Signer, error) {
	encoded = strings.TrimPrefix(strings.TrimSpace(encoded), "p256:")
	seed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(seed) != 32 {
		return nil, fmt.Errorf("RECEIPT_SIGNING_SEED must be a 32-byte base64url seed")
	}
	curve := elliptic.P256()
	// Map the 256-bit seed into [1, N-1] without ever accepting a zero scalar.
	d := new(big.Int).SetBytes(seed)
	nMinusOne := new(big.Int).Sub(curve.Params().N, big.NewInt(1))
	d.Mod(d, nMinusOne)
	d.Add(d, big.NewInt(1))
	x, y := curve.ScalarBaseMult(d.Bytes())
	return NewSignerFromKey(&ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d})
}

// NewSignerFromKey wraps an existing key (used by tests and, later, KMS
// unsealing).
func NewSignerFromKey(key *ecdsa.PrivateKey) (*Signer, error) {
	pub := key.Public().(*ecdsa.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal receipt pubkey: %w", err)
	}
	kid := Thumbprint(pub)
	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   b64url(pad32(pub.X)),
		"y":   b64url(pad32(pub.Y)),
		"kid": kid,
	}
	return &Signer{key: key, kid: kid, jwk: jwk, der: der}, nil
}

// KeyID is the RFC 7638 JWK SHA-256 thumbprint of the public key.
func (s *Signer) KeyID() string { return s.kid }

// PublicJWK returns the public JWK published in attestation evidence as
// receipt_pubkey_jwk. Clients pin it via their trusted_receipt_keys config.
func (s *Signer) PublicJWK() map[string]any {
	out := make(map[string]any, len(s.jwk))
	for k, v := range s.jwk {
		out[k] = v
	}
	return out
}

// PublicKeyDER is the PKIX SubjectPublicKeyInfo DER of the signing key; it is
// bound into the TDX report_data alongside the TLS SPKI.
func (s *Signer) PublicKeyDER() []byte { return s.der }

// Mint produces a compact JWS (header.payload.signature) over the given
// claims. The ES256 signature is the fixed-width R||S concatenation (64
// bytes), not ASN.1 — per RFC 7518 §3.4.
func (s *Signer) Mint(claims map[string]any) (string, error) {
	header, err := canonjson.String(map[string]any{
		"alg": "ES256",
		"kid": s.kid,
		"typ": "JWT",
	})
	if err != nil {
		return "", err
	}
	payload, err := canonjson.String(claims)
	if err != nil {
		return "", err
	}
	input := b64url([]byte(header)) + "." + b64url([]byte(payload))
	digest := sha256.Sum256([]byte(input))
	r, ss, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign receipt: %w", err)
	}
	sig := append(pad32(r), pad32(ss)...)
	return input + "." + b64url(sig), nil
}

// Thumbprint computes the RFC 7638 JWK SHA-256 thumbprint of a P-256 public
// key, base64url-encoded without padding.
func Thumbprint(pub *ecdsa.PublicKey) string {
	// RFC 7638 §3.1: required members in lexicographic order, no whitespace.
	canonical := `{"crv":"P-256","kty":"EC","x":"` + b64url(pad32(pub.X)) + `","y":"` + b64url(pad32(pub.Y)) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ParsePublicJWK reconstructs a P-256 public key from a JWK map — the inverse
// of PublicJWK, used by verifiers.
func ParsePublicJWK(jwk map[string]any) (*ecdsa.PublicKey, error) {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)
	xs, _ := jwk["x"].(string)
	ys, _ := jwk["y"].(string)
	if kty != "EC" || crv != "P-256" {
		return nil, fmt.Errorf("unsupported JWK kty/crv %q/%q", kty, crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(xs)
	if err != nil {
		return nil, fmt.Errorf("JWK x: %w", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(ys)
	if err != nil {
		return nil, fmt.Errorf("JWK y: %w", err)
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, fmt.Errorf("JWK point not on P-256")
	}
	return pub, nil
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// pad32 returns the big-endian encoding of i zero-padded to 32 bytes.
func pad32(i *big.Int) []byte {
	out := make([]byte, 32)
	b := i.Bytes()
	copy(out[32-len(b):], b)
	return out
}
