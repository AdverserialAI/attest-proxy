package receipt

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

// TestMintRoundTrip verifies a receipt exactly the way the browser client
// does in verification.ts: split the compact JWS, check alg/kid, import the
// published JWK, verify ES256 (SHA-256, raw R||S) over the signing input.
func TestMintRoundTrip(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	claims := map[string]any{
		"iss":             "https://verify.adverserial.ai",
		"aud":             "chat.adverserial.ai",
		"nonce":           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"verdict":         "verified",
		"iat":             int64(1759999000),
		"exp":             int64(1759999300),
		"evidence_sha256": "sha256:1mKIEeUwRHV8oq766icqSY6A6QMdHXwqSaAXSM5enLs",
		"model_id":        "lordx64/cyberglm",
		"endpoint":        "https://api.adverserial.ai",
	}
	jws, err := signer.Mint(claims)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	parts := strings.Split(jws, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		t.Fatalf("not a compact JWS: %q", jws)
	}

	// Header: alg ES256, kid = thumbprint, and kid must match the JWK's kid.
	var header map[string]any
	mustDecodeB64JSON(t, parts[0], &header)
	if header["alg"] != "ES256" {
		t.Errorf("alg = %v", header["alg"])
	}
	kid, _ := header["kid"].(string)
	if kid == "" || kid != signer.KeyID() {
		t.Errorf("kid = %q, want %q", kid, signer.KeyID())
	}

	// The published JWK round-trips back to a verifying public key.
	pub, err := ParsePublicJWK(signer.PublicJWK())
	if err != nil {
		t.Fatalf("ParsePublicJWK: %v", err)
	}
	if Thumbprint(pub) != kid {
		t.Errorf("JWK thumbprint mismatch: %q vs %q", Thumbprint(pub), kid)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("signature not base64url: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("ES256 signature must be raw R||S (64 bytes), got %d", len(sig))
	}
	r := new(big.Int).SetBytes(sig[:32])
	ss := new(big.Int).SetBytes(sig[32:])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, digest[:], r, ss) {
		t.Fatal("signature does not verify with the published JWK")
	}

	// Claims round-trip with the expected values.
	var gotClaims map[string]any
	mustDecodeB64JSON(t, parts[1], &gotClaims)
	for k, want := range claims {
		// JSON numbers decode as float64; normalize for comparison.
		if w, ok := want.(int64); ok {
			if gotClaims[k] != float64(w) {
				t.Errorf("claim %s = %v, want %v", k, gotClaims[k], want)
			}
			continue
		}
		if gotClaims[k] != want {
			t.Errorf("claim %s = %v, want %v", k, gotClaims[k], want)
		}
	}
}

// TestTamperedReceiptFails: flipping a payload byte must break verification,
// as must signing with a different key.
func TestSignerFromSeedIsStableAndValid(t *testing.T) {
	seed := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	first, err := NewSignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewSignerFromSeed("p256:" + seed)
	if err != nil {
		t.Fatal(err)
	}
	if first.KeyID() != second.KeyID() {
		t.Fatalf("stable seed yielded different key IDs: %q vs %q", first.KeyID(), second.KeyID())
	}
	if _, err := NewSignerFromSeed("not-a-seed"); err == nil {
		t.Fatal("invalid receipt seed unexpectedly accepted")
	}
}

func TestTamperedReceiptFails(t *testing.T) {
	signer, _ := NewSigner()
	other, _ := NewSigner()
	jws, err := signer.Mint(map[string]any{"verdict": "verified"})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jws, ".")

	pub, _ := ParsePublicJWK(signer.PublicJWK())
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	r := new(big.Int).SetBytes(sig[:32])
	ss := new(big.Int).SetBytes(sig[32:])

	tampered := parts[0] + "." + parts[1][:len(parts[1])-2] + "AA"
	d := sha256.Sum256([]byte(tampered))
	if ecdsa.Verify(pub, d[:], r, ss) {
		t.Fatal("tampered payload verified")
	}

	d = sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	otherPub, _ := ParsePublicJWK(other.PublicJWK())
	if ecdsa.Verify(otherPub, d[:], r, ss) {
		t.Fatal("signature verified under wrong key")
	}
}

// TestKeyIDRFC7638Vector checks the thumbprint against the RFC 7515
// Appendix A-3 P-256 JWK, whose RFC 7638 thumbprint is known.
func TestKeyIDRFC7638Vector(t *testing.T) {
	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
		"y":   "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
	}
	pub, err := ParsePublicJWK(jwk)
	if err != nil {
		t.Fatalf("ParsePublicJWK: %v", err)
	}
	const want = "qT5yKRo0isoECLGe0-hJJux4iMROawVfs8LFcQ2Aveo"
	if got := Thumbprint(pub); got != want {
		t.Fatalf("thumbprint = %q, want %q", got, want)
	}
}

// TestPublicKeyDER parses back through x509 like an SPKI-binding verifier.
func TestPublicKeyDER(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	pubAny, err := x509.ParsePKIXPublicKey(signer.PublicKeyDER())
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("DER decoded to %T, want *ecdsa.PublicKey", pubAny)
	}
	fromJWK, _ := ParsePublicJWK(signer.PublicJWK())
	if !pub.Equal(fromJWK) {
		t.Fatal("DER and JWK publish different public keys")
	}
}

func mustDecodeB64JSON(t *testing.T, s string, v any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url decode: %v", err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("json decode: %v", err)
	}
}
