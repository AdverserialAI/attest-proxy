package entitlement

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func testToken(t *testing.T, private ed25519.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": kid, "typ": "JWT"})
	p, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(input)))
}

func TestValidateAndConsume(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_760_000_000, 0)
	spki := "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	claims := map[string]any{
		"iss": "https://billing.adverserial.ai", "aud": "https://api.adverserial.ai", "typ": "adverserial-confidential-entitlement/v1",
		"jti": "reservation-1", "model": "lordx64/cyberglm", "max_input_tokens": 1024, "max_output_tokens": 64, "max_requests": 1,
		"cnf": map[string]string{"tls_spki_sha256": spki}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	}
	v := Validator{Keys: map[string]ed25519.PublicKey{"billing-1": pub}, Issuer: "https://billing.adverserial.ai", Audience: "https://api.adverserial.ai", Now: func() time.Time { return now }}
	got, err := v.Validate(testToken(t, private, "billing-1", claims), "lordx64/cyberglm", spki, 512, 64)
	if err != nil {
		t.Fatal(err)
	}
	s := UsedStore{Dir: filepath.Join(t.TempDir(), "used")}
	if ok, err := s.Consume(got); err != nil || !ok {
		t.Fatalf("first consume = %v, %v", ok, err)
	}
	if ok, err := s.Consume(got); err != nil || ok {
		t.Fatalf("replay consume = %v, %v", ok, err)
	}
}

func TestValidateRejectsMismatchAndBounds(t *testing.T) {
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_760_000_000, 0)
	spki := "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	claims := map[string]any{"iss": "issuer", "aud": "aud", "typ": "adverserial-confidential-entitlement/v1", "jti": "r", "model": "lordx64/cyberglm", "max_input_tokens": 10, "max_output_tokens": 2, "max_requests": 1, "cnf": map[string]string{"tls_spki_sha256": spki}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
	v := Validator{Keys: map[string]ed25519.PublicKey{"k": pub}, Issuer: "issuer", Audience: "aud", Now: func() time.Time { return now }}
	token := testToken(t, private, "k", claims)
	for _, tc := range []struct {
		model, pin string
		in, out    int
	}{{"lordx64/cyberkimi", spki, 1, 1}, {"lordx64/cyberglm", "sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", 1, 1}, {"lordx64/cyberglm", spki, 11, 1}, {"lordx64/cyberglm", spki, 1, 3}} {
		if _, err := v.Validate(token, tc.model, tc.pin, tc.in, tc.out); err == nil {
			t.Errorf("case %+v unexpectedly accepted", tc)
		}
	}
}

func TestParseJWKS(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	raw := `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}]}`
	keys, err := ParseJWKS(raw)
	if err != nil || len(keys) != 1 {
		t.Fatalf("ParseJWKS = %v, %v", keys, err)
	}
	if _, err := ParseJWKS(`{"keys":[]}`); err == nil {
		t.Error("empty JWKS accepted")
	}
}
