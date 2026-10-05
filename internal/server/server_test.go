package server

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/adverserial/attest-proxy/internal/attestation"
	"github.com/adverserial/attest-proxy/internal/canonjson"
	"github.com/adverserial/attest-proxy/internal/config"
	"github.com/adverserial/attest-proxy/internal/receipt"
	ehbpclient "github.com/tinfoilsh/encrypted-http-body-protocol/client"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

// newTestServer builds a DEV_MODE server with deterministic keys.
func newTestServer(t *testing.T, cfg config.Config, ehbpIdentity ...*ehbpidentity.Identity) (*Server, *httptest.Server) {
	t.Helper()
	signer, err := receipt.NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	cert, _, err := GenerateSelfSigned([]string{"localhost"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	holder, err := NewCertHolder(cert)
	if err != nil {
		t.Fatalf("NewCertHolder: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(cfg, logger, attestation.DevQuoteSource{}, signer, holder, ehbpIdentity...)
	srv.now = func() time.Time { return time.Unix(1759999000, 0) }
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

func TestEHBPReferenceTransportEncryptsBothDirections(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("upstream path = %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"private prompt"`) {
			t.Fatalf("decrypted request not forwarded: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"private answer"}}]}`))
	}))
	t.Cleanup(upstream.Close)

	identity, err := ehbpidentity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.Upstream, cfg.AuthRequired, cfg.EHBPRequired = upstream.URL, false, true
	_, ts := newTestServer(t, cfg, identity)

	transport, err := ehbpclient.NewTransportWithIdentity(identity, ehbpclient.WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: transport}
	request, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/chat/completions", strings.NewReader(`{"model":"lordx64/cyberglm","messages":[{"role":"user","content":"private prompt"}],"stream":false}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(decrypted), "private answer") {
		t.Fatalf("EHBP response = %d %s", response.StatusCode, decrypted)
	}

	fallback, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/chat/completions", strings.NewReader(`{"model":"lordx64/cyberglm"}`))
	if err != nil {
		t.Fatal(err)
	}
	fallback.Header.Set("Content-Type", "application/json")
	fallbackResponse, err := ts.Client().Do(fallback)
	if err != nil {
		t.Fatal(err)
	}
	fallbackResponse.Body.Close()
	if fallbackResponse.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("plaintext fallback status = %d, want %d", fallbackResponse.StatusCode, http.StatusUpgradeRequired)
	}
}

func TestEHBPCORSAllowsAndExposesProtocolHeaders(t *testing.T) {
	cfg := testConfig()
	cfg.CORSAllowOrigin = "https://cc-chat.adverserial.ai"
	_, ts := newTestServer(t, cfg)
	req, err := http.NewRequest(http.MethodOptions, ts.URL+"/v1/chat/completions", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "https://cc-chat.adverserial.ai")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Headers"); !strings.Contains(strings.ToLower(got), "ehbp-encapsulated-key") {
		t.Fatalf("EHBP request header missing from CORS allow list: %q", got)
	}
	if got := resp.Header.Get("Access-Control-Expose-Headers"); !strings.Contains(strings.ToLower(got), "ehbp-response-nonce") {
		t.Fatalf("EHBP response nonce missing from CORS expose list: %q", got)
	}
}

func testConfig() config.Config {
	return config.Config{
		Upstream:        "http://127.0.0.1:1",
		ModelID:         "lordx64/cyberglm",
		PolicyID:        "adverserial-policy/2026-10-dev",
		Endpoint:        "https://api.adverserial.ai",
		PublicBaseURL:   "https://api.adverserial.ai",
		VerificationURL: "https://verify.adverserial.ai",
		ComposeDigest:   "sha256:composedigest",
		ModelDigest:     "sha256:modeldigest",
		RuntimeDigest:   "sha256:runtimedigest",
		ReceiptIssuer:   "https://verify.adverserial.ai",
		ReceiptAudience: "cc-chat.adverserial.ai",
		DevMode:         true,
	}
}

func b64Of(n int) string {
	return base64.RawURLEncoding.EncodeToString(make([]byte, n))
}

// TestNonceValidationMatrix covers WP-3: reject missing, malformed, reused
// (duplicate parameter), and oversized nonces; accept 16–64 raw bytes with or
// without padding.
func TestNonceValidationMatrix(t *testing.T) {
	_, ts := newTestServer(t, testConfig())

	b64 := func(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }
	pad := func(s string) string { return s + "=" }

	cases := []struct {
		name   string
		target string
		method string
		want   int
	}{
		{"missing nonce", "/attestation", http.MethodGet, 400},
		{"empty nonce", "/attestation?nonce=", http.MethodGet, 400},
		{"not base64", "/attestation?nonce=!!!", http.MethodGet, 400},
		{"std base64 plus sign", "/attestation?nonce=ab+cd", http.MethodGet, 400},
		{"std base64 slash", "/attestation?nonce=ab%2Fcd", http.MethodGet, 400},
		{"too short 15B", "/attestation?nonce=" + b64(make([]byte, 15)), http.MethodGet, 400},
		{"min 16B", "/attestation?nonce=" + b64(make([]byte, 16)), http.MethodGet, 200},
		{"typical 32B", "/attestation?nonce=" + b64Of(32), http.MethodGet, 200},
		{"padded 32B", "/attestation?nonce=" + pad(b64Of(32)), http.MethodGet, 200},
		{"max 64B", "/attestation?nonce=" + b64Of(64), http.MethodGet, 200},
		{"oversized 65B", "/attestation?nonce=" + b64Of(65), http.MethodGet, 400},
		{"overlong param", "/attestation?nonce=" + strings.Repeat("A", 200), http.MethodGet, 400},
		{"duplicate nonce", "/attestation?nonce=" + b64Of(32) + "&nonce=" + b64Of(32), http.MethodGet, 400},
		{"POST rejected", "/attestation?nonce=" + b64Of(32), http.MethodPost, 405},
		{"well-known alias", "/.well-known/adverserial-attestation?nonce=" + b64Of(32), http.MethodGet, 200},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, ts.URL+tc.target, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

// attestationResp mirrors the client contract in verification.ts.
type attestationResp struct {
	Evidence            map[string]any `json:"evidence"`
	VerificationReceipt string         `json:"verification_receipt"`
}

// TestAttestationEndToEnd replays the browser verifier's checks against a
// live DEV_MODE response: receipt signature under the published JWK, claim
// values, evidence digest binding, and TDX report_data channel binding.
func TestAttestationEndToEnd(t *testing.T) {
	srv, ts := newTestServer(t, testConfig())

	nonceRaw := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	nonce := base64.RawURLEncoding.EncodeToString(nonceRaw)

	resp, err := http.Get(ts.URL + "/attestation?nonce=" + url.QueryEscape(nonce))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("CORS header = %q, want *", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}

	var body attestationResp
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// --- evidence shape ---
	ev := body.Evidence
	if ev["version"] != float64(1) {
		t.Errorf("version = %v", ev["version"])
	}
	if ev["nonce"] != nonce {
		t.Errorf("nonce echo = %v", ev["nonce"])
	}
	if ev["dev"] != true {
		t.Errorf("dev flag = %v", ev["dev"])
	}
	if state, ok := ev["attestation_state_digest"].(string); !ok || !strings.HasPrefix(state, "sha256:") {
		t.Errorf("attestation_state_digest = %v, want sha256 fingerprint", ev["attestation_state_digest"])
	}
	if ev["gpu_evidence_ref"] != nil {
		t.Errorf("gpu_evidence_ref = %v, want nil placeholder", ev["gpu_evidence_ref"])
	}
	issued, err := time.Parse(time.RFC3339, ev["issued_at"].(string))
	if err != nil {
		t.Fatalf("issued_at: %v", err)
	}
	expires, err := time.Parse(time.RFC3339, ev["expires_at"].(string))
	if err != nil {
		t.Fatalf("expires_at: %v", err)
	}
	if expires.Sub(issued) != receiptTTL {
		t.Errorf("validity window = %v, want %v", expires.Sub(issued), receiptTTL)
	}
	workload, ok := ev["workload"].(map[string]any)
	if !ok {
		t.Fatal("workload missing")
	}
	if workload["model_id"] != "lordx64/cyberglm" ||
		workload["policy_id"] != "adverserial-policy/2026-10-dev" ||
		workload["compose_digest"] != "sha256:composedigest" ||
		workload["model_digest"] != "sha256:modeldigest" ||
		workload["proxy_version"] == "" {
		t.Errorf("workload = %v", workload)
	}

	// tls_spki_sha256 must match the serving certificate's SPKI.
	wantSPKI := attestation.SPKIHash(srv.holder.Leaf())
	if ev["tls_spki_sha256"] != wantSPKI {
		t.Errorf("tls_spki_sha256 = %v, want %v", ev["tls_spki_sha256"], wantSPKI)
	}
	if got, ok := ev["tls_spki_der"].(string); !ok || got == "" {
		t.Errorf("tls_spki_der = %v, want public SPKI DER", got)
	}

	// --- receipt: verify like verification.ts does ---
	jwk, ok := ev["receipt_pubkey_jwk"].(map[string]any)
	if !ok {
		t.Fatal("receipt_pubkey_jwk missing")
	}
	pub, err := receipt.ParsePublicJWK(jwk)
	if err != nil {
		t.Fatalf("ParsePublicJWK: %v", err)
	}

	parts := strings.Split(body.VerificationReceipt, ".")
	if len(parts) != 3 {
		t.Fatalf("receipt is not compact JWS")
	}
	var header, claims map[string]any
	rawHeader, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		t.Fatal(err)
	}
	rawClaims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		t.Fatal(err)
	}
	if header["alg"] != "ES256" || header["kid"] != jwk["kid"] {
		t.Errorf("header = %v, jwk kid = %v", header, jwk["kid"])
	}

	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	rInt := new(big.Int).SetBytes(sig[:32])
	sInt := new(big.Int).SetBytes(sig[32:])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, sum[:], rInt, sInt) {
		t.Fatal("receipt signature invalid under evidence JWK")
	}

	// Claims per the client contract.
	if claims["iss"] != "https://verify.adverserial.ai" ||
		claims["aud"] != "cc-chat.adverserial.ai" ||
		claims["nonce"] != nonce ||
		claims["verdict"] != "verified" ||
		claims["model_id"] != "lordx64/cyberglm" ||
		claims["endpoint"] != "https://api.adverserial.ai" ||
		claims["model_digest"] != "sha256:modeldigest" ||
		claims["runtime_digest"] != "sha256:runtimedigest" {
		t.Errorf("claims = %v", claims)
	}
	if claims["iat"] != float64(1759999000) || claims["exp"] != float64(1759999300) {
		t.Errorf("iat/exp = %v/%v", claims["iat"], claims["exp"])
	}

	// evidence_sha256 = sha256 of the canonicalized evidence, recomputed from
	// the wire representation exactly like the browser does after JSON.parse.
	wantDigest, err := canonjson.Digest(ev)
	if err != nil {
		t.Fatal(err)
	}
	if claims["evidence_sha256"] != wantDigest {
		t.Errorf("evidence_sha256 = %v, want %v", claims["evidence_sha256"], wantDigest)
	}

	// --- TDX report_data channel binding ---
	// report_data = sha256(nonce_raw || tls_spki_der || receipt_spki_der),
	// zero-padded to 64 bytes; the dev quote embeds it verbatim at offset 8.
	wantRD := attestation.ReportData(nonceRaw, srv.holder.Leaf().RawSubjectPublicKeyInfo, srv.signer.PublicKeyDER())
	quoteHex, _ := ev["tdx_quote"].(string)
	if !strings.Contains(quoteHex, hex.EncodeToString(wantRD[:])) {
		t.Errorf("tdx_quote does not embed the expected report_data binding")
	}
	if ev["tdx_event_log"] != "dev-mode-synthetic-event-log" {
		t.Errorf("tdx_event_log = %#v, want published quote replay material", ev["tdx_event_log"])
	}

	// --- signing key is on the curve and matches the kid ---
	derPub, err := x509.ParsePKIXPublicKey(srv.signer.PublicKeyDER())
	if err != nil {
		t.Fatal(err)
	}
	if !derPub.(*ecdsa.PublicKey).Equal(pub) {
		t.Error("receipt_pubkey_jwk does not match the quote-bound signing key")
	}
}

// TestDevModeFlagOmitted when DEV_MODE is off: no dev key in evidence.
// The quote source is still synthetic here (unit test), but the evidence
// must not carry the dev marker unless DEV_MODE is set.
func TestDevModeFlagOmitted(t *testing.T) {
	cfg := testConfig()
	cfg.DevMode = false
	_, ts := newTestServer(t, cfg)

	resp, err := http.Get(ts.URL + "/attestation?nonce=" + b64Of(32))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body attestationResp
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if _, present := body.Evidence["dev"]; present {
		t.Error("evidence must not carry dev flag when DEV_MODE is off")
	}
}

// TestSPKIFollowsActiveCert: the tls_spki_sha256 published in evidence (and
// bound into the quote's report_data) must always describe the certificate
// the TLS server is presenting right now — across an ACME-style renewal swap.
func TestSPKIFollowsActiveCert(t *testing.T) {
	srv, ts := newTestServer(t, testConfig())
	nonce := b64Of(32)

	getSPKI := func() string {
		resp, err := http.Get(ts.URL + "/attestation?nonce=" + nonce)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body attestationResp
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		spki, _ := body.Evidence["tls_spki_sha256"].(string)
		return spki
	}

	first := getSPKI()
	if first != attestation.SPKIHash(srv.holder.Leaf()) {
		t.Fatalf("initial SPKI %q does not match serving cert", first)
	}

	// Simulate an ACME renewal: swap in a fresh certificate.
	newCert, _, err := GenerateSelfSigned([]string{"cc-api.adverserial.ai"})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.holder.Swap(newCert); err != nil {
		t.Fatal(err)
	}

	second := getSPKI()
	if second == first {
		t.Fatal("SPKI did not change after cert swap")
	}
	want := attestation.SPKIHash(srv.holder.Leaf())
	if second != want {
		t.Fatalf("post-swap SPKI %q, want %q", second, want)
	}
}

// TestAttestationWithGPUBundle: when the collector bundle exists, the
// attestation response embeds it (and the receipt digest still matches the
// augmented evidence).
func TestAttestationWithGPUBundle(t *testing.T) {
	dir := t.TempDir()
	bundlePath := dir + "/gpu-evidence.json"
	generatedAt := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	bundle := `{"version":1,"generated_at":"` + generatedAt + `","nonce":"deadbeef",` +
		`"gpus_attested":8,"verdict":"successful","eat_jwts":["eyJ.x.sig0","eyJ.x.sig1"],` +
		`"source":"nv_attestation_sdk remote NRAS"}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.GPUEvidenceFile = bundlePath
	_, ts := newTestServer(t, cfg)

	resp, err := http.Get(ts.URL + "/attestation?nonce=" + b64Of(32))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body attestationResp
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}

	ev := body.Evidence
	if ev["gpu_evidence_ref"] != "nras-eat-bundle" {
		t.Errorf("gpu_evidence_ref = %v", ev["gpu_evidence_ref"])
	}
	if ev["gpu_evidence_fresh_at"] != generatedAt {
		t.Errorf("gpu_evidence_fresh_at = %v", ev["gpu_evidence_fresh_at"])
	}
	if _, stale := ev["gpu_evidence_stale"]; stale {
		t.Error("fresh bundle marked stale")
	}
	gpu, ok := ev["gpu_evidence"].(map[string]any)
	if !ok {
		t.Fatalf("gpu_evidence = %v", ev["gpu_evidence"])
	}
	if gpu["gpus_attested"] != float64(8) || gpu["verdict"] != "successful" {
		t.Errorf("gpu_evidence = %v", gpu)
	}
	jwts, ok := gpu["eat_jwts"].([]any)
	if !ok || len(jwts) != 2 {
		t.Errorf("eat_jwts = %v", gpu["eat_jwts"])
	}

	// The receipt must bind the evidence *including* the GPU bundle.
	parts := strings.Split(body.VerificationReceipt, ".")
	rawClaims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		t.Fatal(err)
	}
	wantDigest, err := canonjson.Digest(ev)
	if err != nil {
		t.Fatal(err)
	}
	if claims["evidence_sha256"] != wantDigest {
		t.Error("evidence_sha256 does not bind the GPU-augmented evidence")
	}
}

// TestRequestReceiptThroughFullHandler: a chat completion through the whole
// server stack yields a WP-7 receipt signed by the same key published in
// /attestation evidence.
func TestRequestReceiptThroughFullHandler(t *testing.T) {
	const respBody = `{"id":"c1","model":"lordx64/cyberglm","usage":{"prompt_tokens":3,"completion_tokens":1}}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(respBody))
	}))
	defer upstream.Close()

	cfg := testConfig()
	cfg.Upstream = upstream.URL
	_, ts := newTestServer(t, cfg)

	// Fetch the attestation to learn the published receipt key.
	attResp, err := http.Get(ts.URL + "/attestation?nonce=" + b64Of(32))
	if err != nil {
		t.Fatal(err)
	}
	var attBody attestationResp
	if err := json.NewDecoder(attResp.Body).Decode(&attBody); err != nil {
		t.Fatal(err)
	}
	attResp.Body.Close()
	jwk, _ := attBody.Evidence["receipt_pubkey_jwk"].(map[string]any)
	pub, err := receipt.ParsePublicJWK(jwk)
	if err != nil {
		t.Fatal(err)
	}

	const reqBody = `{"model":"lordx64/cyberglm","messages":[]}`
	const nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/chat/completions", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-integration-test")
	req.Header.Set("X-Adverserial-Nonce", nonce)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != respBody {
		t.Fatalf("body modified: %s", body)
	}

	jws := resp.Header.Get("X-Adverserial-Receipt")
	if jws == "" {
		t.Fatal("no receipt header")
	}
	parts := strings.Split(jws, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	rInt := new(big.Int).SetBytes(sig[:32])
	sInt := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, sum[:], rInt, sInt) {
		t.Fatal("receipt does not verify against the attestation-published JWK")
	}
	rawClaims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		t.Fatal(err)
	}
	bodySum := sha256.Sum256([]byte(reqBody))
	if claims["request_body_hash"] != "sha256:"+base64.RawURLEncoding.EncodeToString(bodySum[:]) {
		t.Errorf("request_body_hash = %v", claims["request_body_hash"])
	}
	if claims["request_nonce"] != nonce {
		t.Errorf("request_nonce = %v", claims["request_nonce"])
	}
	binding, _ := claims["attestation_binding"].(map[string]any)
	if binding["tls_spki_sha256"] != attBody.Evidence["tls_spki_sha256"] {
		t.Errorf("binding SPKI %v != evidence SPKI %v", binding["tls_spki_sha256"], attBody.Evidence["tls_spki_sha256"])
	}
}
