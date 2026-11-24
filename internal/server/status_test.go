package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/adverserial/attest-proxy/internal/attestation"
	"github.com/adverserial/attest-proxy/internal/buildinfo"
	"github.com/adverserial/attest-proxy/internal/canonjson"
	"github.com/adverserial/attest-proxy/internal/config"
	"github.com/adverserial/attest-proxy/internal/receipt"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

const testUpstreamToken = "upstream-token-0123456789abcdefghijklmnop"

// confidentialTestConfig is a complete confidential configuration against a
// local upstream, with direct-signed metering so no mTLS files are needed.
func confidentialTestConfig(t *testing.T, upstreamURL string) config.Config {
	t.Helper()
	cfg := testConfig()
	cfg.Upstream = upstreamURL
	cfg.ConfidentialMode = true
	cfg.ConfidentialActivation = "active"
	cfg.EntitlementJWKS = `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}`
	cfg.EntitlementReplayDir = t.TempDir()
	cfg.MeterOutboxDir = t.TempDir()
	cfg.MeterURL = "https://billing.adverserial.ai"
	cfg.MeterDeliveryMode = "direct-signed"
	cfg.MeterIngressSecret = "test-ingress"
	cfg.EHBPRequired = true
	return cfg
}

func getJSON(t *testing.T, url string) (int, map[string]any, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	return resp.StatusCode, doc, string(raw)
}

type countingQuotes struct{ calls atomic.Int32 }

func (c *countingQuotes) Quote(ctx context.Context, reportData [64]byte) (attestation.Quote, error) {
	c.calls.Add(1)
	return attestation.DevQuoteSource{}.Quote(ctx, reportData)
}

func TestIngressLimit(t *testing.T) {
	if maxConfidentialIngress != 48 {
		t.Fatalf("maxConfidentialIngress = %d, want 48", maxConfidentialIngress)
	}
	srv, _ := newTestServer(t, testConfig())
	if cap(srv.ingressSlots) != 48 {
		t.Fatalf("ingress slots = %d, want 48", cap(srv.ingressSlots))
	}
}

func TestMeterJWKSPublishesTheMeterKey(t *testing.T) {
	identity, _ := ehbpidentity.NewIdentity()
	srv, ts := newTestServer(t, confidentialTestConfig(t, "http://127.0.0.1:1"), identity)

	code, doc, _ := getJSON(t, ts.URL+meterJWKSPath)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	keys, _ := doc["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("JWKS has %d keys, want 1", len(keys))
	}
	jwk, _ := keys[0].(map[string]any)
	for k, want := range srv.meterSigner.PublicJWK() {
		if jwk[k] != want {
			t.Errorf("jwk[%s] = %v, want %v", k, jwk[k], want)
		}
	}
	if _, private := jwk["d"]; private {
		t.Fatal("JWKS exposes a private member")
	}
	// The published key verifies what the signer signs.
	x, _ := base64.RawURLEncoding.DecodeString(jwk["x"].(string))
	token, _, err := buildTestMeterEvent(srv)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if !ed25519.Verify(ed25519.PublicKey(x), []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("meter event does not verify against the published JWK")
	}

	resp, err := http.Post(ts.URL+meterJWKSPath, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST = %d, want 405", resp.StatusCode)
	}

	// Without a meter key (non-confidential) the set is empty, not an error.
	_, plain := newTestServer(t, testConfig())
	code, doc, _ = getJSON(t, plain.URL+meterJWKSPath)
	if keys, _ := doc["keys"].([]any); code != http.StatusOK || len(keys) != 0 {
		t.Errorf("non-confidential JWKS = %d %v", code, doc)
	}
}

func TestStatuszReportsStateWithoutSecrets(t *testing.T) {
	// The upstream only reports healthy to the VM-internal credential, so
	// upstream_ready also proves the probe reads the bearer source.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" && r.Header.Get("Authorization") == "Bearer "+testUpstreamToken {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	statusFile := filepath.Join(t.TempDir(), "status.json")
	status := map[string]any{
		"ladder_id":  "ladder-7",
		"rung":       3,
		"phase":      "loading weights <script>alert(1)</script>",
		"attempt":    true,
		"started_at": "2026-11-24T10:00:00Z",
		"updated_at": "2026-11-24T10:05:00+00:00",
		"detail":     strings.Repeat("x", 500),
		"token":      testUpstreamToken,
		"prompt":     "user text that must never be served",
	}
	raw, _ := json.Marshal(status)
	if err := os.WriteFile(statusFile, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := confidentialTestConfig(t, upstream.URL)
	cfg.InferenceStatusFile = statusFile
	identity, _ := ehbpidentity.NewIdentity()
	signer, _ := receipt.NewSigner()
	cert, _, _ := GenerateSelfSigned([]string{"localhost"})
	holder, _ := NewCertHolder(cert)
	srv := New(cfg, discardLogger(), attestation.DevQuoteSource{}, signer, holder, identity)
	meterSigner := newMeterSigner(t)
	srv.Configure(Options{MeterSigner: meterSigner, KeysOrigin: "enclave-generated", UpstreamBearer: func() string { return testUpstreamToken }})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	var doc map[string]any
	var body string
	deadline := time.Now().Add(10 * time.Second)
	for {
		var code int
		code, doc, body = getJSON(t, ts.URL+statuszPath)
		if code != http.StatusOK {
			t.Fatalf("status = %d", code)
		}
		if doc["upstream_ready"] == true || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if doc["upstream_ready"] != true {
		t.Error("upstream_ready never became true (probe did not present the credential)")
	}
	for k, want := range map[string]any{
		"version":                buildinfo.Version,
		"keys_origin":            "enclave-generated",
		"receipt_kid":            signer.KeyID(),
		"meter_kid":              meterSigner.KeyID(),
		"meter_jwk_thumbprint":   meterSigner.Thumbprint(),
		"ehbp_public_key_sha256": srv.ehbpPublicKeySHA256(),
	} {
		if doc[k] != want {
			t.Errorf("statusz[%s] = %v, want %v", k, doc[k], want)
		}
	}
	if started, err := time.Parse(time.RFC3339, doc["started_at"].(string)); err != nil || time.Since(started) > time.Minute {
		t.Errorf("started_at = %v (%v)", doc["started_at"], err)
	}
	ingress, _ := doc["ingress"].(map[string]any)
	if ingress["in_use"] != float64(0) || ingress["max"] != float64(48) {
		t.Errorf("ingress = %v", ingress)
	}
	srv.ingressSlots <- struct{}{}
	_, doc2, _ := getJSON(t, ts.URL+statuszPath)
	<-srv.ingressSlots
	if doc2["ingress"].(map[string]any)["in_use"] != float64(1) {
		t.Errorf("ingress in_use did not track an occupied slot: %v", doc2["ingress"])
	}

	inference, _ := doc["inference"].(map[string]any)
	want := map[string]string{
		"ladder_id":  "ladder-7",
		"rung":       "3",
		"phase":      "loading weights ?script?alert?1??/script?",
		"attempt":    "true",
		"started_at": "2026-11-24T10:00:00Z",
		"updated_at": "2026-11-24T10:05:00+00:00",
		"detail":     strings.Repeat("x", 200),
	}
	if len(inference) != len(want) {
		t.Errorf("inference carries %d fields, want exactly the %d whitelisted: %v", len(inference), len(want), inference)
	}
	for k, v := range want {
		if inference[k] != v {
			t.Errorf("inference[%s] = %q, want %q", k, inference[k], v)
		}
	}
	for _, secret := range []string{testUpstreamToken, "user text", "test-ingress", "<script>"} {
		if strings.Contains(body, secret) {
			t.Errorf("statusz leaks %q", secret)
		}
	}

	resp, err := http.Post(ts.URL+statuszPath, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /statusz = %d, want 405", resp.StatusCode)
	}
}

func TestReadInferenceStatusIsDefensive(t *testing.T) {
	dir := t.TempDir()
	write := func(content string) string {
		path := filepath.Join(dir, "s.json")
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if readInferenceStatus("") != nil || readInferenceStatus(filepath.Join(dir, "absent")) != nil {
		t.Error("unset or missing file produced a status")
	}
	for name, content := range map[string]string{
		"not json":  "phase=loading",
		"array":     `["phase"]`,
		"oversized": `{"phase":"` + strings.Repeat("a", maxInferenceStatusBytes) + `"}`,
		"truncated": `{"phase":"load`,
	} {
		if got := readInferenceStatus(write(content)); got != nil {
			t.Errorf("%s: produced %v", name, got)
		}
	}
	got := readInferenceStatus(write(`{"phase":"a\nb\u0000c\"d","rung":null,"detail":{"k":[1,"v"]},"other":"x","attempt":1.5}`))
	want := map[string]any{"phase": "a?b?c?d", "detail": "??k?:?1,?v???", "attempt": "1.5"}
	if len(got) != len(want) {
		t.Fatalf("status = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("status[%s] = %q, want %q", k, got[k], v)
		}
	}
	if s := sanitizeStatusValue(strings.Repeat("é", 300)); s != strings.Repeat("?", 200) {
		t.Errorf("non-ASCII not replaced or not capped at 200 characters (%d)", len(s))
	}
	if s := sanitizeStatusValue("AZaz09 _.:,=/+-"); s != "AZaz09 _.:,=/+-" {
		t.Errorf("allowed alphabet altered: %q", s)
	}
}

func TestKeyAttestationBindsEveryKeyToAQuote(t *testing.T) {
	identity, _ := ehbpidentity.NewIdentity()
	cfg := confidentialTestConfig(t, "http://127.0.0.1:1")
	cfg.DevMode = false
	srv, ts := newTestServer(t, cfg, identity)
	quotes := &countingQuotes{}
	srv.quotes = quotes
	clock := time.Unix(1759999000, 0)
	srv.now = func() time.Time { return clock }

	code, doc, first := getJSON(t, ts.URL+keyAttestationPath)
	if code != http.StatusOK {
		t.Fatalf("status = %d body = %s", code, first)
	}
	statement, _ := doc["statement"].(string)
	quoteHex, _ := doc["quote"].(string)
	if statement == "" || quoteHex == "" || doc["event_log"] == nil {
		t.Fatalf("incomplete key attestation: %s", first)
	}

	// report_data = SHA-512("adverserial-key-attestation-v1\n" || statement).
	quote, err := hex.DecodeString(quoteHex)
	if err != nil {
		t.Fatal(err)
	}
	want := sha512.Sum512([]byte("adverserial-key-attestation-v1\n" + statement))
	if got := quote[8 : 8+64]; string(got) != string(want[:]) {
		t.Fatal("quote report_data is not SHA-512(domain || statement)")
	}

	var st map[string]any
	if err := json.Unmarshal([]byte(statement), &st); err != nil {
		t.Fatalf("statement is not JSON: %v", err)
	}
	// The statement is canonical JSON: re-canonicalizing reproduces its bytes.
	if canonical, err := canonjson.String(st); err != nil || canonical != statement {
		t.Errorf("statement is not canonical JSON (%v)", err)
	}
	leafSPKI := attestation.SPKIHash(srv.holder.Leaf())
	ehbpSum := sha256.Sum256(identity.MarshalPublicKey())
	for k, want := range map[string]any{
		"type":                   "adverserial-key-attestation/v1",
		"keys_origin":            "enclave-generated",
		"proxy_version":          buildinfo.Version,
		"issued_at":              clock.UTC().Format(time.RFC3339),
		"tls_spki_sha256":        leafSPKI,
		"ehbp_public_key":        base64.RawURLEncoding.EncodeToString(identity.MarshalPublicKey()),
		"ehbp_public_key_sha256": "sha256:" + base64.RawURLEncoding.EncodeToString(ehbpSum[:]),
	} {
		if st[k] != want {
			t.Errorf("statement[%s] = %v, want %v", k, st[k], want)
		}
	}
	receiptJWK, _ := st["receipt_pubkey_jwk"].(map[string]any)
	if receiptJWK["kid"] != srv.signer.KeyID() || receiptJWK["x"] != srv.signer.PublicJWK()["x"] {
		t.Errorf("statement receipt key = %v", receiptJWK)
	}
	meterJWK, _ := st["meter_pubkey_jwk"].(map[string]any)
	if meterJWK["kid"] != srv.meterSigner.KeyID() || meterJWK["x"] != srv.meterSigner.PublicJWK()["x"] {
		t.Errorf("statement meter key = %v", meterJWK)
	}
	if _, dev := st["dev"]; dev {
		t.Error("production statement carries dev flag")
	}
	for _, jwk := range []map[string]any{receiptJWK, meterJWK} {
		if _, private := jwk["d"]; private {
			t.Fatal("statement exposes a private JWK member")
		}
	}

	// Cached: repeated calls inside the window reuse the quote.
	for i := 0; i < 5; i++ {
		clock = clock.Add(10 * time.Second)
		if _, _, again := getJSON(t, ts.URL+keyAttestationPath); again != first {
			t.Fatal("key attestation changed inside the cache window")
		}
	}
	if quotes.calls.Load() != 1 {
		t.Fatalf("quote generated %d times inside the cache window, want 1", quotes.calls.Load())
	}
	// Expired: a fresh statement and quote.
	clock = clock.Add(20 * time.Second)
	_, _, later := getJSON(t, ts.URL+keyAttestationPath)
	if later == first || quotes.calls.Load() != 2 {
		t.Fatalf("key attestation not refreshed after the cache window (quotes=%d)", quotes.calls.Load())
	}
	// A rotated serving certificate invalidates the cache immediately.
	cert, _, _ := GenerateSelfSigned([]string{"localhost"})
	if err := srv.holder.Swap(cert); err != nil {
		t.Fatal(err)
	}
	_, rotated, _ := getJSON(t, ts.URL+keyAttestationPath)
	var rotatedStatement map[string]any
	_ = json.Unmarshal([]byte(rotated["statement"].(string)), &rotatedStatement)
	if rotatedStatement["tls_spki_sha256"] == leafSPKI || quotes.calls.Load() != 3 {
		t.Error("key attestation served a stale TLS key after certificate rotation")
	}

	resp, err := http.Post(ts.URL+keyAttestationPath, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST = %d, want 405", resp.StatusCode)
	}
}

// The key attestation is additive: /attestation still binds
// SHA-256("adverserial-attestation-v2\0" || nonce || tls || receipt || ehbp)
// followed by 32 zero bytes, which a deployed verifier depends on.
func TestKeyAttestationLeavesAttestationReportDataUnchanged(t *testing.T) {
	identity, _ := ehbpidentity.NewIdentity()
	srv, ts := newTestServer(t, confidentialTestConfig(t, "http://127.0.0.1:1"), identity)
	if code, _, body := getJSON(t, ts.URL+keyAttestationPath); code != http.StatusOK {
		t.Fatalf("key attestation = %d %s", code, body)
	}
	nonceRaw := []byte("0123456789abcdef0123456789abcdef")
	code, doc, body := getJSON(t, ts.URL+"/attestation?nonce="+base64.RawURLEncoding.EncodeToString(nonceRaw))
	if code != http.StatusOK {
		t.Fatalf("attestation = %d %s", code, body)
	}
	evidence := doc["evidence"].(map[string]any)
	quote, _ := hex.DecodeString(evidence["tdx_quote"].(string))
	h := sha256.New()
	h.Write([]byte("adverserial-attestation-v2\x00"))
	h.Write(nonceRaw)
	h.Write(srv.holder.Leaf().RawSubjectPublicKeyInfo)
	h.Write(srv.signer.PublicKeyDER())
	h.Write(identity.MarshalPublicKey())
	want := append(h.Sum(nil), make([]byte, 32)...)
	if string(quote[8:8+64]) != string(want) {
		t.Fatal("/attestation report_data format changed")
	}
	for _, field := range []string{"version", "nonce", "issued_at", "expires_at", "tdx_quote", "tdx_event_log", "tls_spki_sha256", "tls_spki_der", "receipt_pubkey_jwk", "attestation_state_digest", "workload", "gpu_evidence", "gpu_evidence_ref", "ehbp"} {
		if _, ok := evidence[field]; !ok {
			t.Errorf("/attestation evidence lost field %q", field)
		}
	}
	if len(evidence) != 15 { // the 14 above plus dev (testConfig runs DEV_MODE)
		t.Errorf("/attestation evidence has %d fields, want 15: a field was added or removed", len(evidence))
	}
}

// The confidential edge exposes exactly the new public GET routes and still
// 404s everything else outside the metered inference allowlist.
func TestConfidentialEdgeExposesOnlyTheNewPublicRoutes(t *testing.T) {
	identity, _ := ehbpidentity.NewIdentity()
	_, ts := newTestServer(t, confidentialTestConfig(t, "http://127.0.0.1:1"), identity)
	for _, path := range []string{statuszPath, meterJWKSPath, keyAttestationPath, "/healthz"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, resp.StatusCode)
		}
		if path != "/healthz" && resp.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("GET %s lacks the public-evidence CORS header", path)
		}
	}
	for _, path := range []string{
		"/statusz/", "/statusz/x", "/status", "/metrics", "/debug/pprof/", "/debug/vars",
		"/.well-known/adverserial-meter-jwks.json/", "/.well-known/adverserial-meter-jwks",
		"/.well-known/adverserial-key-attestation/x", "/.well-known/jwks.json",
		"/get_server_info", "/flush_cache", "/health", "/v1/completions",
	} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestConfidentialHandlerRequiresEnclaveMeterKey(t *testing.T) {
	identity, _ := ehbpidentity.NewIdentity()
	signer, _ := receipt.NewSigner()
	cert, _, _ := GenerateSelfSigned([]string{"localhost"})
	holder, _ := NewCertHolder(cert)
	srv := New(confidentialTestConfig(t, "http://127.0.0.1:1"), discardLogger(), attestation.DevQuoteSource{}, signer, holder, identity)
	defer func() {
		if recover() == nil {
			t.Fatal("confidential handler built without an enclave meter key")
		}
	}()
	srv.Handler()
}
