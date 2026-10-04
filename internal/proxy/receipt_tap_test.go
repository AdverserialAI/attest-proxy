package proxy

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/adverserial/attest-proxy/internal/gate"
	"github.com/adverserial/attest-proxy/internal/receipt"
)

// receiptRig boots gate(off) → proxy with usage sink AND receipt config.
type receiptRig struct {
	front  *httptest.Server
	signer *receipt.Signer
	sink   *recordSink
}

func newReceiptRig(t *testing.T, upstream *httptest.Server) *receiptRig {
	t.Helper()
	signer, err := receipt.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	u, _ := url.Parse(upstream.URL)
	sink := newRecordSink()
	tap := &UsageTap{
		Sink:   sink,
		Logger: logger,
		Receipts: &ReceiptConfig{
			Signer:   signer,
			Issuer:   "https://verify.adverserial.ai",
			Audience: "cc-chat.adverserial.ai",
			PolicyID: "adverserial-policy/2026-10-04",
			StateDigest: func() (string, string) {
				return "sha256:testSPKI", "sha256:testStateDigest"
			},
		},
	}
	g := &gate.Gate{Logger: logger, Enforce: false}
	front := httptest.NewServer(Logging(logger, g.Middleware(New(u, logger, nil, tap))))
	t.Cleanup(front.Close)
	return &receiptRig{front: front, signer: signer, sink: sink}
}

// parseAndVerifyReceipt checks the JWS against the rig's published key and
// returns the claims.
func (r *receiptRig) parseAndVerifyReceipt(t *testing.T, jws string) map[string]any {
	t.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("not compact JWS")
	}
	var header map[string]any
	rawHeader, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		t.Fatal(err)
	}
	if header["alg"] != "ES256" || header["kid"] != r.signer.KeyID() {
		t.Errorf("header = %v", header)
	}
	pub, err := receipt.ParsePublicJWK(r.signer.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	rInt := new(big.Int).SetBytes(sig[:32])
	sInt := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], rInt, sInt) {
		t.Fatal("receipt signature invalid")
	}
	var claims map[string]any
	rawClaims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func sha256b64(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

const receiptTestBody = `{"model":"lordx64/cyberglm","messages":[{"role":"user","content":"hi"}]}`
const receiptTestNonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 32 zero bytes

// TestNonStreamReceiptHeader: full claim verification on the header receipt.
func TestNonStreamReceiptHeader(t *testing.T) {
	const respBody = `{"id":"c1","model":"lordx64/cyberglm","choices":[{"message":{"role":"assistant","content":"Hi"}}],"usage":{"prompt_tokens":9,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":4}}}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, respBody)
	}))
	defer upstream.Close()

	rig := newReceiptRig(t, upstream)
	req, _ := http.NewRequest(http.MethodPost, rig.front.URL+"/v1/chat/completions", strings.NewReader(receiptTestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-receipt-test")
	req.Header.Set("X-Adverserial-Nonce", receiptTestNonce)
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
		t.Fatal("X-Adverserial-Receipt header missing")
	}
	claims := rig.parseAndVerifyReceipt(t, jws)

	if claims["v"] != float64(1) ||
		claims["iss"] != "https://verify.adverserial.ai" ||
		claims["aud"] != "cc-chat.adverserial.ai" ||
		claims["request_nonce"] != receiptTestNonce ||
		claims["request_body_hash"] != sha256b64([]byte(receiptTestBody)) ||
		claims["response_hash"] != sha256b64([]byte(respBody)) ||
		claims["model_id"] != "lordx64/cyberglm" ||
		claims["policy_id"] != "adverserial-policy/2026-10-04" {
		t.Errorf("claims = %v", claims)
	}
	binding, _ := claims["attestation_binding"].(map[string]any)
	if binding["tls_spki_sha256"] != "sha256:testSPKI" || binding["evidence_digest"] != "sha256:testStateDigest" {
		t.Errorf("attestation_binding = %v", binding)
	}
	iat, exp := claims["iat"].(float64), claims["exp"].(float64)
	if exp-iat != 120 {
		t.Errorf("exp-iat = %v, want 120", exp-iat)
	}
	usage, _ := claims["usage"].(map[string]any)
	if usage["input_tokens"] != float64(9) || usage["cached_tokens"] != float64(4) || usage["output_tokens"] != float64(5) {
		t.Errorf("usage = %v", usage)
	}

	// Usage tap fired too (same request).
	ev := rig.sink.wait(t)
	if ev.InputTokens != 9 {
		t.Errorf("billing event = %+v", ev)
	}
}

// TestReceiptWrongRequestBody: a different body yields a different
// request_body_hash — the client detects a swapped request.
func TestReceiptWrongRequestBody(t *testing.T) {
	const respBody = `{"usage":{"prompt_tokens":1,"completion_tokens":1}}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, respBody)
	}))
	defer upstream.Close()

	rig := newReceiptRig(t, upstream)
	resp, err := http.Post(rig.front.URL+"/v1/chat/completions", "application/json", strings.NewReader(receiptTestBody))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	claims := rig.parseAndVerifyReceipt(t, resp.Header.Get("X-Adverserial-Receipt"))

	otherBody := `{"model":"lordx64/cyberglm","messages":[{"role":"user","content":"TAMPERED"}]}`
	if claims["request_body_hash"] == sha256b64([]byte(otherBody)) {
		t.Error("request_body_hash matches a tampered body")
	}
	if claims["request_body_hash"] != sha256b64([]byte(receiptTestBody)) {
		t.Error("request_body_hash does not match the sent body")
	}
}

// TestStreamReceiptFinalChunk: the receipt arrives as a final SSE data chunk
// after all upstream content, before the held [DONE]; upstream bytes are
// preserved verbatim and in order; usage tap coexists.
func TestStreamReceiptFinalChunk(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		half := strings.Index(sseBody, `"usage"`) + 3
		for _, part := range []string{sseBody[:half], sseBody[half:]} {
			_, _ = io.WriteString(w, part)
			fl.Flush()
			time.Sleep(15 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	rig := newReceiptRig(t, upstream)
	resp, err := http.Post(rig.front.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"lordx64/cyberglm","stream":true,"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	got := string(body)

	// Structure: upstream content chunks (verbatim, in order), receipt chunk,
	// then the upstream [DONE] last.
	contentEnd := strings.Index(got, "adverserial_receipt")
	if contentEnd < 0 {
		t.Fatalf("no receipt chunk in stream:\n%s", got)
	}
	if !strings.HasPrefix(got, sseBody[:len(sseBody)-len("data: [DONE]\n\n")]) {
		t.Errorf("upstream content not byte-identical before receipt:\n%s", got)
	}
	if !strings.HasSuffix(got, "data: [DONE]\n\n") {
		t.Errorf("stream does not end with upstream [DONE]: %q", got[len(got)-40:])
	}
	if strings.Count(got, "data: [DONE]") != 1 {
		t.Error("[DONE] duplicated or dropped")
	}

	// Extract and verify the receipt chunk.
	var jws string
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "adverserial_receipt") {
			payload := strings.TrimPrefix(line, "data: ")
			var chunk map[string]string
			if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
				t.Fatalf("receipt chunk not JSON: %v", err)
			}
			jws = chunk["adverserial_receipt"]
		}
	}
	if jws == "" {
		t.Fatal("receipt chunk found but unparseable")
	}
	claims := rig.parseAndVerifyReceipt(t, jws)

	// Stream-final hash: concat of upstream data payloads, incl. [DONE].
	h := sha256.New()
	for _, payload := range []string{
		`{"id":"c1","object":"chat.completion.chunk","choices":[{"delta":{"content":"Hel"}}]}`,
		`{"id":"c1","object":"chat.completion.chunk","choices":[{"delta":{"content":"lo"}}]}`,
		`{"id":"c1","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":11,"completion_tokens":2,"prompt_tokens_details":{"cached_tokens":7}}}`,
		"[DONE]",
	} {
		h.Write([]byte(payload))
	}
	want := "sha256:" + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	if claims["response_hash"] != want {
		t.Errorf("response_hash = %v, want %v", claims["response_hash"], want)
	}

	// Usage coexists in both the receipt and the billing event.
	usage, _ := claims["usage"].(map[string]any)
	if usage["input_tokens"] != float64(11) {
		t.Errorf("receipt usage = %v", usage)
	}
	ev := rig.sink.wait(t)
	if ev.InputTokens != 11 || ev.OutputTokens != 2 {
		t.Errorf("billing event = %+v", ev)
	}

	// Server-generated nonce (no X-Adverserial-Nonce sent).
	if nonce, _ := claims["request_nonce"].(string); len(nonce) < 22 {
		t.Errorf("request_nonce = %v, want generated base64url", claims["request_nonce"])
	}
}

// TestStreamWithoutSignerIsByteIdentical: receipts disabled (nil config) →
// the stream passes through untouched (regression guard for the tap).
func TestStreamWithoutSignerIsByteIdentical(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, sseBody)
	}))
	defer upstream.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	u, _ := url.Parse(upstream.URL)
	tap := &UsageTap{Sink: newRecordSink(), Logger: logger} // no Receipts
	g := &gate.Gate{Logger: logger, Enforce: false}
	front := httptest.NewServer(Logging(logger, g.Middleware(New(u, logger, nil, tap))))
	defer front.Close()

	resp, err := http.Post(front.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"m","stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != sseBody {
		t.Fatalf("stream modified without receipt config:\n got %q\nwant %q", body, sseBody)
	}
}
