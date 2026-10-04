package gate

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/adverserial/attest-proxy/internal/billing"
)

// billingStub serves /auth/check with a programmable verdict and counts calls.
type billingStub struct {
	t       *testing.T
	calls   atomic.Int32
	verdict string
	status  int
}

func (b *billingStub) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/check" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		b.calls.Add(1)
		if b.status != 0 {
			w.WriteHeader(b.status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(b.verdict))
	}))
}

func newGate(billingURL string, enforce bool, logBuf *bytes.Buffer) *Gate {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if logBuf != nil {
		logger = slog.New(slog.NewTextHandler(logBuf, nil))
	}
	return &Gate{
		Billing: &billing.Client{BaseURL: billingURL, WriterSecret: "writer-secret"},
		Logger:  logger,
		Enforce: enforce,
	}
}

// okHandler echoes the request body back so tests can prove it survived the
// gate intact.
func okHandler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		info := RequestInfoFrom(r.Context())
		if info == nil {
			t.Error("RequestInfo missing from context")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"echo": json.RawMessage(body),
			"info": info,
		})
	})
}

func postChat(t *testing.T, h http.Handler, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const allowVerdict = `{"authenticated":true,"allowed":true,"reason":"ok","message":""}`
const denyVerdict = `{"authenticated":false,"allowed":false,"reason":"bad_key","message":"unknown api key"}`
const notAllowedVerdict = `{"authenticated":true,"allowed":false,"reason":"plan","message":"model not in plan"}`

func TestGateAllowsAndPreservesBody(t *testing.T) {
	stub := &billingStub{t: t, verdict: allowVerdict}
	bs := stub.server()
	defer bs.Close()

	g := newGate(bs.URL, true, nil)
	h := g.Middleware(okHandler(t))

	const reqBody = `{"model":"lordx64/cyberglm","messages":[{"role":"user","content":"hi"}]}`
	rec := postChat(t, h, "sk-secret-full-key-123456", reqBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	var resp struct {
		Echo json.RawMessage `json:"echo"`
		Info RequestInfo     `json:"info"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if string(resp.Echo) != reqBody {
		t.Errorf("body not preserved verbatim: %s", resp.Echo)
	}
	if resp.Info.Model != "lordx64/cyberglm" {
		t.Errorf("model = %q", resp.Info.Model)
	}
	if resp.Info.KeyPrefix != "sk-secre" {
		t.Errorf("key prefix = %q, want first-8", resp.Info.KeyPrefix)
	}
	if resp.Info.RequestID == "" {
		t.Error("request id empty")
	}
}

func TestGateDenials(t *testing.T) {
	cases := []struct {
		name    string
		verdict string
		key     string
		body    string
		want    int
	}{
		{"missing key", allowVerdict, "", `{"model":"m"}`, 401},
		{"missing model", allowVerdict, "sk-x12345678", `{"messages":[]}`, 400},
		{"invalid json", allowVerdict, "sk-x12345678", `not json`, 400},
		{"unauthenticated", denyVerdict, "sk-x12345678", `{"model":"m"}`, 401},
		{"not allowed", notAllowedVerdict, "sk-x12345678", `{"model":"m"}`, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &billingStub{t: t, verdict: tc.verdict}
			bs := stub.server()
			defer bs.Close()
			var logBuf bytes.Buffer
			g := newGate(bs.URL, true, &logBuf)
			h := g.Middleware(okHandler(t))

			rec := postChat(t, h, tc.key, tc.body)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body)
			}
			if tc.key != "" && strings.Contains(logBuf.String(), tc.key) {
				t.Errorf("full key leaked into logs:\n%s", logBuf.String())
			}
		})
	}
}

// TestGateFailClosed: billing 500 and unreachable both yield 503, no service.
func TestGateFailClosed(t *testing.T) {
	stub := &billingStub{t: t, status: http.StatusInternalServerError}
	bs := stub.server()
	defer bs.Close()
	g := newGate(bs.URL, true, nil)
	rec := postChat(t, g.Middleware(okHandler(t)), "sk-x12345678", `{"model":"m"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("billing 500 → status %d, want 503", rec.Code)
	}

	g = newGate("http://127.0.0.1:1", true, nil)
	rec = postChat(t, g.Middleware(okHandler(t)), "sk-x12345678", `{"model":"m"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("billing unreachable → status %d, want 503", rec.Code)
	}
}

// TestGateCachesVerdicts: second identical request within TTL hits the cache.
func TestGateCachesVerdicts(t *testing.T) {
	stub := &billingStub{t: t, verdict: allowVerdict}
	bs := stub.server()
	defer bs.Close()
	g := newGate(bs.URL, true, nil)
	h := g.Middleware(okHandler(t))

	for i := 0; i < 3; i++ {
		rec := postChat(t, h, "sk-cache-test-key", `{"model":"m"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
	if got := stub.calls.Load(); got != 1 {
		t.Errorf("billing calls = %d, want 1 (cache)", got)
	}

	// Different model → different cache entry.
	postChat(t, h, "sk-cache-test-key", `{"model":"other"}`)
	if got := stub.calls.Load(); got != 2 {
		t.Errorf("billing calls = %d, want 2 after model change", got)
	}
}

// TestGateCacheExpiry: after TTL the verdict is re-fetched.
func TestGateCacheExpiry(t *testing.T) {
	stub := &billingStub{t: t, verdict: allowVerdict}
	bs := stub.server()
	defer bs.Close()
	g := newGate(bs.URL, true, nil)
	g.TTL = 50 * time.Millisecond
	h := g.Middleware(okHandler(t))

	postChat(t, h, "sk-cache-test-key", `{"model":"m"}`)
	time.Sleep(80 * time.Millisecond)
	postChat(t, h, "sk-cache-test-key", `{"model":"m"}`)
	if got := stub.calls.Load(); got != 2 {
		t.Errorf("billing calls = %d, want 2 after TTL expiry", got)
	}
}

// TestGateSkipsNonV1AndGet: GET /v1/models and non-/v1/ POSTs pass through
// without any billing call and without requiring a key.
func TestGateSkipsNonV1AndGet(t *testing.T) {
	stub := &billingStub{t: t, verdict: denyVerdict} // would deny if called
	bs := stub.server()
	defer bs.Close()
	g := newGate(bs.URL, true, nil)
	h := g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for _, target := range []struct{ method, path string }{
		{http.MethodGet, "/v1/models"},
		{http.MethodGet, "/v1/models/anything"},
		{http.MethodPost, "/attestation"},
		{http.MethodGet, "/healthz"},
	} {
		req := httptest.NewRequest(target.method, target.path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s %s → %d, want 200", target.method, target.path, rec.Code)
		}
	}
	if got := stub.calls.Load(); got != 0 {
		t.Errorf("billing called %d times for ungated routes", got)
	}
}

// TestGatePassthroughWhenDisabled: Enforce=false never calls billing but
// still extracts RequestInfo for the usage tap.
func TestGatePassthroughWhenDisabled(t *testing.T) {
	stub := &billingStub{t: t, verdict: denyVerdict}
	bs := stub.server()
	defer bs.Close()
	g := newGate(bs.URL, false, nil)
	h := g.Middleware(okHandler(t))

	rec := postChat(t, h, "sk-anything", `{"model":"m"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := stub.calls.Load(); got != 0 {
		t.Errorf("billing called with enforcement off")
	}
	var resp struct {
		Info RequestInfo `json:"info"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Info.KeyPrefix != "sk-anyth" || resp.Info.Model != "m" {
		t.Errorf("info = %+v", resp.Info)
	}
}

// TestGateRequestNonce: X-Adverserial-Nonce is validated like an attestation
// nonce; absent → generated.
func TestGateRequestNonce(t *testing.T) {
	stub := &billingStub{t: t, verdict: allowVerdict}
	bs := stub.server()
	defer bs.Close()
	g := newGate(bs.URL, false, nil)
	h := g.Middleware(okHandler(t))

	// Valid client nonce is echoed.
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"m"}`))
	req.Header.Set("X-Adverserial-Nonce", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid nonce → %d", rec.Code)
	}
	var resp struct {
		Info RequestInfo `json:"info"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Info.RequestNonce != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Errorf("nonce echo = %q", resp.Info.RequestNonce)
	}
	if resp.Info.RequestBodyHash == "" || !strings.HasPrefix(resp.Info.RequestBodyHash, "sha256:") {
		t.Errorf("RequestBodyHash = %q", resp.Info.RequestBodyHash)
	}

	// Absent → generated.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"m"}`)))
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Info.RequestNonce) < 22 {
		t.Errorf("generated nonce = %q", resp.Info.RequestNonce)
	}

	// Invalid → 400.
	for _, bad := range []string{"!!!", "AA", strings.Repeat("A", 200)} {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"m"}`))
		req.Header.Set("X-Adverserial-Nonce", bad)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("nonce %q → %d, want 400", bad, rec.Code)
		}
	}
}
