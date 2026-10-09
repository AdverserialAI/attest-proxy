package gate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/adverserial/attest-proxy/internal/billing"
	"github.com/adverserial/attest-proxy/internal/entitlement"
	"github.com/adverserial/attest-proxy/internal/meter"
)

// startStub serves /cc/start with a programmable response and captures the
// last request for assertion.
type startStub struct {
	calls   atomic.Int32
	status  int    // when non-zero, answer with this status and no body
	resp    string // JSON answer otherwise
	mu      sync.Mutex
	path    string
	ingress string
	auth    string
	token   string
}

func (s *startStub) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cc/start" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		s.calls.Add(1)
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.mu.Lock()
		s.path = r.URL.Path
		s.ingress = r.Header.Get("X-Adverserial-Meter-Ingress")
		s.auth = r.Header.Get("Authorization")
		s.token = body["start"]
		s.mu.Unlock()
		if s.status != 0 {
			w.WriteHeader(s.status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, s.resp)
	}))
}

func (s *startStub) last() (path, ingress, auth, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path, s.ingress, s.auth, s.token
}

const startTestSPKI = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

const startTestBody = `{"model":"lordx64/cyberglm","max_tokens":32,"messages":[{"role":"user","content":"hi"}]}`

func testEntitlementClaims(jti string, now time.Time) map[string]any {
	return map[string]any{
		"iss": "https://billing.adverserial.ai", "aud": "https://api.adverserial.ai",
		"typ": "adverserial-confidential-entitlement/v1", "jti": jti,
		"model": "lordx64/cyberglm", "max_input_tokens": 4096, "max_output_tokens": 32,
		"max_requests": 1, "cnf": map[string]string{"tls_spki_sha256": startTestSPKI},
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	}
}

// newStartGate builds a fully wired confidential gate against the given
// /cc/start URL and returns it with the entitlement signing key and the
// pinned validation time.
func newStartGate(t *testing.T, meterURL string) (*Gate, ed25519.PrivateKey, time.Time) {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_760_000_000, 0)
	signer, err := meter.NewTestSigner()
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Confidential: true, ConfidentialActive: true,
		Entitlements: &entitlement.Validator{Keys: map[string]ed25519.PublicKey{"billing": pub}, Issuer: "https://billing.adverserial.ai", Audience: "https://api.adverserial.ai", Now: func() time.Time { return now }},
		Replay:       &entitlement.UsedStore{Dir: t.TempDir()},
		ActiveSPKI:   func() string { return startTestSPKI },
		Billing:      &billing.Client{MeterURL: meterURL, MeterIngressSecret: "test-ingress-capability"},
		Meter: &MeterConfig{Signer: signer, Issuer: "https://api.adverserial.ai", Audience: "https://billing.adverserial.ai",
			Outbox: meter.Outbox{Dir: t.TempDir()}},
	}
	return g, private, now
}

func decodeStartPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// countingHandler wraps okHandler and records upstream hits plus whether the
// request context carried a terminal settlement handle.
type countingHandler struct {
	t             *testing.T
	hits          atomic.Int32
	sawSettlement atomic.Bool
}

func (c *countingHandler) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.hits.Add(1)
		if meter.SettlementFrom(r.Context()) != nil {
			c.sawSettlement.Store(true)
		}
		okHandler(c.t).ServeHTTP(w, r)
	})
}

// TestStartGateProceedsFirstDispatch: stored:true/started:false dispatches,
// and the start JWS carries the dispatch-precondition contract.
func TestStartGateProceedsFirstDispatch(t *testing.T) {
	stub := &startStub{resp: `{"stored":true,"started":false}`}
	bs := stub.server()
	defer bs.Close()
	g, private, now := newStartGate(t, bs.URL)
	up := &countingHandler{t: t}
	h := g.Middleware(up.handler())

	token := signedEntitlement(t, private, "billing", testEntitlementClaims("reservation-1", now))
	rec := postChat(t, h, token, startTestBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if up.hits.Load() != 1 {
		t.Fatalf("upstream hits = %d, want 1", up.hits.Load())
	}
	if stub.calls.Load() != 1 {
		t.Fatalf("start calls = %d, want 1", stub.calls.Load())
	}
	if !up.sawSettlement.Load() {
		t.Error("dispatched request carried no terminal settlement handle")
	}
	path, ingress, auth, startToken := stub.last()
	if path != "/cc/start" {
		t.Errorf("start path = %q", path)
	}
	if ingress != "test-ingress-capability" {
		t.Errorf("ingress capability = %q", ingress)
	}
	if auth != "" {
		t.Errorf("start must not carry bearer auth, got %q", auth)
	}

	claims := decodeStartPayload(t, startToken)
	for k, want := range map[string]string{
		"iss": "https://api.adverserial.ai", "aud": "https://billing.adverserial.ai",
		"typ": "adverserial-confidential-start/v1", "jti": "reservation-1",
		"model": "lordx64/cyberglm",
	} {
		if claims[k] != want {
			t.Errorf("start claims[%s] = %v, want %s", k, claims[k], want)
		}
	}
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if exp-iat != 600 {
		t.Errorf("start exp-iat = %v, want 600", exp-iat)
	}
	// The start event names the same request id the gate put in RequestInfo.
	var resp struct {
		Info RequestInfo `json:"info"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Info.RequestID == "" || claims["request_id"] != resp.Info.RequestID {
		t.Errorf("start request_id = %v, RequestInfo.RequestID = %q", claims["request_id"], resp.Info.RequestID)
	}
}

// TestStartGateRefusesSecondDispatch: started:true means this reservation
// already dispatched once; the proxy never dispatches twice (409).
func TestStartGateRefusesSecondDispatch(t *testing.T) {
	stub := &startStub{resp: `{"stored":true,"started":true}`}
	bs := stub.server()
	defer bs.Close()
	g, private, now := newStartGate(t, bs.URL)
	up := &countingHandler{t: t}
	token := signedEntitlement(t, private, "billing", testEntitlementClaims("reservation-1", now))
	rec := postChat(t, g.Middleware(up.handler()), token, startTestBody)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d, want 409 (body %s)", rec.Code, rec.Body)
	}
	if up.hits.Load() != 0 {
		t.Error("upstream was hit on a refused duplicate dispatch")
	}
}

// TestStartGateRefusesReleasedReservation: stored:false means billing
// released or expired the reservation; dispatching would run unbillable
// inference (401). This closes the release-then-replay free-inference hole.
func TestStartGateRefusesReleasedReservation(t *testing.T) {
	stub := &startStub{resp: `{"stored":false,"ignored":"unknown_reservation","ok":true}`}
	bs := stub.server()
	defer bs.Close()
	g, private, now := newStartGate(t, bs.URL)
	up := &countingHandler{t: t}
	token := signedEntitlement(t, private, "billing", testEntitlementClaims("reservation-1", now))
	rec := postChat(t, g.Middleware(up.handler()), token, startTestBody)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401 (body %s)", rec.Code, rec.Body)
	}
	if up.hits.Load() != 0 {
		t.Error("upstream was hit for a released reservation")
	}
}

// TestStartGateFailsClosed: billing non-2xx and unreachable both refuse
// dispatch with 503; the upstream is never touched.
func TestStartGateFailsClosed(t *testing.T) {
	stub := &startStub{status: http.StatusInternalServerError}
	bs := stub.server()
	defer bs.Close()
	g, private, now := newStartGate(t, bs.URL)
	up := &countingHandler{t: t}
	token := signedEntitlement(t, private, "billing", testEntitlementClaims("reservation-1", now))
	rec := postChat(t, g.Middleware(up.handler()), token, startTestBody)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("billing 500 → status %d, want 503", rec.Code)
	}
	if up.hits.Load() != 0 {
		t.Error("upstream was hit when start returned non-2xx")
	}

	g, private, now = newStartGate(t, "http://127.0.0.1:1") // nothing listening
	up = &countingHandler{t: t}
	token = signedEntitlement(t, private, "billing", testEntitlementClaims("reservation-1", now))
	rec = postChat(t, g.Middleware(up.handler()), token, startTestBody)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("billing unreachable → status %d, want 503", rec.Code)
	}
	if up.hits.Load() != 0 {
		t.Error("upstream was hit when billing was unreachable")
	}
}

// TestConfidentialOversizedBodyRejected: an over-limit body must never
// bypass entitlement validation via the unattributed passthrough — in
// confidential mode it is a hard 413 before any upstream or billing work.
func TestConfidentialOversizedBodyRejected(t *testing.T) {
	stub := &startStub{resp: `{"stored":true,"started":false}`}
	bs := stub.server()
	defer bs.Close()
	g, private, now := newStartGate(t, bs.URL)
	up := &countingHandler{t: t}
	h := g.Middleware(up.handler())

	body := `{"model":"lordx64/cyberglm","max_tokens":32,"messages":[{"role":"user","content":"` + strings.Repeat("x", maxModelParseBody) + `"}]}`
	token := signedEntitlement(t, private, "billing", testEntitlementClaims("reservation-oversized", now))
	rec := postChat(t, h, token, body)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%.200s", rec.Code, rec.Body)
	}
	if up.hits.Load() != 0 {
		t.Fatalf("upstream hits = %d, want 0", up.hits.Load())
	}
	if stub.calls.Load() != 0 {
		t.Fatalf("start calls = %d, want 0", stub.calls.Load())
	}
}
