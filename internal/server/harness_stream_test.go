package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/adverserial/attest-proxy/internal/attestation"
	ehbpclient "github.com/tinfoilsh/encrypted-http-body-protocol/client"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

// streamBillingStub serves /cc/start (admit first dispatch) and captures
// /cc/meter settlement tokens for assertion.
type streamBillingStub struct {
	starts atomic.Int32
	mu     sync.Mutex
	meters []string
}

func (b *streamBillingStub) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cc/start":
			b.starts.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"stored":true,"started":false}`)
		case "/cc/meter":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			b.mu.Lock()
			b.meters = append(b.meters, body["meter"])
			b.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func (b *streamBillingStub) meterTokens() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.meters...)
}

// mintStreamEntitlement signs a harness-bound entitlement for the given
// channel SPKI. jti must be fresh per request (single-use replay store).
func mintStreamEntitlement(t *testing.T, private ed25519.PrivateKey, jti, spki string) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss": "https://billing.adverserial.ai", "aud": "https://api.adverserial.ai",
		"typ": "adverserial-confidential-entitlement/v1", "jti": jti,
		"model": "lordx64/cyberglm", "max_input_tokens": 1 << 20, "max_output_tokens": 4096,
		"max_requests": 1, "cnf": map[string]string{"tls_spki_sha256": spki},
		"iat": now.Unix() - 5, "exp": now.Add(time.Minute).Unix(),
	}
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": "billing", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(input)))
}

// TestConfidentialHarnessStreamEndToEnd drives the exact production stack —
// EHBP decrypt, confidential gate (entitlement validation, payload bounds,
// include_usage injection), reverse proxy, SSE usage tap, per-request receipt,
// terminal meter settlement — with the harness-shaped streaming tool-call
// request that rc.26 wrongly rejected, against a mock SGLang and mock billing.
func TestConfidentialHarnessStreamEndToEnd(t *testing.T) {
	sseBody := "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n" +
		"data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n" +
		"data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":2,\"prompt_tokens_details\":{\"cached_tokens\":7}}}\n\n" +
		"data: [DONE]\n\n"

	var upstreamBody atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/v1/chat/completions":
			body, _ := io.ReadAll(r.Body)
			upstreamBody.Store(string(body))
			w.Header().Set("Content-Type", "text/event-stream")
			fl := w.(http.Flusher)
			for _, event := range strings.SplitAfter(sseBody, "\n\n") {
				_, _ = io.WriteString(w, event)
				fl.Flush()
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()

	billing := &streamBillingStub{}
	bs := billing.server()
	defer bs.Close()

	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "OKP", "crv": "Ed25519", "kid": "billing",
		"x": base64.RawURLEncoding.EncodeToString(pub),
	}}})

	cfg := testConfig()
	cfg.Upstream = upstream.URL
	cfg.ConfidentialMode = true
	cfg.ConfidentialActivation = "active"
	cfg.EntitlementJWKS = string(jwks)
	cfg.EntitlementIssuer = "https://billing.adverserial.ai"
	cfg.EntitlementAudience = "https://api.adverserial.ai"
	cfg.EntitlementReplayDir = t.TempDir()
	cfg.MeterIssuer = "https://api.adverserial.ai"
	cfg.MeterAudience = "https://billing.adverserial.ai"
	cfg.MeterURL = bs.URL
	cfg.MeterDeliveryMode = "direct-signed"
	cfg.MeterIngressSecret = "test-ingress"
	cfg.MeterSigningSeed = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	cfg.MeterOutboxDir = t.TempDir()
	cfg.EHBPRequired = true

	identity, err := ehbpidentity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	srv, ts := newTestServer(t, cfg, identity)
	spki := attestation.SPKIHash(srv.holder.Leaf())

	transport, err := ehbpclient.NewTransportWithIdentity(identity, ehbpclient.WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: transport}

	// The exact shape kimi-code / claude-code send mid-session: array content
	// parts, a prior tool-call round trip, tools, streaming (stream_options is
	// NOT set — the gate must inject include_usage for settlement).
	const harnessBody = `{
		"model": "lordx64/cyberglm",
		"max_tokens": 256,
		"stream": true,
		"messages": [
			{"role":"system","content":[{"type":"text","text":"You are an agentic coding assistant."}]},
			{"role":"user","content":[{"type":"text","text":"list files"}]},
			{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"Bash","arguments":"{\"command\":\"ls\"}"}}]},
			{"role":"tool","tool_call_id":"call_1","content":"main.go"},
			{"role":"user","content":[{"type":"text","text":"thanks"}]}
		],
		"tools": [{"type":"function","function":{"name":"Bash","description":"Run a shell command","parameters":{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}}}],
		"tool_choice": "auto"
	}`

	// The upstream readiness probe polls /health on a 2s tick; retry through
	// the warm-up window with a fresh single-use entitlement per attempt.
	var resp *http.Response
	var jti string
	deadline := time.Now().Add(15 * time.Second)
	for attempt := 0; ; attempt++ {
		jti = "harness-stream-" + strings.TrimPrefix(time.Now().Format(".150000"), ".")
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/chat/completions", strings.NewReader(harnessBody))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+mintStreamEntitlement(t, private, jti, spki))
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("EHBP POST: %v", err)
		}
		if resp.StatusCode != http.StatusServiceUnavailable {
			break
		}
		resp.Body.Close()
		if time.Now().After(deadline) {
			t.Fatal("server never became ready")
		}
		time.Sleep(250 * time.Millisecond)
	}

	stream, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, stream)
	}
	got := string(stream)
	for _, want := range []string{`"Hel"`, `"lo"`, `"usage"`, "adverserial_receipt", "data: [DONE]"} {
		if !strings.Contains(got, want) {
			t.Errorf("stream missing %q:\n%s", want, got)
		}
	}
	// The receipt chunk must precede the held [DONE] sentinel.
	if strings.Index(got, "adverserial_receipt") > strings.Index(got, "data: [DONE]") {
		t.Errorf("receipt chunk must precede [DONE]:\n%s", got)
	}

	// The gate must have injected stream_options.include_usage upstream.
	forwarded, _ := upstreamBody.Load().(string)
	if !strings.Contains(forwarded, `"include_usage":true`) {
		t.Errorf("upstream body lacks injected include_usage: %s", forwarded)
	}
	if !strings.Contains(forwarded, `"tool_calls"`) || !strings.Contains(forwarded, `"tool_choice":"auto"`) {
		t.Errorf("tool-call fields did not survive the gate: %s", forwarded)
	}
	if billing.starts.Load() != 1 {
		t.Errorf("/cc/start calls = %d, want 1", billing.starts.Load())
	}

	// Terminal settlement must reach billing with the usage chunk's counts.
	var metered map[string]any
	meterDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(meterDeadline) {
		tokens := billing.meterTokens()
		if len(tokens) > 0 {
			parts := strings.Split(tokens[len(tokens)-1], ".")
			if len(parts) == 3 {
				raw, err := base64.RawURLEncoding.DecodeString(parts[1])
				if err == nil {
					_ = json.Unmarshal(raw, &metered)
				}
			}
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if metered == nil {
		t.Fatal("no /cc/meter settlement reached billing")
	}
	if metered["jti"] != jti {
		t.Errorf("meter jti = %v, want the dispatched reservation %q", metered["jti"], jti)
	}
	if metered["input_tokens"] != float64(11) || metered["cached_tokens"] != float64(7) || metered["output_tokens"] != float64(2) {
		t.Errorf("meter counts = %v/%v/%v, want 11/7/2", metered["input_tokens"], metered["cached_tokens"], metered["output_tokens"])
	}
}
