package billing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCheckAuthContract pins the exact request shape billing expects.
func TestCheckAuthContract(t *testing.T) {
	var gotAuth, gotPath string
	var gotBody authCheckRequest
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("body decode: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authenticated":true,"allowed":true,"reason":"ok","message":""}`))
	}))
	defer stub.Close()

	c := &Client{BaseURL: stub.URL, WriterSecret: "writer-secret"}
	v, err := c.CheckAuth(context.Background(), "sk-full-client-key", "lordx64/cyberglm")
	if err != nil {
		t.Fatalf("CheckAuth: %v", err)
	}
	if gotPath != "/auth/check" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer writer-secret" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotBody.APIKey != "sk-full-client-key" || gotBody.Model != "lordx64/cyberglm" {
		t.Errorf("body = %+v", gotBody)
	}
	if !v.Authenticated || !v.Allowed || v.Reason != "ok" {
		t.Errorf("verdict = %+v", v)
	}
}

// TestCheckAuthFailClosed: non-200 and unreachable are errors, never verdicts.
func TestCheckAuthFailClosed(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer stub.Close()
	c := &Client{BaseURL: stub.URL, WriterSecret: "s"}
	if _, err := c.CheckAuth(context.Background(), "k", "m"); err == nil {
		t.Error("500 must be an error")
	}

	c = &Client{BaseURL: "http://127.0.0.1:1", WriterSecret: "s"}
	if _, err := c.CheckAuth(context.Background(), "k", "m"); err == nil {
		t.Error("unreachable must be an error")
	}
}

// TestUsageContract pins the exact /usage body keys.
func TestUsageContract(t *testing.T) {
	var got map[string]any
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/usage" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer writer-secret" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer stub.Close()

	c := &Client{BaseURL: stub.URL, WriterSecret: "writer-secret"}
	ev := UsageEvent{
		Source:       "attest-proxy",
		Model:        "lordx64/cyberglm",
		APIKeyPrefix: "sk-abcde",
		InputTokens:  128,
		CachedTokens: 64,
		OutputTokens: 42,
		RequestID:    "6f1a0e2e-3b2d-4a1c-9d0e-1f2a3b4c5d6e",
		TS:           "2026-10-04T15:00:00Z",
	}
	if err := c.PostUsage(context.Background(), ev); err != nil {
		t.Fatalf("PostUsage: %v", err)
	}

	want := map[string]any{
		"source":         "attest-proxy",
		"model":          "lordx64/cyberglm",
		"api_key_prefix": "sk-abcde",
		"input_tokens":   float64(128),
		"cached_tokens":  float64(64),
		"output_tokens":  float64(42),
		"request_id":     "6f1a0e2e-3b2d-4a1c-9d0e-1f2a3b4c5d6e",
		"ts":             "2026-10-04T15:00:00Z",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("usage[%s] = %v, want %v", k, got[k], w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("usage has extra keys: %v", got)
	}
}

func TestConfidentialMeterContract(t *testing.T) {
	var got map[string]string
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cc/meter" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("confidential meter must not use shared bearer auth")
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer stub.Close()
	if err := (&Client{BaseURL: stub.URL, WriterSecret: "not-used"}).PostMeter(context.Background(), "header.payload.signature"); err != nil {
		t.Fatal(err)
	}
	if got["meter"] != "header.payload.signature" || len(got) != 1 {
		t.Errorf("body=%v", got)
	}
}

func TestDirectSignedMeterAddsDedicatedCapability(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Adverserial-Meter-Ingress")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	if err := (&Client{MeterURL: server.URL, MeterIngressSecret: "direct-only-capability"}).PostMeter(context.Background(), "header.payload.signature"); err != nil {
		t.Fatal(err)
	}
	if got != "direct-only-capability" {
		t.Fatalf("direct signed capability = %q", got)
	}
}

func TestConfidentialMeterUsesDedicatedIngressURL(t *testing.T) {
	var gotPath string
	ingress := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ingress.Close()
	if err := (&Client{BaseURL: "http://billing.invalid", MeterURL: ingress.URL}).PostMeter(context.Background(), "header.payload.signature"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/cc/meter" {
		t.Errorf("dedicated ingress path = %q", gotPath)
	}
}
