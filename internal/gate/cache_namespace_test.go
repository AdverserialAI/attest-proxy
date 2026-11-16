package gate

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adverserial/attest-proxy/internal/entitlement"
)

func TestSignedCacheScopeIsolationAndLegacyFallback(t *testing.T) {
	stub := &startStub{resp: `{"stored":true,"started":false}`}
	bs := stub.server()
	defer bs.Close()
	g, private, now := newStartGate(t, bs.URL)
	g.ConfidentialCacheIsolation = true
	var salts []string
	h := g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var d map[string]json.RawMessage
		if err := json.Unmarshal(body, &d); err != nil {
			t.Fatal(err)
		}
		var salt string
		if err := json.Unmarshal(d["cache_salt"], &salt); err != nil {
			t.Fatal(err)
		}
		salts = append(salts, salt)
		expected := sha256.Sum256([]byte(startTestBody))
		if RequestInfoFrom(r.Context()).RequestBodyHash != "sha256:"+base64.RawURLEncoding.EncodeToString(expected[:]) {
			t.Error("receipt no longer binds original client bytes")
		}
		if r.ContentLength != int64(len(body)) {
			t.Error("wrong upstream content length")
		}
		if !bytes.Contains(d["messages"], []byte(`"hi"`)) {
			t.Error("prompt changed")
		}
		w.WriteHeader(http.StatusOK)
	}))
	for i, ns := range []string{strings.Repeat("A", 43), strings.Repeat("A", 43), strings.Repeat("B", 43), "", ""} {
		claims := testEntitlementClaims(fmt.Sprintf("reservation-%d", i), now)
		if ns != "" {
			claims["cache_namespace"] = ns
		}
		token := signedEntitlement(t, private, "billing", claims)
		if response := postChat(t, h, token, startTestBody); response.Code != http.StatusOK {
			t.Fatalf("status=%d", response.Code)
		}
	}
	if len(salts) != 5 || salts[0] != salts[1] || salts[0] == salts[2] || salts[3] == salts[4] || salts[0] == salts[3] {
		t.Fatal("tenant/request cache scopes were not isolated")
	}
}

func TestCallerCacheControlsRejectedBeforeDispatchAndReplayConsume(t *testing.T) {
	for _, key := range []string{"cache_salt", "CACHE_SALT", "cache_namespace", "Cache_Namespace"} {
		t.Run(key, func(t *testing.T) {
			stub := &startStub{resp: `{"stored":true,"started":false}`}
			bs := stub.server()
			defer bs.Close()
			g, private, now := newStartGate(t, bs.URL)
			g.ConfidentialCacheIsolation = true
			hits := 0
			h := g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.WriteHeader(http.StatusOK) }))
			token := signedEntitlement(t, private, "billing", testEntitlementClaims("reservation-spoof", now))
			spoof := strings.TrimSuffix(startTestBody, "}") + `,"` + key + `":"another-tenant"}`
			if response := postChat(t, h, token, spoof); response.Code != http.StatusBadRequest {
				t.Fatalf("spoof status=%d", response.Code)
			}
			if hits != 0 || stub.calls.Load() != 0 {
				t.Fatal("spoof reached dispatch")
			}
			if response := postChat(t, h, token, startTestBody); response.Code != http.StatusOK {
				t.Fatalf("clean retry status=%d", response.Code)
			}
		})
	}
}

func TestInvalidSignedNamespaceRejectedBeforeDispatch(t *testing.T) {
	stub := &startStub{resp: `{"stored":true,"started":false}`}
	bs := stub.server()
	defer bs.Close()
	g, private, now := newStartGate(t, bs.URL)
	g.ConfidentialCacheIsolation = true
	hits := 0
	h := g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	claims := testEntitlementClaims("bad-cache-scope", now)
	claims["cache_namespace"] = "not-an-opaque-namespace"
	if response := postChat(t, h, signedEntitlement(t, private, "billing", claims), startTestBody); response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", response.Code)
	}
	if hits != 0 || stub.calls.Load() != 0 {
		t.Fatal("malformed scope dispatched")
	}
}

func TestCacheScopeBindingCannotRunInLegacyMode(t *testing.T) {
	g := &Gate{ConfidentialCacheIsolation: true}
	hits := 0
	h := g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	if response := postChat(t, h, "legacy-key", startTestBody); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", response.Code)
	}
	if hits != 0 {
		t.Fatal("unverified legacy identity entered tenant cache")
	}
}

func TestCacheScopeSeparatesAuthorityModelAndFallback(t *testing.T) {
	base := entitlement.Claims{Issuer: "issuer", Audience: "audience", Model: "adverserial/cyberseek", ID: "reservation", CacheNamespace: strings.Repeat("A", 43)}
	lookup := func(c entitlement.Claims) string {
		b, err := bindCacheSalt([]byte(`{"model":"adverserial/cyberseek"}`), c)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	want := lookup(base)
	for _, change := range []func(*entitlement.Claims){func(c *entitlement.Claims) { c.Model = "publisher/other" }, func(c *entitlement.Claims) { c.Issuer = "other" }, func(c *entitlement.Claims) { c.Audience = "other" }, func(c *entitlement.Claims) { c.CacheNamespace = "" }} {
		c := base
		change(&c)
		if lookup(c) == want {
			t.Fatal("cache authority domains collided")
		}
	}
	if _, err := bindCacheSalt([]byte(`{"CACHE_SALT":"spoof"}`), base); err == nil {
		t.Fatal("defense-in-depth spoof check missing")
	}
}

func TestCacheBindingPreservesStreamingAndResponsesContracts(t *testing.T) {
	for _, tc := range []struct{ path, body string }{
		{"/v1/chat/completions", `{"model":"lordx64/cyberglm","max_tokens":32,"stream":true,"messages":[{"role":"user","content":"hi"}]}`},
		{"/v1/responses", `{"model":"lordx64/cyberglm","max_output_tokens":32,"input":"hi"}`},
	} {
		t.Run(tc.path, func(t *testing.T) {
			stub := &startStub{resp: `{"stored":true,"started":false}`}
			bs := stub.server()
			defer bs.Close()
			g, private, now := newStartGate(t, bs.URL)
			g.ConfidentialCacheIsolation = true
			h := g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				var d map[string]json.RawMessage
				_ = json.Unmarshal(b, &d)
				if len(d["cache_salt"]) == 0 {
					t.Error("cache scope absent")
				}
				if tc.path == "/v1/chat/completions" && !bytes.Contains(d["stream_options"], []byte(`"include_usage":true`)) {
					t.Error("stream usage injection lost")
				}
				sum := sha256.Sum256([]byte(tc.body))
				if RequestInfoFrom(r.Context()).RequestBodyHash != "sha256:"+base64.RawURLEncoding.EncodeToString(sum[:]) {
					t.Error("original request hash lost")
				}
				w.WriteHeader(http.StatusOK)
			}))
			request := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			request.Header.Set("Authorization", "Bearer "+signedEntitlement(t, private, "billing", testEntitlementClaims("route-test", now)))
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d", response.Code)
			}
		})
	}
}

func TestOlderBackendsReceiveNoCacheMetadataWhenDisabled(t *testing.T) {
	stub := &startStub{resp: `{"stored":true,"started":false}`}
	bs := stub.server()
	defer bs.Close()
	g, private, now := newStartGate(t, bs.URL)
	h := g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != startTestBody {
			t.Error("disabled feature changed legacy payload")
		}
		w.WriteHeader(http.StatusOK)
	}))
	claims := testEntitlementClaims("legacy-engine", now)
	claims["cache_namespace"] = strings.Repeat("A", 43)
	if response := postChat(t, h, signedEntitlement(t, private, "billing", claims), startTestBody); response.Code != http.StatusOK {
		t.Fatalf("status=%d", response.Code)
	}
}
