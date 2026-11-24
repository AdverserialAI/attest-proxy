package gate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

var (
	clientSaltA = strings.Repeat("a", 32)
	clientSaltB = strings.Repeat("b", 32)
)

// saltGate is a wired confidential gate plus a helper that sends one request
// for the given tenant and returns the response and the upstream-bound body.
type saltGate struct {
	t      *testing.T
	h      http.Handler
	g      *Gate
	up     *countingHandler
	mint   func(claims map[string]any) string
	serial int
}

func newSaltGate(t *testing.T) *saltGate {
	t.Helper()
	stub := &startStub{resp: `{"stored":true,"started":false}`}
	bs := stub.server()
	t.Cleanup(bs.Close)
	g, private, now := newStartGate(t, bs.URL)
	up := &countingHandler{t: t}
	s := &saltGate{t: t, g: g, up: up, h: g.Middleware(up.handler())}
	s.mint = func(claims map[string]any) string {
		s.serial++
		base := testEntitlementClaims(fmt.Sprintf("reservation-%d", s.serial), now)
		for k, v := range claims {
			base[k] = v
		}
		return signedEntitlement(t, private, "billing", base)
	}
	return s
}

func chatBody(extra string) string {
	return `{"model":"lordx64/cyberglm","max_tokens":32,"messages":[{"role":"user","content":"hi"}]` + extra + `}`
}

// send posts body on path for the tenant and returns (status, upstream doc).
func (s *saltGate) send(path, sub, body string) (int, map[string]json.RawMessage) {
	s.t.Helper()
	claims := map[string]any{}
	if sub != "" {
		claims["sub"] = sub
	}
	rec := postPath(s.t, s.h, s.mint(claims), path, body)
	if rec.Code != http.StatusOK {
		return rec.Code, nil
	}
	var resp struct {
		Echo map[string]json.RawMessage `json:"echo"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		s.t.Fatalf("upstream echo: %v", err)
	}
	return rec.Code, resp.Echo
}

func (s *saltGate) salt(path, sub, body string) string {
	s.t.Helper()
	code, doc := s.send(path, sub, body)
	if code != http.StatusOK {
		s.t.Fatalf("status = %d for %s", code, body)
	}
	var salt string
	if err := json.Unmarshal(doc["cache_salt"], &salt); err != nil || salt == "" {
		s.t.Fatalf("upstream body has no string cache_salt: %s", doc["cache_salt"])
	}
	return salt
}

func TestTenantCacheSaltDerivation(t *testing.T) {
	s := newSaltGate(t)
	withA := chatBody(`,"cache_salt":"` + clientSaltA + `"`)
	withB := chatBody(`,"cache_salt":"` + clientSaltB + `"`)

	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		body := func(b string) string {
			if path == "/v1/responses" {
				return strings.Replace(strings.Replace(b, `"max_tokens"`, `"max_output_tokens"`, 1), `"messages":[{"role":"user","content":"hi"}]`, `"input":"hi"`, 1)
			}
			return b
		}
		acmeA := s.salt(path, "acct_acme", body(withA))
		// Same tenant, same client salt → same forwarded value (cache hits).
		if again := s.salt(path, "acct_acme", body(withA)); again != acmeA {
			t.Errorf("%s: same tenant and salt produced %q then %q", path, acmeA, again)
		}
		// Different tenant, same client salt → different value.
		if other := s.salt(path, "acct_other", body(withA)); other == acmeA {
			t.Errorf("%s: two tenants share a cache salt", path)
		}
		// Same tenant, different client salt → different partition.
		if acmeB := s.salt(path, "acct_acme", body(withB)); acmeB == acmeA {
			t.Errorf("%s: distinct client salts collapsed", path)
		}
		// The salt is always present upstream, also when the client sent none,
		// and a salt-less request is its own partition per tenant.
		none := s.salt(path, "acct_acme", body(chatBody("")))
		if none == acmeA {
			t.Errorf("%s: absent salt equals an explicit salt", path)
		}
		if s.salt(path, "acct_acme", body(chatBody(""))) != none {
			t.Errorf("%s: absent salt is not stable for a tenant", path)
		}
		if s.salt(path, "acct_other", body(chatBody(""))) == none {
			t.Errorf("%s: tenants without a salt share a cache key", path)
		}
		// The client's own value never reaches the model runtime.
		if acmeA == clientSaltA || strings.Contains(acmeA, clientSaltA) {
			t.Errorf("%s: client salt forwarded verbatim", path)
		}
		// Exactly the specified construction.
		mac := hmac.New(sha256.New, s.g.cacheSaltKey)
		mac.Write([]byte("sub:acct_acme\x00" + clientSaltA))
		if want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)); acmeA != want {
			t.Errorf("%s: cache_salt = %q, want HMAC-SHA256 value %q", path, acmeA, want)
		}
	}
}

// A client cannot reach another tenant's partition by choosing a salt that
// imitates the tenant/salt framing, and an entitlement without a signed
// subject is isolated per request.
func TestTenantCacheSaltCannotBeSteeredByTheClient(t *testing.T) {
	s := newSaltGate(t)
	withA := chatBody(`,"cache_salt":"` + clientSaltA + `"`)

	victim := s.salt("/v1/chat/completions", "acct_victim", withA)
	// The attacker knows the victim's subject and client salt; every value it
	// can place in its own request still lands under its own subject.
	for _, attempt := range []string{
		clientSaltA,
		"acct_victim" + clientSaltA,
		strings.Repeat("a", 31) + "_" + clientSaltA,
	} {
		got := s.salt("/v1/chat/completions", "acct_attacker", chatBody(`,"cache_salt":"`+attempt+`"`))
		if got == victim {
			t.Fatalf("attacker salt %q reached the victim's cache partition", attempt)
		}
	}

	// No sub claim: the tenant falls back to the single-use jti.
	first := s.salt("/v1/chat/completions", "", withA)
	second := s.salt("/v1/chat/completions", "", withA)
	if first == second {
		t.Error("requests without a signed subject share a cache key")
	}
	// A subject equal to another entitlement's jti cannot collide with the
	// jti namespace.
	if got := s.salt("/v1/chat/completions", "reservation-1", withA); got == first || got == second {
		t.Error("sub and jti namespaces collide")
	}
	if len(s.g.cacheSaltKey) != 32 {
		t.Fatalf("cache salt key is %d bytes, want 32", len(s.g.cacheSaltKey))
	}

	// A second process (fresh key) maps the same tenant and salt elsewhere.
	other := newSaltGate(t)
	if other.salt("/v1/chat/completions", "acct_victim", withA) == victim {
		t.Error("cache salt key is not per-process random")
	}
}

func TestClientCacheFieldsRejectedBeforeEntitlementIsConsumed(t *testing.T) {
	s := newSaltGate(t)
	bad := map[string]string{
		"extra_key string":       `,"extra_key":"tenant-b"`,
		"extra_key list":         `,"extra_key":["a","b"]`,
		"extra_key null":         `,"extra_key":null`,
		"extra_key empty":        `,"extra_key":""`,
		"extra_key mixed case":   `,"Extra_Key":"x"`,
		"cache_salt mixed case":  `,"Cache_Salt":"` + clientSaltA + `"`,
		"cache_salt duplicate":   `,"cache_salt":"` + clientSaltA + `","cache_salt":"` + clientSaltB + `"`,
		"salt too short":         `,"cache_salt":"` + strings.Repeat("a", 31) + `"`,
		"salt too long":          `,"cache_salt":"` + strings.Repeat("a", 129) + `"`,
		"salt empty":             `,"cache_salt":""`,
		"salt bad alphabet":      `,"cache_salt":"` + strings.Repeat("a", 31) + `+"`,
		"salt with NUL":          `,"cache_salt":"` + strings.Repeat("a", 31) + `\u0000"`,
		"salt with space":        `,"cache_salt":"` + strings.Repeat("a", 31) + ` "`,
		"salt number":            `,"cache_salt":12345678901234567890123456789012`,
		"salt null":              `,"cache_salt":null`,
		"salt array":             `,"cache_salt":["` + clientSaltA + `"]`,
		"salt object":            `,"cache_salt":{"v":"` + clientSaltA + `"}`,
		"salt and extra_key":     `,"cache_salt":"` + clientSaltA + `","extra_key":"x"`,
		"salt non-ASCII letters": `,"cache_salt":"` + strings.Repeat("é", 32) + `"`,
	}
	for name, extra := range bad {
		for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
			body := chatBody(extra)
			if path == "/v1/responses" {
				body = strings.Replace(strings.Replace(body, `"max_tokens"`, `"max_output_tokens"`, 1), `"messages":[{"role":"user","content":"hi"}]`, `"input":"hi"`, 1)
			}
			token := s.mint(map[string]any{"sub": "acct_acme"})
			rec := postPath(t, s.h, token, path, body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s on %s: status = %d, want 400 (%s)", name, path, rec.Code, rec.Body)
				continue
			}
			// The refusal burned nothing: the same entitlement still works.
			ok := strings.Replace(body, extra, "", 1)
			if rec := postPath(t, s.h, token, path, ok); rec.Code != http.StatusOK {
				t.Errorf("%s on %s: entitlement was consumed by the refused request (%d)", name, path, rec.Code)
			}
		}
	}
	if hits := s.up.hits.Load(); int(hits) != 2*len(bad) {
		t.Errorf("upstream hits = %d, want %d (only the corrected requests)", hits, 2*len(bad))
	}
	// Boundary lengths are accepted.
	for _, n := range []int{32, 128} {
		if code, _ := s.send("/v1/chat/completions", "acct_acme", chatBody(`,"cache_salt":"`+strings.Repeat("Z", n-2)+`_-"`)); code != http.StatusOK {
			t.Errorf("%d-character salt refused: %d", n, code)
		}
	}
}

// The rewrite is upstream-only: the receipt hash and the entitlement input
// bound still describe the client's exact bytes, and it composes with the
// include_usage injection on streams.
func TestCacheSaltRewritePreservesClientBinding(t *testing.T) {
	s := newSaltGate(t)
	body := chatBody(`,"stream":true,"cache_salt":"` + clientSaltA + `"`)

	// An entitlement whose input bound equals the client body length exactly:
	// the longer rewritten body must not be what is checked against it.
	token := s.mint(map[string]any{"sub": "acct_acme", "max_input_tokens": len(body)})
	rec := postChat(t, s.h, token, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body)
	}
	var resp struct {
		Echo map[string]json.RawMessage `json:"echo"`
		Info RequestInfo                `json:"info"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	if want := "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:]); resp.Info.RequestBodyHash != want {
		t.Errorf("receipt body hash = %q, want the client's bytes %q", resp.Info.RequestBodyHash, want)
	}
	if !strings.Contains(string(resp.Echo["stream_options"]), `"include_usage":true`) {
		t.Errorf("include_usage injection lost: %s", resp.Echo["stream_options"])
	}
	if strings.Contains(string(resp.Echo["cache_salt"]), clientSaltA) {
		t.Error("client salt forwarded verbatim on a stream")
	}
	for _, key := range []string{"model", "max_tokens", "messages", "stream"} {
		if _, ok := resp.Echo[key]; !ok {
			t.Errorf("rewrite dropped %q", key)
		}
	}
	// One byte over the bound is still refused.
	token = s.mint(map[string]any{"sub": "acct_acme", "max_input_tokens": len(body) - 1})
	if rec := postChat(t, s.h, token, body); rec.Code != http.StatusUnauthorized {
		t.Errorf("over-bound request = %d, want 401", rec.Code)
	}
}

func TestBindCacheSaltFailsClosed(t *testing.T) {
	key := make([]byte, 32)
	if _, err := bindCacheSalt([]byte(`{"model":"m"}`), nil, "sub:a"); err == nil {
		t.Error("missing key accepted")
	}
	if _, err := bindCacheSalt([]byte(`{"model":"m"}`), key, ""); err == nil {
		t.Error("empty tenant accepted")
	}
	if _, err := bindCacheSalt([]byte(`[1,2]`), key, "sub:a"); err == nil {
		t.Error("non-object body accepted")
	}
	if _, err := bindCacheSalt([]byte(`{"extra_key":"x"}`), key, "sub:a"); err == nil {
		t.Error("extra_key accepted")
	}
	// Tenant/salt framing is unambiguous.
	if tenantCacheSalt(key, "sub:ab", strings.Repeat("c", 32)) == tenantCacheSalt(key, "sub:a", "b"+strings.Repeat("c", 32)) {
		t.Error("tenant and salt boundaries are ambiguous")
	}
}

// Legacy (non-confidential) requests are not rewritten.
func TestLegacyModeLeavesCacheFieldsAlone(t *testing.T) {
	g := &Gate{Enforce: false}
	rec := postChat(t, g.Middleware(okHandler(t)), "", `{"model":"m","cache_salt":"x","extra_key":"y"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"cache_salt":"x"`) {
		t.Errorf("legacy request altered: %d %s", rec.Code, rec.Body)
	}
}

func TestClientSaltPartitionsWhenNoSubject(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	saltA := strings.Repeat("a", 43)
	saltB := strings.Repeat("b", 43)
	get := func(body, tenant string) string {
		t.Helper()
		out, err := bindCacheSalt([]byte(body), key, tenant)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]string
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatal(err)
		}
		return doc["cache_salt"]
	}
	// Same client salt across two single-use entitlements: same partition.
	if get(`{"cache_salt":"`+saltA+`"}`, "jti:1") != get(`{"cache_salt":"`+saltA+`"}`, "jti:2") {
		t.Error("same client salt without subject must share a partition")
	}
	// Different client salts never share.
	if get(`{"cache_salt":"`+saltA+`"}`, "jti:1") == get(`{"cache_salt":"`+saltB+`"}`, "jti:2") {
		t.Error("different client salts must not share")
	}
	// No client salt: every request is alone.
	if get(`{}`, "jti:1") == get(`{}`, "jti:2") {
		t.Error("requests without subject or salt must not share")
	}
	// A subject-bound tenant never lands in the client-salt partition.
	if get(`{"cache_salt":"`+saltA+`"}`, "sub:x") == get(`{"cache_salt":"`+saltA+`"}`, "jti:1") {
		t.Error("subject tenants must stay separate from client-salt partitions")
	}
}
