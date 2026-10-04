package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testIndexHTML = "<!doctype html><html><body>chat spa</body></html>"
	testAppJS     = "console.log('hashed asset');"
)

// newChatTestServer builds a DEV_MODE server with the chat vhost and a fake
// upstream that answers /v1/models.
func newChatTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()

	docroot := t.TempDir()
	if err := os.WriteFile(filepath.Join(docroot, "index.html"), []byte(testIndexHTML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(docroot, "_app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(docroot, "_app", "app.a1b2c3.js"), []byte(testAppJS), 0o644); err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"lordx64/cyberglm"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"unknown upstream route"}`))
	}))
	t.Cleanup(upstream.Close)

	cfg := testConfig()
	cfg.Upstream = upstream.URL
	cfg.ChatHost = "cc-chat.adverserial.ai"
	cfg.ChatDocroot = docroot
	_, ts := newTestServer(t, cfg)
	return ts, docroot
}

func getWithHost(t *testing.T, ts *httptest.Server, host, path string) (int, http.Header, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	if host != "" {
		req.Host = host
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, string(body)
}

func TestChatHostServesAsset(t *testing.T) {
	ts, _ := newChatTestServer(t)
	status, hdr, body := getWithHost(t, ts, "cc-chat.adverserial.ai", "/_app/app.a1b2c3.js")
	if status != http.StatusOK || body != testAppJS {
		t.Fatalf("status=%d body=%q", status, body)
	}
	if cc := hdr.Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Errorf("Cache-Control = %q", cc)
	}
}

func TestChatHostSPAFallback(t *testing.T) {
	ts, _ := newChatTestServer(t)
	for _, p := range []string{"/", "/chat", "/chat/some/deep/route"} {
		status, hdr, body := getWithHost(t, ts, "cc-chat.adverserial.ai", p)
		if status != http.StatusOK || body != testIndexHTML {
			t.Errorf("GET %s: status=%d body=%q", p, status, body)
		}
		if cc := hdr.Get("Cache-Control"); cc != "no-cache" {
			t.Errorf("GET %s: Cache-Control = %q, want no-cache", p, cc)
		}
	}
}

func TestChatHostMissingAssetIs404(t *testing.T) {
	ts, _ := newChatTestServer(t)
	status, _, _ := getWithHost(t, ts, "cc-chat.adverserial.ai", "/_app/gone.js")
	if status != http.StatusNotFound {
		t.Errorf("missing asset → %d, want 404 (no SPA fallback for asset paths)", status)
	}
}

// TestChatHostAPIRoutesStillWork: /v1/models on the chat host is proxied and
// augmented; /attestation is served.
func TestChatHostAPIRoutesStillWork(t *testing.T) {
	ts, _ := newChatTestServer(t)

	status, _, body := getWithHost(t, ts, "cc-chat.adverserial.ai", "/v1/models")
	if status != http.StatusOK {
		t.Fatalf("/v1/models on chat host → %d", status)
	}
	if !strings.Contains(body, "confidential_verification") {
		t.Error("/v1/models on chat host was not augmented")
	}

	// Host with a port must still match.
	status, _, _ = getWithHost(t, ts, "cc-chat.adverserial.ai:8443", "/v1/models")
	if status != http.StatusOK {
		t.Errorf("/v1/models with ported host → %d", status)
	}

	// Attestation on the chat host works (public evidence).
	nonce := b64Of(32)
	status, _, body = getWithHost(t, ts, "cc-chat.adverserial.ai", "/attestation?nonce="+nonce)
	if status != http.StatusOK || !strings.Contains(body, "verification_receipt") {
		t.Errorf("/attestation on chat host → %d", status)
	}
}

// TestWrongHostUnaffected: non-chat hosts never see the static content.
func TestWrongHostUnaffected(t *testing.T) {
	ts, _ := newChatTestServer(t)
	status, _, body := getWithHost(t, ts, "api.adverserial.ai", "/_app/app.a1b2c3.js")
	if status == http.StatusOK && body == testAppJS {
		t.Fatal("static asset served on the wrong host")
	}
	if strings.Contains(body, testIndexHTML) {
		t.Fatal("SPA fallback leaked to the wrong host")
	}
}

// TestHostOnlyNormalization covers port stripping and case.
func TestHostOnlyNormalization(t *testing.T) {
	cases := map[string]string{
		"cc-chat.adverserial.ai":      "cc-chat.adverserial.ai",
		"cc-chat.adverserial.ai:8443": "cc-chat.adverserial.ai",
		"CC-CHAT.Adverserial.AI:443":  "cc-chat.adverserial.ai",
		"  cc-chat.adverserial.ai ":   "cc-chat.adverserial.ai",
	}
	for in, want := range cases {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q) = %q, want %q", in, got, want)
		}
	}
}
