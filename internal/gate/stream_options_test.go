package gate

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestInjectIncludeUsage: only streaming POST /v1/chat/completions bodies are
// rewritten; other stream_options keys survive and include_usage is forced.
func TestInjectIncludeUsage(t *testing.T) {
	t.Run("stream gets include_usage", func(t *testing.T) {
		out, ok := injectIncludeUsage("/v1/chat/completions", []byte(`{"model":"m","stream":true}`))
		if !ok {
			t.Fatal("not injected")
		}
		var doc map[string]any
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatal(err)
		}
		opts, _ := doc["stream_options"].(map[string]any)
		if opts["include_usage"] != true {
			t.Errorf("stream_options = %v", doc["stream_options"])
		}
		if doc["model"] != "m" || doc["stream"] != true {
			t.Errorf("other fields disturbed: %v", doc)
		}
	})

	t.Run("existing stream_options keys preserved", func(t *testing.T) {
		out, ok := injectIncludeUsage("/v1/chat/completions",
			[]byte(`{"model":"m","stream":true,"stream_options":{"seed":7,"include_usage":false}}`))
		if !ok {
			t.Fatal("not injected")
		}
		var doc map[string]any
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatal(err)
		}
		opts, _ := doc["stream_options"].(map[string]any)
		if opts["seed"] != float64(7) {
			t.Errorf("existing key lost: %v", opts)
		}
		if opts["include_usage"] != true {
			t.Errorf("include_usage not forced true: %v", opts)
		}
	})

	t.Run("null stream_options replaced", func(t *testing.T) {
		out, ok := injectIncludeUsage("/v1/chat/completions", []byte(`{"model":"m","stream":true,"stream_options":null}`))
		if !ok {
			t.Fatal("not injected")
		}
		var doc map[string]any
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatal(err)
		}
		opts, _ := doc["stream_options"].(map[string]any)
		if opts["include_usage"] != true {
			t.Errorf("stream_options = %v", doc["stream_options"])
		}
	})

	untouched := []struct{ name, path, body string }{
		{"non-stream request", "/v1/chat/completions", `{"model":"m"}`},
		{"stream false", "/v1/chat/completions", `{"model":"m","stream":false}`},
		{"responses route", "/v1/responses", `{"model":"m","stream":true}`},
		{"malformed json", "/v1/chat/completions", `{"model":"m","stream":true`},
		{"malformed stream_options", "/v1/chat/completions", `{"model":"m","stream":true,"stream_options":[1]}`},
	}
	for _, tc := range untouched {
		t.Run(tc.name, func(t *testing.T) {
			if out, ok := injectIncludeUsage(tc.path, []byte(tc.body)); ok || out != nil {
				t.Errorf("injected into %s: ok=%v out=%s", tc.name, ok, out)
			}
		})
	}
}

// TestGateInjectsIncludeUsageAfterBinding: the upstream-bound body carries
// include_usage while the receipt binding (request body hash) and the
// entitlement input bound still describe the client's original bytes, and
// Content-Length tracks the rewritten body.
func TestGateInjectsIncludeUsageAfterBinding(t *testing.T) {
	g := &Gate{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Enforce: false}
	var gotBody []byte
	var gotContentLength int64
	var gotHash string
	h := g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotContentLength = r.ContentLength
		if info := RequestInfoFrom(r.Context()); info != nil {
			gotHash = info.RequestBodyHash
		}
		w.WriteHeader(http.StatusOK)
	}))

	const original = `{"model":"m","stream":true,"stream_options":{"seed":7},"messages":[{"role":"user","content":"hi"}]}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(original)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(gotBody, &doc); err != nil {
		t.Fatal(err)
	}
	opts, _ := doc["stream_options"].(map[string]any)
	if opts["include_usage"] != true || opts["seed"] != float64(7) {
		t.Errorf("upstream stream_options = %v", doc["stream_options"])
	}
	if gotContentLength != int64(len(gotBody)) {
		t.Errorf("Content-Length = %d, body %d", gotContentLength, len(gotBody))
	}
	sum := sha256.Sum256([]byte(original))
	if want := "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:]); gotHash != want {
		t.Errorf("RequestBodyHash = %q, want original-body %q", gotHash, want)
	}

	// Non-stream requests forward byte-identical.
	const plain = `{"model":"m","messages":[]}`
	gotBody = nil
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(plain)))
	if string(gotBody) != plain {
		t.Errorf("non-stream body modified: %s", gotBody)
	}

	// /v1/responses streams forward byte-identical.
	const responses = `{"model":"m","stream":true,"input":"hi"}`
	gotBody = nil
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(responses)))
	if string(gotBody) != responses {
		t.Errorf("/v1/responses body modified: %s", gotBody)
	}
}

// rc.20 (V3): the upstream coerces non-boolean truthy stream flags — the
// injection must cover every spelling that actually streams, or the stream
// settles zero tokens (free inference).
func TestInjectIncludeUsageTruthyStreamVariants(t *testing.T) {
	inject := []string{`true`, `1`, `"true"`, `"yes"`, `"on"`, `"1"`}
	for _, v := range inject {
		body := []byte(`{"model":"m/x","stream":` + v + `,"max_tokens":8}`)
		out, ok := injectIncludeUsage("/v1/chat/completions", body)
		if !ok {
			t.Errorf("stream=%s must inject include_usage", v)
			continue
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatalf("rewritten body is not JSON: %v", err)
		}
		var opts struct {
			IncludeUsage bool `json:"include_usage"`
		}
		if err := json.Unmarshal(doc["stream_options"], &opts); err != nil || !opts.IncludeUsage {
			t.Errorf("stream=%s: include_usage missing after rewrite", v)
		}
	}
	skip := []string{`false`, `0`, `null`, `"false"`, `"0"`, `"no"`, `"off"`, `""`}
	for _, v := range skip {
		body := []byte(`{"model":"m/x","stream":` + v + `,"max_tokens":8}`)
		if _, ok := injectIncludeUsage("/v1/chat/completions", body); ok {
			t.Errorf("stream=%s must not be treated as streaming", v)
		}
	}
}
