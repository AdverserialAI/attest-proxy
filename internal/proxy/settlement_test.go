package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adverserial/attest-proxy/internal/gate"
	"github.com/adverserial/attest-proxy/internal/meter"
)

// failPoster keeps durable outbox records in place so tests can inspect them
// (the background flush attempt fails and the file is retained).
type failPoster struct{}

func (failPoster) PostMeter(context.Context, string) error { return errors.New("hold record") }

func newTestSettlement(t *testing.T, dir string) *meter.TerminalSettlement {
	t.Helper()
	signer, err := meter.NewTestSigner()
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return meter.NewTerminalSettlement(signer, "https://api.adverserial.ai", "https://billing.adverserial.ai",
		meter.Outbox{Dir: dir, Poster: failPoster{}},
		"reservation-test", "request-test", "lordx64/cyberglm", logger)
}

// settlementChain builds gate(Enforce=false) → settlement injector → proxy
// with tap: the same terminal paths the confidential gate wires in
// production, with the per-request handle the gate would have created.
func settlementChain(t *testing.T, upstream *httptest.Server, settle *meter.TerminalSettlement, sink *recordSink) *httptest.Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	u, _ := url.Parse(upstream.URL)
	tap := &UsageTap{Sink: sink, Logger: logger}
	rp := New(u, logger, nil, tap)
	inject := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rp.ServeHTTP(w, r.WithContext(meter.WithSettlement(r.Context(), settle)))
	})
	g := &gate.Gate{Logger: logger, Enforce: false}
	front := httptest.NewServer(Logging(logger, g.Middleware(inject)))
	t.Cleanup(front.Close)
	return front
}

func waitOutboxRecord(t *testing.T, dir string) []byte {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		entries, _ := os.ReadDir(dir)
		if len(entries) > 1 {
			t.Fatalf("outbox records = %d, want exactly 1", len(entries))
		}
		if len(entries) == 1 {
			if b, err := os.ReadFile(filepath.Join(dir, entries[0].Name())); err == nil && len(b) > 0 {
				return b
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("no outbox record within timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// settlementClaims waits for the single durable meter record and decodes its
// JWS payload.
func settlementClaims(t *testing.T, dir string) map[string]any {
	t.Helper()
	parts := strings.Split(strings.TrimSpace(string(waitOutboxRecord(t, dir))), ".")
	if len(parts) != 3 {
		t.Fatalf("outbox record is not a compact JWS")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func assertSettlement(t *testing.T, m map[string]any, input, cached, output float64) {
	t.Helper()
	if m["typ"] != "adverserial-confidential-meter/v1" {
		t.Errorf("typ = %v", m["typ"])
	}
	if m["jti"] != "reservation-test" || m["request_id"] != "request-test" {
		t.Errorf("identity = %v/%v", m["jti"], m["request_id"])
	}
	if m["model"] != "lordx64/cyberglm" {
		t.Errorf("model = %v", m["model"])
	}
	if m["input_tokens"] != input || m["cached_tokens"] != cached || m["output_tokens"] != output {
		t.Errorf("counts = %v/%v/%v, want %v/%v/%v",
			m["input_tokens"], m["cached_tokens"], m["output_tokens"], input, cached, output)
	}
}

// TestCompletedStreamSettlesRealCountsOnce: a completed stream settles with
// the observed usage counts, exactly once (finalize and Close both settle),
// and the legacy sink stays silent while a settlement handle exists.
func TestCompletedStreamSettlesRealCountsOnce(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, sseBody)
	}))
	defer upstream.Close()

	dir := t.TempDir()
	settle := newTestSettlement(t, dir)
	sink := newRecordSink()
	front := settlementChain(t, upstream, settle, sink)

	resp, err := http.Post(front.URL+"/v1/chat/completions", "application/json", strings.NewReader(chatReq))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != sseBody {
		t.Fatalf("stream not byte-identical:\n got %q\nwant %q", body, sseBody)
	}
	assertSettlement(t, settlementClaims(t, dir), 11, 7, 2)
	sink.expectNone(t, 150*time.Millisecond)
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("outbox records after close = %d, want exactly 1", len(entries))
	}
}

// TestNonStreamingSettlesObservedCounts: the JSON path observes and settles
// through the handle rather than firing the legacy event.
func TestNonStreamingSettlesObservedCounts(t *testing.T) {
	const respBody = `{"id":"c1","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"Hello"}}],"usage":{"prompt_tokens":9,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":4}}}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, respBody)
	}))
	defer upstream.Close()

	dir := t.TempDir()
	settle := newTestSettlement(t, dir)
	sink := newRecordSink()
	front := settlementChain(t, upstream, settle, sink)

	resp, err := http.Post(front.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(strings.Replace(chatReq, `"stream":true`, `"stream":false`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != respBody {
		t.Fatalf("body modified: %s", body)
	}
	assertSettlement(t, settlementClaims(t, dir), 9, 4, 5)
	sink.expectNone(t, 150*time.Millisecond)
}

// TestErrorHandlerSettlesZeros: dial errors (and any transport failure
// before response headers) settle the reservation with zero counts.
func TestErrorHandlerSettlesZeros(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	u, _ := url.Parse("http://127.0.0.1:1") // nothing listening: dial fails
	dir := t.TempDir()
	settle := newTestSettlement(t, dir)
	rp := New(u, logger, nil, &UsageTap{Logger: logger})
	inject := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rp.ServeHTTP(w, r.WithContext(meter.WithSettlement(r.Context(), settle)))
	})
	g := &gate.Gate{Logger: logger, Enforce: false}
	front := httptest.NewServer(Logging(logger, g.Middleware(inject)))
	defer front.Close()

	resp, err := http.Post(front.URL+"/v1/chat/completions", "application/json", strings.NewReader(chatReq))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	assertSettlement(t, settlementClaims(t, dir), 0, 0, 0)
}

// blockingStream writes the given events, flushes, then holds the stream open
// until the proxy cancels the upstream request (client disconnect).
func blockingStream(t *testing.T, events ...string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		for _, ev := range events {
			_, _ = io.WriteString(w, ev)
		}
		if fl != nil {
			fl.Flush()
		}
		<-r.Context().Done()
	}))
}

// readUntilLineContaining reads the response stream until a line containing
// needle arrives, proving that chunk already passed through the tap.
func readUntilLineContaining(t *testing.T, body io.Reader, needle string) {
	t.Helper()
	br := bufio.NewReader(body)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("never saw %q in stream", needle)
		}
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("stream ended before %q: %v", needle, err)
		}
		if strings.Contains(line, needle) {
			return
		}
	}
}

// TestClientAbortAfterUsageSettlesObservedCounts: when the client disconnects
// mid-stream after a usage chunk already passed, settlement carries the
// observed counts.
func TestClientAbortAfterUsageSettlesObservedCounts(t *testing.T) {
	upstream := blockingStream(t,
		"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
		"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":2,\"prompt_tokens_details\":{\"cached_tokens\":7}}}\n\n",
	)
	defer upstream.Close()

	dir := t.TempDir()
	settle := newTestSettlement(t, dir)
	front := settlementChain(t, upstream, settle, newRecordSink())

	resp, err := http.Post(front.URL+"/v1/chat/completions", "application/json", strings.NewReader(chatReq))
	if err != nil {
		t.Fatal(err)
	}
	readUntilLineContaining(t, resp.Body, `"usage"`)
	resp.Body.Close() // client abort mid-stream
	assertSettlement(t, settlementClaims(t, dir), 11, 7, 2)
}

// TestClientAbortBeforeUsageSettlesZeros: when the client disconnects before
// any usage chunk, settlement still fires — with zero counts.
func TestClientAbortBeforeUsageSettlesZeros(t *testing.T) {
	upstream := blockingStream(t,
		"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
	)
	defer upstream.Close()

	dir := t.TempDir()
	settle := newTestSettlement(t, dir)
	front := settlementChain(t, upstream, settle, newRecordSink())

	resp, err := http.Post(front.URL+"/v1/chat/completions", "application/json", strings.NewReader(chatReq))
	if err != nil {
		t.Fatal(err)
	}
	readUntilLineContaining(t, resp.Body, `"delta"`)
	resp.Body.Close()
	assertSettlement(t, settlementClaims(t, dir), 0, 0, 0)
}

// TestSettleRecoverySettlesZeros: a panic in the confidential handler chain
// settles the reservation (zeros — nothing was observed) and answers 500.
func TestSettleRecoverySettlesZeros(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	settle := newTestSettlement(t, dir)
	h := SettleRecovery(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(chatReq))
	req = req.WithContext(meter.WithSettlement(req.Context(), settle))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req) // must not propagate the panic
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	assertSettlement(t, settlementClaims(t, dir), 0, 0, 0)
}

// TestSettleRecoveryWithoutSettlement: with no handle in the context (every
// non-confidential request) recovery still answers 500 and nothing enqueues.
func TestSettleRecoveryWithoutSettlement(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := SettleRecovery(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(chatReq)))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}
