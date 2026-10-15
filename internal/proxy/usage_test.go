package proxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/adverserial/attest-proxy/internal/billing"
	"github.com/adverserial/attest-proxy/internal/gate"
)

// lockedBuffer makes the test logger safe when the proxy's request goroutine
// finishes just after the client has consumed the response.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

type recordSink struct {
	events chan billing.UsageEvent
	err    error
}

func newRecordSink() *recordSink {
	return &recordSink{events: make(chan billing.UsageEvent, 4)}
}

func (s *recordSink) PostUsage(_ context.Context, ev billing.UsageEvent) error {
	if s.err != nil {
		return s.err
	}
	s.events <- ev
	return nil
}

func (s *recordSink) wait(t *testing.T) billing.UsageEvent {
	t.Helper()
	select {
	case ev := <-s.events:
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("no usage event within timeout")
		return billing.UsageEvent{}
	}
}

func (s *recordSink) expectNone(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case ev := <-s.events:
		t.Fatalf("unexpected usage event: %+v", ev)
	case <-time.After(d):
	}
}

// tapChain builds gate(Enforce=false) → proxy with tap, against upstream.
func tapChain(t *testing.T, upstream *httptest.Server, sink *recordSink) *httptest.Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	u, _ := url.Parse(upstream.URL)
	tap := &UsageTap{Sink: sink, Logger: logger}
	g := &gate.Gate{Logger: logger, Enforce: false}
	front := httptest.NewServer(Logging(logger, g.Middleware(New(u, logger, nil, tap))))
	t.Cleanup(front.Close)
	return front
}

const chatReq = `{"model":"lordx64/cyberglm","messages":[{"role":"user","content":"hi"}],"stream":true}`

// sseBody is a realistic chat.completion stream ending in a usage chunk.
var sseBody = "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n" +
	"data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n" +
	"data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":2,\"prompt_tokens_details\":{\"cached_tokens\":7}}}\n\n" +
	"data: [DONE]\n\n"

// TestSSEUsageTapByteIdentical: the client receives the exact upstream bytes
// and the usage event carries the counts from the final chunk.
func TestSSEUsageTapByteIdentical(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		// Write in small pieces, splitting the usage line across flushes to
		// exercise the partial-line path.
		half := strings.Index(sseBody, `"usage"`) + 3
		for _, part := range []string{sseBody[:half], sseBody[half:]} {
			_, _ = io.WriteString(w, part)
			fl.Flush()
			time.Sleep(20 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	sink := newRecordSink()
	front := tapChain(t, upstream, sink)

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

	ev := sink.wait(t)
	if ev.Source != "attest-proxy" || ev.Model != "lordx64/cyberglm" ||
		ev.InputTokens != 11 || ev.CachedTokens != 7 || ev.OutputTokens != 2 {
		t.Errorf("event = %+v", ev)
	}
	if ev.RequestID == "" || ev.TS == "" {
		t.Errorf("event missing request_id/ts: %+v", ev)
	}
	if _, err := time.Parse(time.RFC3339, ev.TS); err != nil {
		t.Errorf("ts not RFC3339: %q", ev.TS)
	}
	// Exactly one event.
	sink.expectNone(t, 150*time.Millisecond)
}

// TestSSEStreamWithoutUsage: a completed stream with no usage chunk still
// settles the reservation — with zero counts (and no legacy usage event).
// rc.21: a completed stream without a usage chunk settles the observed
// deltas (was: zero counts, a free-completion hole).
func TestSSEStreamWithoutUsage(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n")
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
	io.ReadAll(resp.Body)
	resp.Body.Close()
	assertSettlement(t, settlementClaims(t, dir), 0, 0, 1)
	sink.expectNone(t, 200*time.Millisecond)
}

// TestNonStreamingUsage: JSON response is forwarded byte-identical and the
// usage event fires.
func TestNonStreamingUsage(t *testing.T) {
	const respBody = `{"id":"c1","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"Hello"}}],"usage":{"prompt_tokens":9,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":4}}}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, respBody)
	}))
	defer upstream.Close()

	sink := newRecordSink()
	front := tapChain(t, upstream, sink)
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
	ev := sink.wait(t)
	if ev.InputTokens != 9 || ev.CachedTokens != 4 || ev.OutputTokens != 5 {
		t.Errorf("event = %+v", ev)
	}
}

// TestResponsesShapeUsage: the /v1/responses usage shape maps to the same
// billing fields.
func TestResponsesShapeUsage(t *testing.T) {
	const respBody = `{"id":"r1","object":"response","usage":{"input_tokens":21,"output_tokens":8,"input_tokens_details":{"cached_tokens":3}}}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, respBody)
	}))
	defer upstream.Close()

	sink := newRecordSink()
	front := tapChain(t, upstream, sink)
	resp, err := http.Post(front.URL+"/v1/responses", "application/json",
		strings.NewReader(`{"model":"lordx64/cyberglm","input":"hi"}`))
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	ev := sink.wait(t)
	if ev.InputTokens != 21 || ev.CachedTokens != 3 || ev.OutputTokens != 8 {
		t.Errorf("event = %+v", ev)
	}
}

// TestZeroSettlementOnUpstreamError: an upstream error status after dispatch
// still settles the reservation — with zero counts — while the legacy usage
// tap stays silent and the client sees the upstream status unchanged.
func TestZeroSettlementOnUpstreamError(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusInternalServerError} {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"error":{"message":"boom","usage":{"prompt_tokens":1}}}`)
		}))
		dir := t.TempDir()
		settle := newTestSettlement(t, dir)
		sink := newRecordSink()
		front := settlementChain(t, upstream, settle, sink)
		resp, err := http.Post(front.URL+"/v1/chat/completions", "application/json", strings.NewReader(chatReq))
		if err != nil {
			t.Fatal(err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != status {
			t.Errorf("status = %d, want upstream %d", resp.StatusCode, status)
		}
		assertSettlement(t, settlementClaims(t, dir), 0, 0, 0)
		sink.expectNone(t, 150*time.Millisecond)
		front.Close()
		upstream.Close()
	}
}

// TestTapContentNeverLogged: response content passes through the tap without
// reaching the logs.
func TestTapContentNeverLogged(t *testing.T) {
	const marker = "MARKER-tap-content-9x2"
	body := strings.Replace(sseBody, "Hello", marker+"Hello", 1)
	body = strings.Replace(body, "Hel", marker, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, body)
	}))
	defer upstream.Close()

	var logBuf lockedBuffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	u, _ := url.Parse(upstream.URL)
	sink := newRecordSink()
	tap := &UsageTap{Sink: sink, Logger: logger}
	g := &gate.Gate{Logger: logger, Enforce: false}
	front := httptest.NewServer(Logging(logger, g.Middleware(New(u, logger, nil, tap))))
	defer front.Close()

	resp, err := http.Post(front.URL+"/v1/chat/completions", "application/json", strings.NewReader(chatReq))
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	sink.wait(t)
	if strings.Contains(logBuf.String(), marker) {
		t.Fatalf("content marker in logs:\n%s", logBuf.String())
	}
}

// TestUsageWriteFailureDoesNotFailRequest: a failing sink must not affect the
// response at all.
func TestUsageWriteFailureDoesNotFailRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, sseBody)
	}))
	defer upstream.Close()

	sink := newRecordSink()
	sink.err = context.DeadlineExceeded
	front := tapChain(t, upstream, sink)
	resp, err := http.Post(front.URL+"/v1/chat/completions", "application/json", strings.NewReader(chatReq))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != sseBody {
		t.Errorf("status=%d body=%q", resp.StatusCode, body)
	}
	time.Sleep(100 * time.Millisecond) // let the failing write run
}

// rc.20 (V4): a /v1/responses SSE stream nests usage under
// response.completed's "response" object — the tap must extract it or the
// stream settles zero tokens (free inference).
func TestResponsesStreamNestedUsageSettlesRealCounts(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\"}\n\n")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r1\",\"usage\":{\"input_tokens\":12,\"output_tokens\":7,\"input_tokens_details\":{\"cached_tokens\":4}}}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()
	dir := t.TempDir()
	settle := newTestSettlement(t, dir)
	sink := newRecordSink()
	front := settlementChain(t, upstream, settle, sink)
	resp, err := http.Post(front.URL+"/v1/responses", "application/json",
		strings.NewReader(`{"model":"lordx64/cyberglm","input":"hi","stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	assertSettlement(t, settlementClaims(t, dir), 12, 4, 7)
}

// rc.20 (V7): upstream error bodies can carry Python tracebacks and internal
// filesystem paths; the client must get a sanitized JSON error with the
// original status, and the reservation still settles zeros.
func TestUpstreamErrorBodyIsScrubbed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"object":"error","message":"1 validation error:\n  {'type': 'missing', 'loc': ('body', 'file')}\n\n  File \"/sgl-workspace/sglang/python/sglang/srt/entrypoints/http_server.py\", line 42, in something\n    Traceback (most recent call last):"}`)
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
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want upstream 400", resp.StatusCode)
	}
	for _, leak := range []string{`/sgl-workspace`, `File "`, "Traceback"} {
		if strings.Contains(string(body), leak) {
			t.Errorf("scrubbed body still leaks %q: %s", leak, body)
		}
	}
	if !strings.Contains(string(body), "validation error") {
		t.Errorf("scrubbed body lost the useful message head: %s", body)
	}
	assertSettlement(t, settlementClaims(t, dir), 0, 0, 0)
}

// rc.20 defense in depth: even if a request is dispatched on a path outside
// the tap allowlist (the fence should prevent this), the reservation still
// settles instead of dangling.
func TestUntappedPathStillSettles(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"object":"text_completion","usage":{"prompt_tokens":4,"completion_tokens":9}}`)
	}))
	defer upstream.Close()
	dir := t.TempDir()
	settle := newTestSettlement(t, dir)
	sink := newRecordSink()
	front := settlementChain(t, upstream, settle, sink)
	resp, err := http.Post(front.URL+"/v1/completions", "application/json",
		strings.NewReader(`{"model":"lordx64/cyberglm","prompt":"hi"}`))
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	assertSettlement(t, settlementClaims(t, dir), 0, 0, 0)
	sink.expectNone(t, 150*time.Millisecond)
}

// rc.21: an oversized (or unreadable) non-streaming response must never reach
// the client — the response fails with 502 and the reservation settles via
// the ErrorHandler, instead of truncated free content + zero settle.
func TestOversizedNonStreamResponseFailsWith502(t *testing.T) {
	big := make([]byte, maxUsageBody+1024)
	for i := range big {
		big[i] = 'a'
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(big)
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
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (oversized upstream body must not be delivered)", resp.StatusCode)
	}
	if len(body) > maxUsageBody {
		t.Fatalf("client received %d bytes of unmetered content", len(body))
	}
	assertSettlement(t, settlementClaims(t, dir), 0, 0, 0)
}

func TestSanitizeUpstreamMessageStripsPaths(t *testing.T) {
	cases := map[string]string{
		`OSError: /sgl-workspace/sglang/python/sglang/srt/x.py: permission denied`: "permission denied",
		`1 validation error:\n  File "/sgl-workspace/a/b.py", line 1\n    boom`:    "validation error",
		`plain message`: "plain message",
	}
	for in, want := range cases {
		got := sanitizeUpstreamMessage(in)
		for _, leak := range []string{"/sgl-workspace", `File "`} {
			if strings.Contains(got, leak) {
				t.Errorf("sanitize(%q) leaks %q: %q", in, leak, got)
			}
		}
		if !strings.Contains(got, want) {
			t.Errorf("sanitize(%q) = %q, want it to keep %q", in, got, want)
		}
	}
}

func TestOutputDeltas(t *testing.T) {
	cases := []struct {
		payload string
		want    int
	}{
		{`{"choices":[{"delta":{"content":"hi"}}]}`, 1},
		{`{"choices":[{"delta":{"reasoning_content":"thinking"}}]}`, 1},
		{`{"choices":[{"delta":{"content":""}}]}`, 0},
		{`{"choices":[{"delta":{"role":"assistant","content":null}}]}`, 0},
		{`{"choices":[{"text":" world"}]}`, 1},
		{`{"type":"response.output_text.delta","delta":"chunk"}`, 1},
		{`{"type":"response.completed","response":{"usage":{}}}`, 0},
		{`[DONE]`, 0},
		{`not json`, 0},
	}
	for _, tc := range cases {
		if got := outputDeltas([]byte(tc.payload)); got != tc.want {
			t.Errorf("outputDeltas(%s) = %d, want %d", tc.payload, got, tc.want)
		}
	}
}

// rc.23: a malformed upstream emitting many newline-terminated lines without
// a blank separator must never grow the tap unboundedly: the stream aborts
// with a sanitized failure, no receipt chunk, exactly one settlement.
func TestSSEEventByteBudget(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		var b strings.Builder
		for b.Len() < maxSSEEventBytes+4096 {
			b.WriteString("data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n") // never blank
		}
		_, _ = io.WriteString(w, b.String())
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
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if len(body) > maxSSEEventBytes+8192 {
		t.Fatalf("client received %d bytes — event buffer was unbounded", len(body))
	}
	if bytes.Contains(body, []byte("adverserial_receipt")) {
		t.Error("receipt minted for an aborted oversized-event stream")
	}
	m := settlementClaims(t, dir)
	if m["input_tokens"].(float64) != 0 || m["cached_tokens"].(float64) != 0 {
		t.Errorf("input/cached = %v/%v, want 0/0", m["input_tokens"], m["cached_tokens"])
	}
	if m["output_tokens"].(float64) <= 0 {
		t.Error("expected the observed deltas to be settled, got zero output")
	}
}
