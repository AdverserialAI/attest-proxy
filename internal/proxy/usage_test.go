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
	"testing"
	"time"

	"github.com/adverserial/attest-proxy/internal/billing"
	"github.com/adverserial/attest-proxy/internal/gate"
)

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

// TestSSEStreamWithoutUsage: no usage chunk → no billing write.
func TestSSEStreamWithoutUsage(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n")
	}))
	defer upstream.Close()

	sink := newRecordSink()
	front := tapChain(t, upstream, sink)
	resp, err := http.Post(front.URL+"/v1/chat/completions", "application/json", strings.NewReader(chatReq))
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	time.Sleep(100 * time.Millisecond) // let any fire happen
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

// TestNoUsageEventOnUpstreamError: error responses produce no usage write.
func TestNoUsageEventOnUpstreamError(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusInternalServerError} {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"error":{"message":"boom","usage":{"prompt_tokens":1}}}`)
		}))
		sink := newRecordSink()
		front := tapChain(t, upstream, sink)
		resp, err := http.Post(front.URL+"/v1/chat/completions", "application/json", strings.NewReader(chatReq))
		if err != nil {
			t.Fatal(err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		front.Close()
		upstream.Close()
		time.Sleep(100 * time.Millisecond)
		sink.expectNone(t, 150*time.Millisecond)
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

	var logBuf bytes.Buffer
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
