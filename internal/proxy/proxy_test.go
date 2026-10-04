package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestSSEStreamingPassthrough proves the proxy does not buffer streamed
// responses: SSE events must arrive incrementally while the upstream is still
// producing them.
func TestSSEStreamingPassthrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Error("upstream ResponseWriter is not a Flusher")
			return
		}
		for i := 0; i < 3; i++ {
			fmt.Fprintf(w, "data: event-%d\n\n", i)
			fl.Flush()
			time.Sleep(150 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := Logging(logger, New(u, logger, nil, nil))
	front := httptest.NewServer(handler)
	defer front.Close()

	start := time.Now()
	resp, err := http.Get(front.URL + "/v1/chat/completions")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	var events []string
	var arrivals []time.Duration
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			events = append(events, line)
			arrivals = append(arrivals, time.Since(start))
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(events) != 3 || events[0] != "data: event-0" || events[2] != "data: event-2" {
		t.Fatalf("events = %v", events)
	}
	// Upstream takes ~450ms total. If the proxy buffered, event-0 would
	// arrive at the very end together with the rest.
	if arrivals[0] > 400*time.Millisecond {
		t.Errorf("first event arrived after %v — response was buffered", arrivals[0])
	}
	if arrivals[2]-arrivals[0] < 200*time.Millisecond {
		t.Errorf("events arrived in a single burst (%v apart) — not streamed", arrivals[2]-arrivals[0])
	}
}

// TestAuthorizationPassthrough: credentials reach the upstream untouched.
func TestAuthorizationPassthrough(t *testing.T) {
	var gotAuth, gotContentType string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	front := httptest.NewServer(Logging(logger, New(u, logger, nil, nil)))
	defer front.Close()

	req, _ := http.NewRequest(http.MethodPost, front.URL+"/v1/chat/completions", strings.NewReader(`{"stream":false}`))
	req.Header.Set("Authorization", "Bearer test-key-123")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "Bearer test-key-123" {
		t.Errorf("upstream Authorization = %q", gotAuth)
	}
	if gotContentType != "application/json" {
		t.Errorf("upstream Content-Type = %q", gotContentType)
	}
}

// TestNoContentLogging sends a unique marker through request headers, request
// body, and response body, then asserts it appears in no log line. This is
// the regression test for the no-content-logging invariant (WP-2): there is
// no LOG_CONTENT escape hatch by design, and this test would catch one.
func TestNoContentLogging(t *testing.T) {
	const marker = "MARKER-7f3a9c2d-never-log-me"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"echo":"%s"}`, marker)
	}))
	defer upstream.Close()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	u, _ := url.Parse(upstream.URL)
	front := httptest.NewServer(Logging(logger, New(u, logger, nil, nil)))
	defer front.Close()

	req, _ := http.NewRequest(http.MethodPost,
		front.URL+"/v1/chat/completions?prompt="+marker, // query strings must not be logged either
		strings.NewReader(`{"messages":[{"role":"user","content":"`+marker+`"}]}`))
	req.Header.Set("Authorization", "Bearer "+marker)
	req.Header.Set("X-Custom", marker)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), marker) {
		t.Fatal("marker did not pass through the proxy — test is broken")
	}

	logs := logBuf.String()
	if strings.Contains(logs, marker) {
		t.Fatalf("log contains content marker:\n%s", logs)
	}
	// Sanity: the request was logged with metadata only.
	if !strings.Contains(logs, "/v1/chat/completions") ||
		!strings.Contains(logs, "POST") ||
		!strings.Contains(logs, "status=200") {
		t.Errorf("expected metadata log line, got:\n%s", logs)
	}
}

// TestUpstreamErrorLoggedWithoutContent: even proxy errors must not leak
// request data beyond method + path class.
func TestUpstreamErrorLoggedWithoutContent(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	u, _ := url.Parse("http://127.0.0.1:1") // nothing listening
	front := httptest.NewServer(Logging(logger, New(u, logger, nil, nil)))
	defer front.Close()

	resp, err := http.Post(front.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"content":"MARKER-should-not-appear"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	if strings.Contains(logBuf.String(), "MARKER") {
		t.Fatalf("error path logged content:\n%s", logBuf.String())
	}
}

func TestPathClass(t *testing.T) {
	cases := map[string]string{
		"/":                                     "/",
		"":                                      "/",
		"/v1/chat/completions":                  "/v1/chat/completions",
		"/v1/models":                            "/v1/models",
		"/v1/models/lordx64/cyberglm":           "/v1/models/:id/cyberglm",
		"/v1/files/file-7f3a9c2d":               "/v1/files/:id",
		"/health":                               "/health",
		"/generate":                             "/generate",
		"/v1/chat/completions/1234567890abcdef": "/v1/chat/completions/:id",
		"/verylongsegmentthatgoesonandonandonandonandon": "/:id",
		"/v1/chat/%2e%2e": "/v1/chat/:id",
	}
	for in, want := range cases {
		if got := PathClass(in); got != want {
			t.Errorf("PathClass(%q) = %q, want %q", in, got, want)
		}
	}
}
