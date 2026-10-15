package server

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConfidentialIngressGuardRejectsOversizedDeclaredBody(t *testing.T) {
	called := false
	h := confidentialIngressGuard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}), make(chan struct{}, 1), 16, time.Second)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("x"))
	req.ContentLength = 17
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rr.Code)
	}
	if called {
		t.Fatal("oversized body reached the EHBP handler")
	}
}

func TestConfidentialIngressGuardBoundsConcurrentPreAuthWork(t *testing.T) {
	slots := make(chan struct{}, 1)
	entered := make(chan struct{})
	release := make(chan struct{})
	h := confidentialIngressGuard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(entered)
		<-release
	}), slots, 1024, time.Second)

	done := make(chan struct{})
	go func() {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("x")))
		close(done)
	}()
	<-entered

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("x")))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
	close(release)
	<-done
}

type blockingBody struct {
	once   sync.Once
	closed chan struct{}
}

func newBlockingBody() *blockingBody { return &blockingBody{closed: make(chan struct{})} }

func (b *blockingBody) Read([]byte) (int, error) {
	<-b.closed
	return 0, errors.New("body closed")
}

func (b *blockingBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

func TestConfidentialIngressGuardClosesStalledBody(t *testing.T) {
	body := newBlockingBody()
	h := confidentialIngressGuard(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
	}), make(chan struct{}, 1), 1024, 20*time.Millisecond)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Body, req.ContentLength = body, -1

	done := make(chan struct{})
	go func() {
		h.ServeHTTP(httptest.NewRecorder(), req)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("stalled request body was not closed by deadline")
	}
}
