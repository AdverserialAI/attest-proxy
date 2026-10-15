package server

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// The gate accepts at most 8 MiB of decrypted request JSON. EHBP framing
	// adds a small authenticated overhead; one additional MiB leaves ample room
	// for normal 8 KiB frames while refusing an oversized encrypted upload
	// before it can be buffered or decrypted.
	maxEncryptedConfidentialBody int64 = 9 << 20

	// An inference server on this node admits a small fixed queue. Keep the
	// pre-auth encrypted-body work similarly bounded, so a fan-out cannot turn
	// into unbounded allocations, goroutines, or HPKE work before admission.
	maxConfidentialIngress = 16

	// The request body has a known, small upper bound. This deadline applies
	// only while its body is open; it does not limit a long-lived SSE response.
	maxEncryptedBodyReadDuration = 60 * time.Second
)

// deadlineReadCloser interrupts a stalled request-body read. A handler's
// request context alone does not interrupt a blocking Body.Read, so the timer
// closes the body itself. Closing it when the body is fully consumed stops the
// timer before inference streaming begins.
type deadlineReadCloser struct {
	io.ReadCloser
	once  sync.Once
	timer *time.Timer
	done  chan struct{}
}

func withBodyDeadline(body io.ReadCloser, d time.Duration) *deadlineReadCloser {
	b := &deadlineReadCloser{ReadCloser: body, done: make(chan struct{})}
	// Install the timer before starting its waiter. The done channel lets an
	// ordinary early Close retire the waiter instead of leaking one goroutine
	// per completed request.
	b.timer = time.NewTimer(d)
	go func() {
		select {
		case <-b.timer.C:
			_ = b.Close()
		case <-b.done:
		}
	}()
	return b
}

func (b *deadlineReadCloser) Close() error {
	var err error
	b.once.Do(func() {
		if b.timer != nil {
			b.timer.Stop()
		}
		close(b.done)
		err = b.ReadCloser.Close()
	})
	return err
}

// confidentialIngressGuard applies before the EHBP middleware. It protects
// the encrypted bytes, which otherwise are not subject to the plaintext gate
// limit until after the EHBP implementation has allocated and decrypted them.
func (s *Server) confidentialIngressGuard(next http.Handler) http.Handler {
	return confidentialIngressGuard(next, s.ingressSlots, maxEncryptedConfidentialBody, maxEncryptedBodyReadDuration)
}

func confidentialIngressGuard(next http.Handler, slots chan struct{}, maxBytes int64, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, "/v1/") {
			next.ServeHTTP(w, r)
			return
		}
		if r.ContentLength > maxBytes {
			writeError(w, http.StatusRequestEntityTooLarge, "encrypted request body too large")
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			writeError(w, http.StatusServiceUnavailable, "confidential inference is busy; retry shortly")
			return
		}

		// MaxBytesReader enforces the cap for chunked requests. The deadline
		// wrapper closes this exact reader when an encrypted body stalls.
		limited := http.MaxBytesReader(w, r.Body, maxBytes)
		r.Body = withBodyDeadline(limited, timeout)
		defer r.Body.Close()
		next.ServeHTTP(w, r)
	})
}
