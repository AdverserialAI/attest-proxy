package meter

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// TerminalSettlement guarantees exactly one meter event per dispatched
// confidential request, on every terminal path: upstream success, upstream
// error status, transport failure, client abort, and handler panic. The gate
// creates one after the start precondition succeeds and stashes it in the
// request context; each terminal path calls Settle and the first call wins.
//
// Counts are best-known: terminal paths that observed a usage chunk report it
// via Observe before Settle, everything else settles zeros so billing can
// release the reservation instead of leaking it. The outbox filename dedupes
// on (reservation, request_id), so even a duplicated enqueue is harmless —
// the sync.Once keeps the ordering deterministic.
type TerminalSettlement struct {
	signer      *Signer
	issuer      string
	audience    string
	outbox      Outbox
	reservation string
	requestID   string
	model       string
	logger      *slog.Logger

	once sync.Once
	mu   sync.Mutex
	// latest observed counts; all zero until a usage chunk is observed
	input, cached, output int
}

// NewTerminalSettlement builds the per-request handle. A nil logger disables
// delivery warnings.
func NewTerminalSettlement(signer *Signer, issuer, audience string, outbox Outbox, reservation, requestID, model string, logger *slog.Logger) *TerminalSettlement {
	return &TerminalSettlement{
		signer:      signer,
		issuer:      issuer,
		audience:    audience,
		outbox:      outbox,
		reservation: reservation,
		requestID:   requestID,
		model:       model,
		logger:      logger,
	}
}

// Observe records the latest known usage counts, clamped to what the meter
// signer accepts: a buggy upstream emitting negative counts or cached>input
// must never silently drop the settlement (that leaks the reservation).
// It is a no-op on a nil handle (non-confidential requests carry none).
func (s *TerminalSettlement) Observe(input, cached, output int) {
	if s == nil {
		return
	}
	input, cached, output = max(input, 0), max(cached, 0), max(output, 0)
	cached = min(cached, input)
	s.mu.Lock()
	s.input, s.cached, s.output = input, cached, output
	s.mu.Unlock()
}

// Settle enqueues the terminal meter event with the latest observed counts
// (all zeros when none) and kicks a background delivery attempt. Only the
// first call has an effect. It is a no-op on a nil handle.
func (s *TerminalSettlement) Settle() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		s.mu.Lock()
		input, cached, output := s.input, s.cached, s.output
		s.mu.Unlock()
		token, claims, err := Build(s.signer, s.reservation, s.requestID, s.model, s.issuer, s.audience, input, cached, output, time.Now().UTC())
		if err != nil {
			// A settlement must never be dropped: retry with zero counts so the
			// reservation at least releases (the alternative is a silent leak
			// whenever the upstream emits unusable counts).
			if s.logger != nil {
				s.logger.Error("confidential meter signing failed; settling zeros", "request_id", s.requestID, "error", err.Error())
			}
			token, claims, err = Build(s.signer, s.reservation, s.requestID, s.model, s.issuer, s.audience, 0, 0, 0, time.Now().UTC())
			if err != nil {
				if s.logger != nil {
					s.logger.Error("confidential meter zero-settlement signing failed", "request_id", s.requestID, "error", err.Error())
				}
				return
			}
		}
		if err := s.outbox.Enqueue(token, claims); err != nil {
			// Persistence failures (full/failing volume) must not lose the
			// settlement either: retry in the background for a bounded window.
			if s.logger != nil {
				s.logger.Error("confidential meter persistence failed; retrying in background", "request_id", s.requestID, "error", err.Error())
			}
			go s.retryEnqueue(token, claims)
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := s.outbox.Flush(ctx); err != nil && s.logger != nil {
				s.logger.Warn("confidential meter delivery deferred", "request_id", s.requestID, "error", err.Error())
			}
		}()
	})
}

// retryEnqueue retries a failed outbox write for a bounded window. Losing the
// record is worse than a late one: an unsettled started reservation holds the
// account's concurrency and reserved funds until billing-side expiry.
func (s *TerminalSettlement) retryEnqueue(token string, claims Claims) {
	for attempt := 0; attempt < 6; attempt++ {
		time.Sleep(10 * time.Second)
		if err := s.outbox.Enqueue(token, claims); err == nil {
			if s.logger != nil {
				s.logger.Info("confidential meter persisted after retry", "request_id", s.requestID, "attempt", attempt+1)
			}
			return
		}
	}
	if s.logger != nil {
		s.logger.Error("confidential meter persistence permanently failed", "request_id", s.requestID)
	}
}

type settlementCtxKey struct{}

// WithSettlement attaches the per-request settlement handle to ctx.
func WithSettlement(ctx context.Context, s *TerminalSettlement) context.Context {
	return context.WithValue(ctx, settlementCtxKey{}, s)
}

// SettlementFrom returns the settlement handle attached by the gate, or nil
// for requests without one (every non-confidential request).
func SettlementFrom(ctx context.Context) *TerminalSettlement {
	s, _ := ctx.Value(settlementCtxKey{}).(*TerminalSettlement)
	return s
}
