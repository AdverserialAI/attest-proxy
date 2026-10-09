package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/adverserial/attest-proxy/internal/billing"
	"github.com/adverserial/attest-proxy/internal/gate"
	"github.com/adverserial/attest-proxy/internal/meter"
	"github.com/adverserial/attest-proxy/internal/receipt"
)

// UsageSink accepts counts-only usage events (the billing client).
type UsageSink interface {
	PostUsage(ctx context.Context, ev billing.UsageEvent) error
}

// maxUsageBody caps buffering of non-streaming responses for usage parsing.
const maxUsageBody = 8 << 20

// maxSSEScanLine bounds the tap's partial-line buffer; a longer single line
// (pathological) drops scan state but never alters forwarded bytes.
const maxSSEScanLine = 1 << 20

// ReceiptTTL is the WP-7 per-request receipt validity window (iat → exp).
const ReceiptTTL = 120 * time.Second

// ReceiptConfig configures WP-7 per-request enclave receipts. StateDigest
// returns the current (tls_spki_sha256, attestation-state digest) pair cited
// in attestation_binding.
type ReceiptConfig struct {
	Signer      *receipt.Signer
	Issuer      string
	Audience    string
	PolicyID    string
	StateDigest func() (string, string)
}

// ConfidentialMeterConfig produces an authenticated, count-only billing
// record for entitlement-authenticated requests. The durable outbox writes
// before a background delivery attempt, so billing outages cannot turn into
// untraceable/unsettled inference usage.
type ConfidentialMeterConfig struct {
	Signer   *meter.Signer
	Issuer   string
	Audience string
	Outbox   meter.Outbox
}

// UsageTap extracts token counts from /v1/chat/completions and /v1/responses
// responses, reports them to billing, and mints WP-7 per-request receipts.
//
// It reads nothing beyond the usage JSON: non-streaming bodies are buffered
// (they are complete JSON documents), SSE streams are processed per event
// while bytes pass through. Billing writes are fire-and-forget; receipts are
// hash-only and minted locally, so neither blocks the user response.
//
// Stream hashing rule (must match the SDK): for every upstream `data:` line,
// strip the trailing CR, drop "data:" and ONE leading space, and feed the
// remaining payload bytes to the stream hash — including the final "[DONE]"
// sentinel, excluding the proxy-injected receipt chunk.
type UsageTap struct {
	Sink     UsageSink                // may be nil (billing disabled)
	Receipts *ReceiptConfig           // may be nil (receipts disabled)
	Meter    *ConfidentialMeterConfig // nil retains legacy usage event behavior
	Logger   *slog.Logger

	now func() time.Time // test hook
}

// tappablePath limits tapping to the usage-bearing routes.
func tappablePath(p string) bool {
	return p == "/v1/chat/completions" || p == "/v1/responses"
}

// ModifyResponse implements httputil.ReverseProxy.ModifyResponse.
func (t *UsageTap) ModifyResponse(resp *http.Response) error {
	req := resp.Request
	if req == nil || req.Method != http.MethodPost || !tappablePath(req.URL.Path) {
		return nil
	}
	info := gate.RequestInfoFrom(req.Context())
	if info == nil || info.Model == "" {
		return nil // no attribution available (e.g. oversized body)
	}
	if resp.StatusCode != http.StatusOK {
		// Upstream rejected or failed after dispatch: settle with zero counts
		// so billing can release the reservation. No usage event, no receipt.
		meter.SettlementFrom(req.Context()).Settle()
		return nil
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	switch {
	case strings.HasPrefix(ct, "text/event-stream"):
		resp.Body = newSSETap(resp.Body, t, info, meter.SettlementFrom(req.Context()))
	case ct == "" || strings.Contains(ct, "application/json"):
		settle := meter.SettlementFrom(req.Context())
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxUsageBody+1))
		_ = resp.Body.Close()
		if err != nil || len(body) > maxUsageBody {
			restoreBody(resp, body)
			settle.Settle() // unparsable response: best-known counts are zeros
			return nil
		}
		restoreBody(resp, body)
		usage, hasUsage := extractUsageJSON(body)
		var usagePtr *usageCounts
		if hasUsage {
			u := usage
			usagePtr = &u
		}
		if usagePtr != nil {
			if settle != nil {
				settle.Observe(usagePtr.Input, usagePtr.Cached, usagePtr.Output)
				settle.Settle()
			} else {
				t.fire(info, *usagePtr)
			}
		} else {
			settle.Settle() // 200 without a usage object: settle zeros
		}
		if t.Receipts != nil {
			sum := sha256.Sum256(body)
			jws, err := t.mintReceipt(info, "sha256:"+base64.RawURLEncoding.EncodeToString(sum[:]), usagePtr)
			if err == nil {
				resp.Header.Set("X-Adverserial-Receipt", jws)
			} else if t.Logger != nil {
				t.Logger.Warn("receipt minting failed", "error", err.Error())
			}
		}
	default:
		// Unexpected 200 content type: the body forwards untouched; settle
		// with zero counts (best-known) so the reservation cannot leak.
		meter.SettlementFrom(req.Context()).Settle()
	}
	return nil
}

// mintReceipt signs the WP-7 per-request receipt (hash-only claims).
func (t *UsageTap) mintReceipt(info *gate.RequestInfo, responseHash string, usage *usageCounts) (string, error) {
	cfg := t.Receipts
	tlsSPKI, stateDigest := cfg.StateDigest()
	now := t.nowFn().Unix()
	claims := map[string]any{
		"v":                 1,
		"iss":               cfg.Issuer,
		"aud":               cfg.Audience,
		"request_nonce":     info.RequestNonce,
		"request_body_hash": info.RequestBodyHash,
		"response_hash":     responseHash,
		"model_id":          info.Model,
		"policy_id":         cfg.PolicyID,
		"attestation_binding": map[string]any{
			"tls_spki_sha256": tlsSPKI,
			"evidence_digest": stateDigest,
		},
		"iat": now,
		"exp": now + int64(ReceiptTTL/time.Second),
	}
	if usage != nil {
		claims["usage"] = map[string]any{
			"input_tokens":  usage.Input,
			"cached_tokens": usage.Cached,
			"output_tokens": usage.Output,
		}
	}
	return cfg.Signer.Mint(claims)
}

// fire posts the usage event in the background with a short timeout. It
// serves the legacy Sink path and the confidential fallback when the request
// carries no terminal settlement handle (the gate always attaches one in
// confidential mode, so the settlement path is authoritative there).
func (t *UsageTap) fire(info *gate.RequestInfo, u usageCounts) {
	if t.Meter != nil && info.ReservationID != "" {
		token, claims, err := meter.Build(t.Meter.Signer, info.ReservationID, info.RequestID,
			info.Model, t.Meter.Issuer, t.Meter.Audience, u.Input, u.Cached, u.Output, t.nowFn().UTC())
		if err != nil {
			if t.Logger != nil {
				t.Logger.Error("confidential meter signing failed", "request_id", info.RequestID, "error", err.Error())
			}
			return
		}
		if err := t.Meter.Outbox.Enqueue(token, claims); err != nil {
			if t.Logger != nil {
				t.Logger.Error("confidential meter persistence failed", "request_id", info.RequestID, "error", err.Error())
			}
			return
		}
		logger := t.Logger
		outbox := t.Meter.Outbox
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := outbox.Flush(ctx); err != nil && logger != nil {
				logger.Warn("confidential meter delivery deferred", "request_id", info.RequestID, "error", err.Error())
			}
		}()
		return
	}
	if t.Sink == nil {
		return
	}
	ev := billing.UsageEvent{
		Source:       "attest-proxy",
		Model:        info.Model,
		APIKeyPrefix: info.KeyPrefix,
		InputTokens:  u.Input,
		CachedTokens: u.Cached,
		OutputTokens: u.Output,
		RequestID:    info.RequestID,
		TS:           t.nowFn().UTC().Format(time.RFC3339),
	}
	logger := t.Logger
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := t.Sink.PostUsage(ctx, ev); err != nil && logger != nil {
			logger.Warn("usage write failed",
				"request_id", ev.RequestID, "model", ev.Model, "error", err.Error())
		}
	}()
}

func (t *UsageTap) nowFn() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

// usageCounts are the three numbers billing accepts.
type usageCounts struct {
	Input  int
	Cached int
	Output int
}

// usageJSON covers both the chat-completions shape (prompt_tokens,
// completion_tokens, prompt_tokens_details.cached_tokens) and the responses
// shape (input_tokens, output_tokens, input_tokens_details.cached_tokens).
type usageJSON struct {
	PromptTokens     *int `json:"prompt_tokens"`
	CompletionTokens *int `json:"completion_tokens"`
	InputTokens      *int `json:"input_tokens"`
	OutputTokens     *int `json:"output_tokens"`
	PromptDetails    *struct {
		CachedTokens int `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
	InputDetails *struct {
		CachedTokens int `json:"cached_tokens"`
	} `json:"input_tokens_details"`
}

// extractUsageJSON parses a JSON document or SSE data payload and returns
// counts when it carries a non-null usage object.
func extractUsageJSON(body []byte) (usageCounts, bool) {
	var doc struct {
		Usage *usageJSON `json:"usage"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Usage == nil {
		return usageCounts{}, false
	}
	u := doc.Usage
	var out usageCounts
	switch {
	case u.PromptTokens != nil: // chat completions shape
		out.Input = *u.PromptTokens
		if u.CompletionTokens != nil {
			out.Output = *u.CompletionTokens
		}
		if u.PromptDetails != nil {
			out.Cached = u.PromptDetails.CachedTokens
		}
	case u.InputTokens != nil: // responses shape
		out.Input = *u.InputTokens
		if u.OutputTokens != nil {
			out.Output = *u.OutputTokens
		}
		if u.InputDetails != nil {
			out.Cached = u.InputDetails.CachedTokens
		}
	default:
		return usageCounts{}, false
	}
	return out, true
}

// sseTapReader processes a text/event-stream: it hashes every upstream data
// payload (stream-final hash), captures the usage chunk, holds back a
// terminal "data: [DONE]" event, and at upstream EOF emits the WP-7 receipt
// chunk followed by the held [DONE] — upstream events are never dropped or
// reordered, and without a ReceiptConfig the byte stream is untouched.
type sseTapReader struct {
	rc     io.ReadCloser
	tap    *UsageTap
	info   *gate.RequestInfo
	settle *meter.TerminalSettlement // nil outside confidential mode

	buf     [32 * 1024]byte
	in      []byte // bytes not yet split into complete lines
	cur     []byte // bytes of the event currently being accumulated
	out     []byte // passthrough bytes ready to emit
	hold    []byte // held terminal [DONE] event
	curDone bool   // current event's data payload is [DONE]
	eof     bool
	err     error // deferred non-EOF read error
	done    bool  // finalize ran

	hasher hash.Hash
	usage  *usageCounts
	fired  bool
}

func newSSETap(rc io.ReadCloser, tap *UsageTap, info *gate.RequestInfo, settle *meter.TerminalSettlement) *sseTapReader {
	return &sseTapReader{rc: rc, tap: tap, info: info, settle: settle, hasher: sha256.New()}
}

func (r *sseTapReader) Read(p []byte) (int, error) {
	for len(r.out) == 0 {
		if r.eof {
			r.finalize()
			if len(r.out) == 0 {
				if r.err != nil {
					return 0, r.err
				}
				return 0, io.EOF
			}
			break
		}
		n, err := r.rc.Read(r.buf[:])
		if n > 0 {
			r.process(r.buf[:n])
		}
		if err == io.EOF {
			r.eof = true
			continue
		}
		if err != nil {
			// Hard upstream error: flush everything verbatim, no receipt.
			r.out = append(r.out, r.in...)
			r.out = append(r.out, r.cur...)
			r.out = append(r.out, r.hold...)
			r.in, r.cur, r.hold = nil, nil, nil
			r.err = err
			r.eof = true
		}
	}
	n := copy(p, r.out)
	r.out = r.out[n:]
	return n, nil
}

func (r *sseTapReader) Close() error {
	if !r.eof {
		// Aborted stream (client disconnect): no receipt — it would cover a
		// partial stream. Still report captured usage to the legacy sink.
		r.fireUsage()
	}
	// Client abort, or the post-EOF close of a completed stream: settle
	// exactly once with the observed counts (zeros when none arrived).
	r.settle.Settle()
	return r.rc.Close()
}

// process splits newly read bytes into lines and dispatches complete events.
func (r *sseTapReader) process(data []byte) {
	r.in = append(r.in, data...)
	for {
		i := bytes.IndexByte(r.in, '\n')
		if i < 0 {
			if len(r.in) > maxSSEScanLine {
				// Pathological line: forward raw, drop scan state.
				r.cur = append(r.cur, r.in...)
				r.in = nil
			}
			return
		}
		line := r.in[:i]
		r.in = r.in[i+1:]
		r.scanLine(line)
		r.cur = append(r.cur, line...)
		r.cur = append(r.cur, '\n')
		if isBlankLine(line) {
			r.dispatchEvent()
		}
	}
}

// scanLine feeds the stream hash and usage extractor. line excludes the LF.
func (r *sseTapReader) scanLine(line []byte) {
	raw := bytes.TrimSuffix(line, []byte("\r"))
	if !bytes.HasPrefix(raw, []byte("data:")) {
		return
	}
	payload := raw[len("data:"):]
	if len(payload) > 0 && payload[0] == ' ' {
		payload = payload[1:]
	}
	r.hasher.Write(payload)
	if bytes.Equal(payload, []byte("[DONE]")) {
		r.curDone = true
		return
	}
	if !bytes.Contains(payload, []byte(`"usage"`)) {
		return
	}
	if u, ok := extractUsageJSON(payload); ok {
		u := u
		r.usage = &u
		r.settle.Observe(u.Input, u.Cached, u.Output)
	}
}

// dispatchEvent forwards a complete SSE event, or holds a terminal [DONE].
func (r *sseTapReader) dispatchEvent() {
	if r.curDone {
		r.hold = append(r.hold, r.cur...)
	} else {
		r.out = append(r.out, r.cur...)
	}
	r.cur = nil
	r.curDone = false
}

// finalize runs at upstream EOF: flush any partial trailing event, fire
// usage, mint the receipt chunk, and release the held [DONE] after it.
func (r *sseTapReader) finalize() {
	if r.done {
		return
	}
	r.done = true
	if len(r.in) > 0 {
		r.scanLine(r.in)
		r.cur = append(r.cur, r.in...)
		r.in = nil
	}
	if len(r.cur) > 0 {
		r.dispatchEvent()
	}
	r.fireUsage()
	// Terminal settle at upstream EOF: a completed stream carries the real
	// observed counts, a usage-less stream settles zeros. Exactly once.
	r.settle.Settle()
	if r.tap.Receipts != nil && r.err == nil {
		if jws, err := r.tap.mintReceipt(r.info, "sha256:"+base64.RawURLEncoding.EncodeToString(r.hasher.Sum(nil)), r.usage); err == nil {
			chunk, _ := json.Marshal(map[string]string{"adverserial_receipt": jws})
			r.out = append(r.out, "data: "...)
			r.out = append(r.out, chunk...)
			r.out = append(r.out, '\n', '\n')
		} else if r.tap.Logger != nil {
			r.tap.Logger.Warn("receipt minting failed", "error", err.Error())
		}
	}
	r.out = append(r.out, r.hold...)
	r.hold = nil
}

func (r *sseTapReader) fireUsage() {
	if r.fired || r.usage == nil {
		return
	}
	r.fired = true
	// With a settlement handle the meter event is Settle's job (exactly once,
	// carrying the observed counts); fire serves only the legacy sink path.
	if r.settle == nil {
		r.tap.fire(r.info, *r.usage)
	}
}

func isBlankLine(line []byte) bool {
	return len(line) == 0 || (len(line) == 1 && line[0] == '\r')
}
