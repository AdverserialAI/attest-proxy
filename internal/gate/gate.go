// Package gate implements the auth gate for /v1/ POST routes and the shared
// request-info extraction (model, key prefix, request id) used by both the
// gate and the usage tap.
//
// Fail-closed rules: billing unreachable or non-200 → 503, no inference. In
// confidential mode the same rule covers the /cc/start dispatch precondition:
// a reservation whose start billing cannot durably record is never
// dispatched. The client API key is never logged; denials log the 8-char
// prefix only.
package gate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/adverserial/attest-proxy/internal/attestation"
	"github.com/adverserial/attest-proxy/internal/billing"
	"github.com/adverserial/attest-proxy/internal/entitlement"
	"github.com/adverserial/attest-proxy/internal/meter"
)

// maxModelParseBody caps how much of a request body the gate buffers to
// extract the model field. Larger requests are rejected when auth is
// enforced (or proxied without usage attribution when it is not).
const maxModelParseBody = 64 << 20

// RequestInfo carries per-request attribution and binding data extracted from
// the request: model id, the client key's 8-char prefix, a fresh request id,
// the request nonce (client-supplied X-Adverserial-Nonce or generated), and
// the hash of the exact body bytes forwarded upstream.
type RequestInfo struct {
	Model           string
	KeyPrefix       string
	RequestID       string
	RequestNonce    string // base64url, echoed in the WP-7 receipt
	RequestBodyHash string // "sha256:<base64url>" of the raw request body
	ReservationID   string // opaque entitlement jti; never logged or forwarded
}

type ctxKey struct{}

// RequestInfoFrom returns the RequestInfo attached by the gate middleware.
func RequestInfoFrom(ctx context.Context) *RequestInfo {
	info, _ := ctx.Value(ctxKey{}).(*RequestInfo)
	return info
}

// MeterConfig carries the METER_* configuration the gate needs for the
// reservation lifecycle: signing /cc/start events and building per-request
// terminal settlements. The outbox is the same durable outbox the usage tap
// flushes.
type MeterConfig struct {
	Signer   *meter.Signer
	Issuer   string
	Audience string
	Outbox   meter.Outbox
}

// Gate is the auth middleware. Enforce=false disables the billing check (the
// middleware still extracts RequestInfo for usage attribution).
type Gate struct {
	Billing *billing.Client
	Logger  *slog.Logger
	Enforce bool

	// Confidential replaces raw-key billing authorization. Entitlements carry
	// one model-scoped, channel-bound request authorization and are validated
	// entirely inside the CVM. The replay store must live on persistent storage.
	Confidential bool
	// ConfidentialActive is false during evidence collection. In that state the
	// proxy deliberately returns before it reads a request body, so a prompt
	// cannot reach the CVM before the published policy is independently bound.
	ConfidentialActive bool
	Entitlements       *entitlement.Validator
	Replay             *entitlement.UsedStore
	ActiveSPKI         func() string

	// Meter wires the confidential reservation lifecycle into the gate: the
	// fail-closed /cc/start dispatch precondition and the per-request terminal
	// settlement handle stashed in the request context. Required when
	// Confidential is true; ignored otherwise.
	Meter *MeterConfig

	TTL time.Duration // verdict cache lifetime, default 60s

	mu    sync.Mutex
	cache map[string]cacheEntry

	newRequestID func() string // test hook
}

type cacheEntry struct {
	verdict billing.Verdict
	expires time.Time
}

// Middleware returns the gate middleware wrapping the /v1/ proxy handler.
func (g *Gate) Middleware(next http.Handler) http.Handler {
	if g.Logger == nil {
		g.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if g.newRequestID == nil {
		g.newRequestID = newUUID
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, "/v1/") {
			next.ServeHTTP(w, r)
			return
		}
		if g.Confidential && (g.Entitlements == nil || g.Replay == nil || g.ActiveSPKI == nil || g.Meter == nil || g.Billing == nil) {
			writeError(w, http.StatusServiceUnavailable, "confidential authorization not configured")
			return
		}
		if g.Confidential && !g.ConfidentialActive {
			writeError(w, http.StatusServiceUnavailable, "confidential inference is not active; attestation evidence collection is in progress")
			return
		}
		if g.Enforce && g.Billing == nil {
			// Fail closed: misconfiguration must never serve inference.
			writeError(w, http.StatusServiceUnavailable, "authentication not configured")
			return
		}

		key, hasKey := bearerKey(r)
		if (g.Enforce || g.Confidential) && !hasKey {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}

		// Buffer the body once; the model field is needed for the auth check
		// and for usage attribution. The buffered body is restored verbatim
		// for the upstream.
		body, restore, over, err := readBody(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "could not read request body")
			return
		}
		if over {
			if g.Enforce {
				writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
			r.Body = restore() // proxy without attribution
			next.ServeHTTP(w, r)
			return
		}
		r.Body = restore()
		r.ContentLength = int64(len(body))

		var parsed struct {
			Model     string `json:"model"`
			MaxTokens *int   `json:"max_tokens"`
		}
		_ = json.Unmarshal(body, &parsed) // malformed JSON → empty model
		if (g.Enforce || g.Confidential) && parsed.Model == "" {
			writeError(w, http.StatusBadRequest, "request body must be JSON with a \"model\" field")
			return
		}

		// WP-7 request nonce: client-supplied X-Adverserial-Nonce when valid,
		// otherwise generated here and returned via the receipt.
		nonce := r.Header.Get("X-Adverserial-Nonce")
		if nonce != "" {
			if _, err := attestation.ValidateNonce(nonce); err != nil {
				writeError(w, http.StatusBadRequest, "invalid X-Adverserial-Nonce: "+err.Error())
				return
			}
		} else {
			nonce = newNonce()
		}
		bodySum := sha256.Sum256(body)
		// The client's exact body length is the entitlement input bound and the
		// receipt binds the client's exact bytes; both are captured before the
		// upstream-bound body is rewritten below.
		clientBodyLen := len(body)

		info := &RequestInfo{
			Model:           parsed.Model,
			KeyPrefix:       keyPrefix(key),
			RequestID:       g.newRequestID(),
			RequestNonce:    nonce,
			RequestBodyHash: "sha256:" + base64.RawURLEncoding.EncodeToString(bodySum[:]),
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, info))

		// Streaming chat completions always carry stream_options.include_usage
		// upstream so a completed stream ends in a usage chunk and terminal
		// settlement reports real counts. The client's original body hash and
		// input bound above are unaffected.
		if upstreamBody, ok := injectIncludeUsage(r.URL.Path, body); ok {
			body = upstreamBody
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		}

		if g.Confidential {
			// A byte-level tokenizer cannot emit more tokens than UTF-8 bytes;
			// using the exact raw JSON body is therefore a conservative local
			// input bound without parsing or retaining prompt content.
			if parsed.MaxTokens == nil || *parsed.MaxTokens < 1 {
				writeError(w, http.StatusBadRequest, "confidential requests require a positive max_tokens")
				return
			}
			claims, err := g.Entitlements.Validate(key, parsed.Model, g.ActiveSPKI(), clientBodyLen, *parsed.MaxTokens)
			if err != nil {
				g.Logger.Info("confidential entitlement denied", "model", parsed.Model, "reason", err.Error())
				writeError(w, http.StatusUnauthorized, "invalid, expired, replayed, or mismatched confidential entitlement")
				return
			}
			used, err := g.Replay.Consume(claims)
			if err != nil {
				g.Logger.Error("confidential replay store failed", "error", err.Error())
				writeError(w, http.StatusServiceUnavailable, "confidential authorization store unavailable")
				return
			}
			if !used {
				writeError(w, http.StatusUnauthorized, "confidential entitlement was already used")
				return
			}
			info.ReservationID = claims.ID
			info.KeyPrefix = "" // an entitlement is not a platform API key
			if status, msg := g.registerDispatch(r.Context(), info); status != 0 {
				writeError(w, status, msg)
				return
			}
			// From here on the reservation owes settlement on every terminal
			// path; the handle travels with the request context.
			settle := meter.NewTerminalSettlement(g.Meter.Signer, g.Meter.Issuer, g.Meter.Audience,
				g.Meter.Outbox, claims.ID, info.RequestID, info.Model, g.Logger)
			r = r.WithContext(meter.WithSettlement(r.Context(), settle))
			next.ServeHTTP(w, r)
			return
		}

		if !g.Enforce {
			next.ServeHTTP(w, r)
			return
		}

		verdict, err := g.check(r.Context(), key, parsed.Model)
		if err != nil {
			// Fail closed: billing unreachable or non-200 → no inference.
			g.Logger.Warn("billing auth check failed", "error", err.Error())
			writeError(w, http.StatusServiceUnavailable, "authentication service unavailable")
			return
		}
		if !verdict.Authenticated {
			g.Logger.Info("auth denied",
				"key_prefix", info.KeyPrefix, "model", info.Model, "reason", orDefault(verdict.Reason, "unauthenticated"))
			writeError(w, http.StatusUnauthorized, orDefault(verdict.Message, orDefault(verdict.Reason, "invalid api key")))
			return
		}
		if !verdict.Allowed {
			g.Logger.Info("auth denied",
				"key_prefix", info.KeyPrefix, "model", info.Model, "reason", orDefault(verdict.Reason, "not allowed"))
			writeError(w, http.StatusForbidden, orDefault(verdict.Message, orDefault(verdict.Reason, "model not allowed for this key")))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// registerDispatch implements the fail-closed dispatch precondition: billing
// must durably record that this reservation's inference is starting before
// any upstream work runs. The start POST is synchronous and deliberately not
// routed through the durable outbox — when start cannot reach billing the
// request is simply never dispatched, so no settlement is ever owed. It
// returns (0, "") to proceed, or the HTTP status and client message to
// refuse with.
func (g *Gate) registerDispatch(ctx context.Context, info *RequestInfo) (int, string) {
	token, _, err := meter.BuildStart(g.Meter.Signer, info.ReservationID, info.RequestID,
		info.Model, g.Meter.Issuer, g.Meter.Audience, time.Now().UTC())
	if err != nil {
		g.Logger.Error("confidential start signing failed", "request_id", info.RequestID, "error", err.Error())
		return http.StatusServiceUnavailable, "confidential dispatch registration unavailable"
	}
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := g.Billing.PostStart(callCtx, token)
	if err != nil {
		// Fail closed: network error, timeout, or any non-2xx → no inference.
		g.Logger.Warn("confidential start registration failed", "request_id", info.RequestID, "error", err.Error())
		return http.StatusServiceUnavailable, "confidential dispatch registration unavailable"
	}
	if !res.Stored {
		// Billing released or expired the reservation after minting the
		// entitlement; dispatching now would run unbillable inference.
		g.Logger.Info("confidential reservation no longer held by billing",
			"request_id", info.RequestID, "reason", orDefault(res.Ignored, "not stored"))
		return http.StatusUnauthorized, "confidential reservation was released or expired"
	}
	if res.Started {
		// This reservation already dispatched once; never dispatch twice.
		g.Logger.Info("confidential reservation already dispatched", "request_id", info.RequestID)
		return http.StatusConflict, "confidential reservation was already dispatched"
	}
	return 0, ""
}

// check returns a cached verdict when fresh, otherwise calls billing. Billing
// errors are never cached.
func (g *Gate) check(ctx context.Context, key, model string) (billing.Verdict, error) {
	ttl := g.TTL
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	// Cache keys are hashed so the map never holds raw client keys.
	sum := sha256.Sum256([]byte(key + "\x00" + model))
	ck := hex.EncodeToString(sum[:])

	g.mu.Lock()
	if e, ok := g.cache[ck]; ok && time.Now().Before(e.expires) {
		g.mu.Unlock()
		return e.verdict, nil
	}
	g.mu.Unlock()

	callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	v, err := g.Billing.CheckAuth(callCtx, key, model)
	if err != nil {
		return billing.Verdict{}, err
	}

	g.mu.Lock()
	if g.cache == nil {
		g.cache = map[string]cacheEntry{}
	}
	if len(g.cache) > 10000 { // lazy sweep of expired entries
		now := time.Now()
		for k, e := range g.cache {
			if now.After(e.expires) {
				delete(g.cache, k)
			}
		}
	}
	g.cache[ck] = cacheEntry{verdict: v, expires: time.Now().Add(ttl)}
	g.mu.Unlock()
	return v, nil
}

// bearerKey extracts the Bearer token from the Authorization header.
func bearerKey(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return "", false
	}
	key := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	return key, key != ""
}

// keyPrefix returns the first 8 characters of key (fewer if shorter) — the
// only form in which the client key may leave the request path.
func keyPrefix(key string) string {
	if len(key) > 8 {
		return key[:8]
	}
	return key
}

// newUUID returns a random RFC 4122 v4 UUID.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// newNonce returns a fresh 32-byte base64url request nonce.
func newNonce() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// readBody reads up to maxModelParseBody bytes. When the body is larger,
// over=true and restore reassembles the full stream for the upstream.
func readBody(rc io.ReadCloser) (body []byte, restore func() io.ReadCloser, over bool, err error) {
	buf := make([]byte, 0, 64<<10)
	tmp := make([]byte, 32<<10)
	for {
		n, rerr := rc.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if len(buf) > maxModelParseBody {
			return buf, func() io.ReadCloser {
				return struct {
					io.Reader
					io.Closer
				}{io.MultiReader(bytes.NewReader(buf), rc), rc}
			}, true, nil
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			rc.Close()
			return nil, nil, false, rerr
		}
	}
	_ = rc.Close()
	snapshot := buf
	return buf, func() io.ReadCloser { return io.NopCloser(bytes.NewReader(snapshot)) }, false, nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}
