// Package proxy implements the reverse proxy to the loopback inference
// server and the request-logging middleware.
//
// Content policy (WP-2 hard requirement): this proxy NEVER logs request or
// response bodies, headers, cookies, query strings, or any data derived from
// them. Logs carry method, path class, status, byte count, and duration only.
// There is deliberately no debug/content log level and no LOG_CONTENT-style
// escape hatch.
package proxy

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// New builds a streaming-safe reverse proxy to the upstream inference server.
// aug and tap may be nil; aug injects confidential_verification metadata into
// GET /v1/models, tap extracts usage counts from completion responses.
func New(upstream *url.URL, logger *slog.Logger, aug *ModelsAugmenter, tap *UsageTap, upstreamBearer ...string) *httputil.ReverseProxy {
	rp := httputil.NewSingleHostReverseProxy(upstream)
	if len(upstreamBearer) > 0 && upstreamBearer[0] != "" {
		base := rp.Director
		secret := upstreamBearer[0]
		rp.Director = func(req *http.Request) {
			base(req)
			// A client entitlement is valid only at attest-proxy. SGLang sees
			// a separate sealed loopback credential, never a customer key or
			// billing token.
			req.Header.Set("Authorization", "Bearer "+secret)
		}
	}
	if aug != nil {
		rp.Director = DirectorWrap(rp.Director)
	}
	if aug != nil || tap != nil {
		rp.ModifyResponse = func(resp *http.Response) error {
			if tap != nil {
				if err := tap.ModifyResponse(resp); err != nil {
					return err
				}
			}
			if aug != nil {
				return aug.ModifyResponse(resp)
			}
			return nil
		}
	}

	// 100ms flush keeps SSE-style streaming responsive even when the upstream
	// does not flush explicitly; event-stream responses flush immediately.
	rp.FlushInterval = 100 * time.Millisecond

	rp.Transport = &http.Transport{
		// Direct connection only: ignore any HTTP(S)_PROXY environment.
		Proxy: nil,
		// Never inject or transparently decode gzip: client encodings pass
		// through end-to-end, and /v1/models (whose Accept-Encoding is
		// stripped by DirectorWrap) always arrives as identity JSON.
		DisableCompression: true,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 5 * time.Second,
		// Time to first byte from the model server; LLM prefill on large
		// prompts can legitimately take minutes. There is intentionally no
		// overall timeout: streams may stay open for a long time.
		ResponseHeaderTimeout: 5 * time.Minute,
	}

	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Warn("upstream error",
			"method", r.Method,
			"path", PathClass(r.URL.Path),
			"error", err.Error(),
		)
		http.Error(w, `{"error":"upstream unavailable"}`, http.StatusBadGateway)
	}

	return rp
}

// Logging returns middleware that logs one line per request: method, path
// class, status, response byte count, and duration. It never touches request
// or response bodies, headers, or query strings. Token counts are not logged:
// they live inside response bodies (final SSE usage chunk), which this proxy
// does not inspect.
func Logging(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		logger.Info("request",
			"method", r.Method,
			"path", PathClass(r.URL.Path),
			"status", rec.status,
			"bytes", rec.bytes,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// recorder counts status and bytes while preserving the streaming-related
// interfaces of the underlying ResponseWriter (Flush for SSE, Hijack for
// upgrades, Unwrap for http.ResponseController).
type recorder struct {
	http.ResponseWriter
	status int
	bytes  int64
	wrote  bool
}

func (r *recorder) WriteHeader(code int) {
	if !r.wrote {
		r.status = code
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(p []byte) (int, error) {
	if !r.wrote {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(p)
	r.bytes += int64(n)
	return n, err
}

func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("hijacking not supported")
}

func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// PathClass reduces a URL path to a low-cardinality class safe for logging:
// API shape segments (letters, plus version tokens like "v1") survive
// unchanged — e.g. /v1/chat/completions — while resource IDs and anything
// else that could carry caller-supplied data become ":id".
func PathClass(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if s == "" {
			continue
		}
		if !isClassSegment(s) {
			segs[i] = ":id"
		}
	}
	return strings.Join(segs, "/")
}

func isClassSegment(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	if isVersionToken(s) {
		return true
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

// isVersionToken matches API version segments: v1, v2, v10beta, ...
func isVersionToken(s string) bool {
	if len(s) < 2 || (s[0] != 'v' && s[0] != 'V') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') {
			continue
		}
		return false
	}
	return true
}
