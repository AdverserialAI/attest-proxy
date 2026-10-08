// Package server wires the attestation endpoint, health check, and reverse
// proxy into a single TLS-terminating HTTP server.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/adverserial/attest-proxy/internal/attestation"
	"github.com/adverserial/attest-proxy/internal/billing"
	"github.com/adverserial/attest-proxy/internal/buildinfo"
	"github.com/adverserial/attest-proxy/internal/canonjson"
	"github.com/adverserial/attest-proxy/internal/config"
	"github.com/adverserial/attest-proxy/internal/entitlement"
	"github.com/adverserial/attest-proxy/internal/gate"
	"github.com/adverserial/attest-proxy/internal/meter"
	"github.com/adverserial/attest-proxy/internal/proxy"
	"github.com/adverserial/attest-proxy/internal/receipt"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	ehbpprotocol "github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

// receiptTTL is the validity window of verification receipts (WP-3 freshness).
const receiptTTL = 5 * time.Minute

// Server holds the runtime state of attest-proxy.
type Server struct {
	cfg    config.Config
	logger *slog.Logger
	quotes attestation.QuoteSource
	signer *receipt.Signer
	holder *CertHolder // active serving cert (self-signed or ACME, hot-swappable)
	gpu    *attestation.GPUBundleCache
	ehbp   *ehbpidentity.Identity

	// now is a test hook; production uses time.Now.
	now         func() time.Time
	meterOutbox *meter.Outbox
	meterOnce   sync.Once
}

// New assembles the server. holder supplies the active serving certificate;
// its leaf SPKI is published and quote-bound on every attestation response.
func New(
	cfg config.Config,
	logger *slog.Logger,
	quotes attestation.QuoteSource,
	signer *receipt.Signer,
	holder *CertHolder,
	ehbpIdentity ...*ehbpidentity.Identity,
) *Server {
	var gpu *attestation.GPUBundleCache
	if cfg.GPUEvidenceFile != "" {
		gpu = &attestation.GPUBundleCache{Path: cfg.GPUEvidenceFile}
	}
	var receiver *ehbpidentity.Identity
	if len(ehbpIdentity) > 0 {
		receiver = ehbpIdentity[0]
	}
	return &Server{
		cfg:    cfg,
		logger: logger,
		quotes: quotes,
		signer: signer,
		holder: holder,
		gpu:    gpu,
		ehbp:   receiver,
		now:    time.Now,
	}
}

// TLSConfig returns the TLS configuration serving the holder's active
// certificate (supports in-place renewal).
func TLSConfig(holder *CertHolder) *tls.Config {
	return &tls.Config{
		GetCertificate: holder.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}

// Handler returns the root handler: attestation routes, health check, CORS,
// content-free access logging, the chat static vhost, the /v1/ auth gate, and
// the reverse proxy catch-all.
func (s *Server) Handler() http.Handler {
	upstream, err := url.Parse(s.cfg.Upstream)
	if err != nil {
		// Config validation already rejects this; belt and braces.
		panic(err)
	}

	var billingClient *billing.Client
	if s.cfg.BillingURL != "" {
		billingClient = &billing.Client{BaseURL: s.cfg.BillingURL, WriterSecret: s.cfg.BillingWriterSecret}
	}
	if s.cfg.ConfidentialMode {
		// The prompt path never calls billing. Only signed count-only meter
		// records leave this workload, via either a separate mTLS ingress or the
		// explicitly-labelled direct-signed fallback.
		if s.cfg.MeterDeliveryMode == "direct-signed" {
			billingClient = &billing.Client{MeterURL: s.cfg.MeterURL, MeterIngressSecret: s.cfg.MeterIngressSecret, HTTP: billing.NewTLS13HTTPClient()}
		} else {
			mtlsClient, err := billing.NewMutualTLSHTTPClient(s.cfg.MeterClientCertFile, s.cfg.MeterClientKeyFile, s.cfg.MeterServerCAFile)
			if err != nil {
				panic("invalid confidential meter mTLS configuration: " + err.Error())
			}
			billingClient = &billing.Client{MeterURL: s.cfg.MeterURL, HTTP: mtlsClient}
		}
	}
	g := &gate.Gate{
		Billing:            billingClient,
		Logger:             s.logger,
		Enforce:            s.cfg.AuthRequired,
		ConfidentialActive: s.cfg.ConfidentialActivation == "active",
	}
	tap := &proxy.UsageTap{
		Logger: s.logger,
		Receipts: &proxy.ReceiptConfig{
			Signer:      s.signer,
			Issuer:      s.cfg.ReceiptIssuer,
			Audience:    s.cfg.ReceiptAudience,
			PolicyID:    s.cfg.PolicyID,
			StateDigest: s.attestationStateDigest,
		},
	}
	if billingClient != nil {
		tap.Sink = billingClient // interface must stay nil when billing is off
	}
	if s.cfg.ConfidentialMode {
		keys, err := entitlement.ParseJWKS(s.cfg.EntitlementJWKS)
		if err != nil {
			panic("invalid confidential entitlement JWKS: " + err.Error())
		}
		meterSigner, err := meter.NewSigner(s.cfg.MeterSigningSeed)
		if err != nil {
			panic("invalid confidential meter signer: " + err.Error())
		}
		replay := &entitlement.UsedStore{Dir: s.cfg.EntitlementReplayDir}
		g.Confidential = true
		g.Entitlements = &entitlement.Validator{Keys: keys, Issuer: s.cfg.EntitlementIssuer, Audience: s.cfg.EntitlementAudience}
		g.Replay = replay
		g.ActiveSPKI = func() string { return attestation.SPKIHash(s.holder.Leaf()) }
		outbox := meter.Outbox{Dir: s.cfg.MeterOutboxDir, Poster: billingClient}
		s.meterOutbox = &outbox
		tap.Sink = nil // confidential mode never sends the legacy usage schema
		tap.Meter = &proxy.ConfidentialMeterConfig{Signer: meterSigner, Issuer: s.cfg.MeterIssuer, Audience: s.cfg.MeterAudience, Outbox: outbox}
		s.startMeterRetry()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/attestation", s.handleAttestation)
	mux.HandleFunc("/.well-known/adverserial-attestation", s.handleAttestation)
	mux.HandleFunc("/healthz", s.handleHealthz)
	api := g.Middleware(proxy.New(upstream, s.logger, s.modelsAugmenter(), tap, s.cfg.UpstreamBearer))
	if s.cfg.EHBPRequired {
		if s.ehbp == nil {
			panic("EHBP_REQUIRED without receiver key")
		}
		api = s.requireEHBP(s.ehbp.Middleware()(api))
		mux.HandleFunc(ehbpprotocol.KeysPath, s.ehbp.ConfigHandler)
	}
	// Fence the model API surface: only /v1/ reaches the upstream. SGLang's
	// native /generate, /vertex_generate, /invocations, memory-management, and
	// config endpoints must never be reachable through the public edge.
	mux.Handle("/", fencedAPI(api))

	return proxy.Logging(s.logger, s.cors(s.hostRouter(mux)))
}

// fencedAPI forwards only the /v1/ model API to the upstream and refuses
// every other path, so an upstream feature endpoint fails closed by default.
func fencedAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/") {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// startMeterRetry drains durable count-only records after boot and every 30
// seconds. It is intentionally independent of request handling; a billing
// outage leaves the file in place for retry rather than dropping usage.
func (s *Server) startMeterRetry() {
	if s.meterOutbox == nil {
		return
	}
	s.meterOnce.Do(func() {
		outbox := *s.meterOutbox
		go func() {
			for {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				err := outbox.Flush(ctx)
				cancel()
				if err != nil && s.logger != nil {
					s.logger.Warn("confidential meter retry deferred", "error", err.Error())
				}
				time.Sleep(30 * time.Second)
			}
		}()
	})
}

// modelsAugmenter builds the /v1/models injector from config plus the current
// receipt key. It returns nil when no public base URL is configured.
func (s *Server) modelsAugmenter() *proxy.ModelsAugmenter {
	if s.cfg.PublicBaseURL == "" {
		return nil
	}
	kid := s.signer.KeyID()
	aug := &proxy.ModelsAugmenter{
		AttestationURL:  strings.TrimSuffix(s.cfg.PublicBaseURL, "/") + "/attestation",
		VerificationURL: s.cfg.VerificationURL,
		ReceiptIssuer:   s.cfg.ReceiptIssuer,
		ReceiptAudience: s.cfg.ReceiptAudience,
		TrustedKeys:     map[string]any{kid: s.signer.PublicJWK()},
		Endpoint:        s.cfg.PublicBaseURL,
		ModelDigest:     s.cfg.ModelDigest,
		RuntimeDigest:   s.cfg.RuntimeDigest,
	}
	if len(s.cfg.AttestedModels) > 0 {
		aug.Allowed = make(map[string]bool, len(s.cfg.AttestedModels))
		for _, id := range s.cfg.AttestedModels {
			aug.Allowed[id] = true
		}
	}
	return aug
}

// cors emits CORS headers for the browser client. The attestation endpoints
// serve public, unauthenticated evidence and always allow any origin; API
// routes only get CORS headers when CORS_ALLOW_ORIGIN is configured.
func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isAttestationPath(r.URL.Path) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET")
				w.Header().Set("Access-Control-Max-Age", "300")
				w.WriteHeader(http.StatusNoContent)
				return
			}
		} else if s.cfg.CORSAllowOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", s.cfg.CORSAllowOrigin)
			// Browser EHBP clients must be able to send the encapsulated request
			// key and read the derived response nonce; otherwise cross-origin
			// confidential streaming silently fails at the CORS boundary.
			w.Header().Set("Access-Control-Expose-Headers", "x-adverserial-receipt, ehbp-response-nonce")
			w.Header().Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "authorization, content-type, x-adverserial-nonce, ehbp-encapsulated-key")
				w.Header().Set("Access-Control-Expose-Headers", "x-adverserial-receipt, ehbp-response-nonce")
				w.Header().Set("Access-Control-Max-Age", "300")
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isAttestationPath(p string) bool {
	return p == "/attestation" || p == "/.well-known/adverserial-attestation"
}

// gpuSnapshot returns the current GPU evidence bundle state (zero value when
// the collector file is absent or unreadable).
func (s *Server) gpuSnapshot() attestation.GPUEvidence {
	if s.gpu == nil {
		return attestation.GPUEvidence{}
	}
	return s.gpu.Snapshot()
}

// attestationStateDigest returns the (tls_spki_sha256, state digest) pair
// cited in WP-7 receipts' attestation_binding. The digest tracks the active
// certificate, receipt key, workload digests, and GPU evidence freshness.
func (s *Server) attestationStateDigest() (string, string) {
	spki := attestation.SPKIHash(s.holder.Leaf())
	digest, err := attestation.AttestationStateDigest(
		attestation.Workload{
			PolicyID:      s.cfg.PolicyID,
			ModelID:       s.cfg.ModelID,
			ProxyVersion:  buildinfo.Version,
			ComposeDigest: s.cfg.ComposeDigest,
			ModelDigest:   s.cfg.ModelDigest,
		},
		s.cfg.RuntimeDigest,
		spki,
		s.signer.KeyID(),
		s.ehbpPublicKeySHA256(),
		s.gpuSnapshot(),
	)
	if err != nil {
		return spki, ""
	}
	return spki, digest
}

func (s *Server) ehbpPublicKeySHA256() string {
	if s.ehbp == nil {
		return ""
	}
	sum := sha256.Sum256(s.ehbp.MarshalPublicKey())
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// handleAttestation implements WP-3: validate the client nonce, fetch a fresh
// TDX quote bound to nonce + TLS SPKI + receipt pubkey, build the evidence,
// and mint the ES256 verification receipt (WP-4 channel binding).
func (s *Server) handleAttestation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	nonceRaw, nonceParam, err := decodeNonce(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Fresh quote on every request — replaying quotes is the whole point of
	// the nonce binding, so there is no quote cache by design. The SPKI of
	// the *active* serving certificate (self-signed or ACME) is bound in.
	leaf := s.holder.Leaf()
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	var ehbpPublicKey []byte
	var ehbpMetadata map[string]any
	if s.ehbp != nil {
		config, err := s.ehbp.MarshalConfig()
		if err != nil {
			s.logger.Error("EHBP configuration encoding failed", "error", err.Error())
			writeError(w, http.StatusInternalServerError, "attestation state unavailable")
			return
		}
		ehbpPublicKey = s.ehbp.MarshalPublicKey()
		ehbpMetadata = map[string]any{
			"protocol":          "ehbp-rfc9180-v1",
			"key_config":        base64.RawURLEncoding.EncodeToString(config),
			"public_key":        base64.RawURLEncoding.EncodeToString(ehbpPublicKey),
			"public_key_sha256": s.ehbpPublicKeySHA256(),
		}
	}
	reportData := attestation.ReportData(nonceRaw, leaf.RawSubjectPublicKeyInfo, s.signer.PublicKeyDER(), ehbpPublicKey)
	quote, err := s.quotes.Quote(ctx, reportData)
	if err != nil {
		s.logger.Error("quote failed", "error", err.Error())
		writeError(w, http.StatusBadGateway, "attestation quote unavailable")
		return
	}

	now := s.now().UTC().Truncate(time.Second)
	expires := now.Add(receiptTTL)
	workload := attestation.Workload{
		PolicyID:      s.cfg.PolicyID,
		ModelID:       s.cfg.ModelID,
		ProxyVersion:  buildinfo.Version,
		ComposeDigest: s.cfg.ComposeDigest,
		ModelDigest:   s.cfg.ModelDigest,
	}
	gpu := s.gpuSnapshot()
	tlsSPKI := attestation.SPKIHash(leaf)
	stateDigest, err := attestation.AttestationStateDigest(workload, s.cfg.RuntimeDigest, tlsSPKI, s.signer.KeyID(), s.ehbpPublicKeySHA256(), gpu)
	if err != nil {
		s.logger.Error("attestation state digest failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "attestation state unavailable")
		return
	}

	evidence := attestation.BuildEvidence(attestation.EvidenceInput{
		Nonce:                  nonceParam,
		IssuedAt:               now,
		ExpiresAt:              expires,
		QuoteHex:               quote.QuoteHex,
		EventLog:               quote.EventLog,
		TLSSPKISHA256:          tlsSPKI,
		TLSSPKIDER:             leaf.RawSubjectPublicKeyInfo,
		EHBP:                   ehbpMetadata,
		ReceiptJWK:             s.signer.PublicJWK(),
		AttestationStateDigest: stateDigest,
		Workload:               workload,
		GPU:                    gpu,
		Dev:                    s.cfg.DevMode,
	})

	digest, err := canonjson.Digest(evidence)
	if err != nil {
		s.logger.Error("evidence canonicalization failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "evidence encoding failed")
		return
	}

	claims := map[string]any{
		"iss":             s.cfg.ReceiptIssuer,
		"aud":             s.cfg.ReceiptAudience,
		"nonce":           nonceParam,
		"verdict":         "verified",
		"iat":             now.Unix(),
		"exp":             expires.Unix(),
		"evidence_sha256": digest,
		"model_id":        s.cfg.ModelID,
		"endpoint":        s.cfg.Endpoint,
	}
	// Empty digests are omitted rather than sent as "" so a client pinning a
	// digest fails closed against an unconfigured proxy.
	if s.cfg.ModelDigest != "" {
		claims["model_digest"] = s.cfg.ModelDigest
	}
	if s.cfg.RuntimeDigest != "" {
		claims["runtime_digest"] = s.cfg.RuntimeDigest
	}

	jws, err := s.signer.Mint(claims)
	if err != nil {
		s.logger.Error("receipt signing failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "receipt signing failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"evidence":             evidence,
		"verification_receipt": jws,
	})
}

// decodeNonce extracts and validates the nonce query parameter. The nonce
// must be base64url (padding optional) decoding to 16–64 bytes; missing,
// malformed, duplicated, or oversized values are rejected.
func decodeNonce(q url.Values) ([]byte, string, error) {
	params, ok := q["nonce"]
	if !ok || len(params) == 0 {
		return nil, "", errString("missing nonce parameter")
	}
	if len(params) != 1 {
		return nil, "", errString("duplicate nonce parameter")
	}
	s := params[0]
	raw, err := attestation.ValidateNonce(s)
	if err != nil {
		return nil, "", err
	}
	return raw, s, nil
}

type errString string

func (e errString) Error() string { return string(e) }

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}
