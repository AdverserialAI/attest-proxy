// Package config loads attest-proxy configuration from environment variables.
package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// canonicalModelID intentionally accepts only publisher/model identifiers.
// Receipts, metering, and public discovery must not emit short aliases such
// as "cyberglm": aliases belong, if needed, at an external compatibility
// gateway before a request reaches the attested boundary.
var canonicalModelID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}/[a-z0-9][a-z0-9._-]{0,127}$`)
var sha256Digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Config is the runtime configuration of the proxy.
type Config struct {
	ListenAddr     string // LISTEN_ADDR, default :8443
	Upstream       string // UPSTREAM, default http://127.0.0.1:30000
	UpstreamBearer string // UPSTREAM_BEARER_TOKEN — loopback inference credential
	ModelID        string // MODEL_ID, default lordx64/cyberglm
	PolicyID       string // POLICY_ID
	Endpoint       string // ENDPOINT — public base URL, echoed into receipt claims
	ComposeDigest  string // COMPOSE_DIGEST — sha256 of the dstack compose file
	ModelDigest    string // MODEL_DIGEST — sha256 of the model artifact
	// ModelManifestFile is written by the isolated read-only model measurer.
	// When set, its validated digest becomes ModelDigest before the proxy starts.
	ModelManifestFile string // MODEL_MANIFEST_FILE
	RuntimeDigest     string // RUNTIME_DIGEST — immutable runtime image digest; TDX event log binds the complete compose

	ReceiptIssuer   string // RECEIPT_ISSUER   → receipt claim iss
	ReceiptAudience string // RECEIPT_AUDIENCE → receipt claim aud
	// ReceiptSigningSeed is a sealed 32-byte base64url seed for the stable
	// P-256 receipt key. Its public JWK is pinned in the public policy.
	ReceiptSigningSeed string // RECEIPT_SIGNING_SEED

	DstackSocket string // DSTACK_SOCKET, default /var/run/dstack.sock
	DevMode      bool   // DEV_MODE — synthetic evidence, no dstack quote

	// CORSAllowOrigin, when set, is emitted as Access-Control-Allow-Origin on
	// proxied API routes (the browser client calls the API cross-origin).
	// The attestation endpoints are public evidence and always allow *.
	CORSAllowOrigin string // CORS_ALLOW_ORIGIN, default "" (disabled)

	// TLSHostnames are the SANs of the in-process self-signed certificate.
	TLSHostnames []string // TLS_HOSTNAMES, comma-separated

	// PublicBaseURL is the externally reachable base URL of this proxy; it is
	// used to build the attestation_url and expected.endpoint values injected
	// into GET /v1/models for the browser verifier. Defaults to ENDPOINT.
	PublicBaseURL string // PUBLIC_BASE_URL

	// VerificationURL is the public verification site advertised in the
	// injected confidential_verification block.
	VerificationURL string // VERIFICATION_URL, default https://verify.adverserial.ai

	// AttestedModels filters which /v1/models entries gain the
	// confidential_verification block. Empty means every listed model.
	AttestedModels []string // ATTESTED_MODELS, comma-separated

	// ACMEDomains enables ACME DNS-01 certificate issuance when non-empty.
	// When empty, the proxy keeps its in-process self-signed certificate.
	ACMEDomains []string // ACME_DOMAINS, comma-separated
	ACMEEmail   string   // ACME_EMAIL — account contact
	// ACMEDirectoryURL defaults to the Let's Encrypt production directory;
	// point it at https://acme-staging-v02.api.letsencrypt.org/directory while
	// testing issuance to avoid rate limits.
	ACMEDirectoryURL string // ACME_DIRECTORY_URL
	GandiPAT         string // GANDI_PAT — Gandi LiveDNS personal access token
	GandiZone        string // GANDI_ZONE — e.g. adverserial.ai
	// CertDir persists the ACME account key and issued certificates (mount the
	// dstack volume here). Required when ACME_DOMAINS is set.
	CertDir string // CERT_DIR

	// Billing / auth gate (WP-9 boundary: billing sees api_key_prefix + token
	// counts + model + request_id, never content).
	BillingURL          string // BILLING_URL — billing service base URL
	BillingWriterSecret string // BILLING_WRITER_SECRET — bearer for billing writes
	// AuthRequired (default on) gates POST /v1/* behind billing /auth/check.
	// Required envs when on: BILLING_URL, BILLING_WRITER_SECRET.
	AuthRequired bool // AUTH_REQUIRED

	// ConfidentialMode replaces the legacy raw-API-key /auth/check gate with
	// local verification of a billing-signed, one-use entitlement. It must be
	// enabled only after the CVM compose has the corresponding sealed secrets
	// and persistent volumes. It never forwards a customer API key to SGLang.
	ConfidentialMode bool // CONFIDENTIAL_MODE
	// ConfidentialActivation keeps a newly provisioned CVM evidence-only until
	// an independently verified, signed policy has been published. Allowed
	// values are "pre-activation" and "active".
	ConfidentialActivation string // CONFIDENTIAL_ACTIVATION
	EntitlementJWKS        string // ENTITLEMENT_JWKS_JSON — billing public keys
	EntitlementIssuer      string // ENTITLEMENT_ISSUER
	EntitlementAudience    string // ENTITLEMENT_AUDIENCE
	EntitlementReplayDir   string // ENTITLEMENT_REPLAY_DIR — persistent volume
	MeterSigningSeed       string // METER_SIGNING_SEED — sealed Ed25519 seed
	MeterIssuer            string // METER_ISSUER
	MeterAudience          string // METER_AUDIENCE
	MeterOutboxDir         string // METER_OUTBOX_DIR — persistent volume
	// MeterURL is the externally deployed TLS-terminating meter ingress. In
	// confidential mode it is mandatory and must not be the Heroku billing app.
	MeterURL            string // METER_URL — e.g. https://meter-ingress.adverserial.ai
	MeterClientCertFile string // METER_CLIENT_CERT_FILE — materialized CVM client certificate PEM
	MeterClientKeyFile  string // METER_CLIENT_KEY_FILE — materialized CVM client private key PEM
	MeterServerCAFile   string // METER_SERVER_CA_FILE — materialized meter ingress CA PEM
	// MeterTLSBundleB64 is a sealed base64url JSON bundle. When supplied, the
	// proxy validates and materializes it under its private state volume before
	// creating the mTLS client. No shared Docker secret volume is required.
	MeterTLSBundleB64 string // METER_TLS_BUNDLE_B64

	// Chat vhost: when both are set, requests with Host == ChatHost get the
	// static SPA from ChatDocroot (API routes still reach the API handlers).
	ChatHost    string // CHAT_HOST, e.g. cc-chat.adverserial.ai
	ChatDocroot string // CHAT_DOCROOT, e.g. /data/chat-dist

	// GPUEvidenceFile is the cached NRAS EAT bundle written by the collector
	// sidecar; embedded in attestation evidence as gpu_evidence.
	GPUEvidenceFile string // GPU_EVIDENCE_FILE, default /data/gpu-evidence.json
}

// FromEnv reads configuration using getenv (pass os.Getenv in production).
func FromEnv(getenv func(string) string) (Config, error) {
	cfg := Config{
		ListenAddr:         orDefault(getenv("LISTEN_ADDR"), ":8443"),
		Upstream:           orDefault(getenv("UPSTREAM"), "http://127.0.0.1:30000"),
		UpstreamBearer:     getenv("UPSTREAM_BEARER_TOKEN"),
		ModelID:            orDefault(getenv("MODEL_ID"), "lordx64/cyberglm"),
		PolicyID:           orDefault(getenv("POLICY_ID"), "adverserial-policy/dev"),
		Endpoint:           orDefault(getenv("ENDPOINT"), "https://api.adverserial.ai"),
		ComposeDigest:      getenv("COMPOSE_DIGEST"),
		ModelDigest:        getenv("MODEL_DIGEST"),
		ModelManifestFile:  getenv("MODEL_MANIFEST_FILE"),
		RuntimeDigest:      getenv("RUNTIME_DIGEST"),
		ReceiptIssuer:      orDefault(getenv("RECEIPT_ISSUER"), "https://verify.adverserial.ai"),
		ReceiptAudience:    orDefault(getenv("RECEIPT_AUDIENCE"), "cc-chat.adverserial.ai"),
		ReceiptSigningSeed: getenv("RECEIPT_SIGNING_SEED"),
		DstackSocket:       orDefault(getenv("DSTACK_SOCKET"), "/var/run/dstack.sock"),
		CORSAllowOrigin:    getenv("CORS_ALLOW_ORIGIN"),
		PublicBaseURL:      orDefault(getenv("PUBLIC_BASE_URL"), orDefault(getenv("ENDPOINT"), "https://api.adverserial.ai")),
		VerificationURL:    orDefault(getenv("VERIFICATION_URL"), "https://verify.adverserial.ai"),
		AttestedModels:     splitCSV(getenv("ATTESTED_MODELS")),
		ACMEDomains:        splitCSV(getenv("ACME_DOMAINS")),
		ACMEEmail:          getenv("ACME_EMAIL"),
		ACMEDirectoryURL: orDefault(getenv("ACME_DIRECTORY_URL"),
			"https://acme-v02.api.letsencrypt.org/directory"),
		GandiPAT:  getenv("GANDI_PAT"),
		GandiZone: getenv("GANDI_ZONE"),
		CertDir:   getenv("CERT_DIR"),

		BillingURL:             getenv("BILLING_URL"),
		BillingWriterSecret:    getenv("BILLING_WRITER_SECRET"),
		EntitlementJWKS:        getenv("ENTITLEMENT_JWKS_JSON"),
		EntitlementIssuer:      orDefault(getenv("ENTITLEMENT_ISSUER"), "https://billing.adverserial.ai"),
		EntitlementAudience:    orDefault(getenv("ENTITLEMENT_AUDIENCE"), "https://cc-api.adverserial.ai"),
		EntitlementReplayDir:   getenv("ENTITLEMENT_REPLAY_DIR"),
		MeterSigningSeed:       getenv("METER_SIGNING_SEED"),
		MeterIssuer:            orDefault(getenv("METER_ISSUER"), "https://cc-api.adverserial.ai"),
		MeterAudience:          orDefault(getenv("METER_AUDIENCE"), "https://billing.adverserial.ai"),
		MeterOutboxDir:         getenv("METER_OUTBOX_DIR"),
		MeterURL:               getenv("METER_URL"),
		MeterClientCertFile:    getenv("METER_CLIENT_CERT_FILE"),
		MeterClientKeyFile:     getenv("METER_CLIENT_KEY_FILE"),
		MeterServerCAFile:      getenv("METER_SERVER_CA_FILE"),
		ConfidentialActivation: orDefault(getenv("CONFIDENTIAL_ACTIVATION"), "pre-activation"),
		ChatHost:               strings.ToLower(getenv("CHAT_HOST")),
		ChatDocroot:            getenv("CHAT_DOCROOT"),
		GPUEvidenceFile:        orDefault(getenv("GPU_EVIDENCE_FILE"), "/data/gpu-evidence.json"),
	}

	authRequired, err := parseBoolDefault(getenv("AUTH_REQUIRED"), true)
	if err != nil {
		return Config{}, fmt.Errorf("AUTH_REQUIRED: %w", err)
	}
	cfg.AuthRequired = authRequired
	confidentialMode, err := parseBoolDefault(getenv("CONFIDENTIAL_MODE"), false)
	if err != nil {
		return Config{}, fmt.Errorf("CONFIDENTIAL_MODE: %w", err)
	}
	cfg.ConfidentialMode = confidentialMode
	if cfg.AuthRequired && (cfg.BillingURL == "" || cfg.BillingWriterSecret == "") {
		return Config{}, fmt.Errorf("BILLING_URL and BILLING_WRITER_SECRET are required when AUTH_REQUIRED is on (set AUTH_REQUIRED=0 to disable)")
	}
	if cfg.ConfidentialMode {
		if cfg.AuthRequired {
			return Config{}, fmt.Errorf("AUTH_REQUIRED must be 0 when CONFIDENTIAL_MODE is enabled; raw API keys must not enter the CVM")
		}
		if cfg.ModelDigest == "" && cfg.ModelManifestFile == "" {
			return Config{}, fmt.Errorf("MODEL_DIGEST or MODEL_MANIFEST_FILE is required when CONFIDENTIAL_MODE is enabled")
		}
		for _, required := range []struct{ name, value string }{
			{"ENTITLEMENT_JWKS_JSON", cfg.EntitlementJWKS},
			{"ENTITLEMENT_REPLAY_DIR", cfg.EntitlementReplayDir},
			{"METER_SIGNING_SEED", cfg.MeterSigningSeed},
			{"METER_OUTBOX_DIR", cfg.MeterOutboxDir},
			{"METER_URL", cfg.MeterURL},
			{"UPSTREAM_BEARER_TOKEN", cfg.UpstreamBearer},
			{"RECEIPT_SIGNING_SEED", cfg.ReceiptSigningSeed},
		} {
			if required.value == "" {
				return Config{}, fmt.Errorf("%s is required when CONFIDENTIAL_MODE is enabled", required.name)
			}
		}
		paths := []struct{ name, value string }{
			{"METER_CLIENT_CERT_FILE", cfg.MeterClientCertFile},
			{"METER_CLIENT_KEY_FILE", cfg.MeterClientKeyFile},
			{"METER_SERVER_CA_FILE", cfg.MeterServerCAFile},
		}
		if cfg.MeterTLSBundleB64 != "" {
			for _, path := range paths {
				if path.value != "" {
					return Config{}, fmt.Errorf("%s cannot be combined with METER_TLS_BUNDLE_B64", path.name)
				}
			}
			cfg.MeterClientCertFile = "/state/meter-tls/client.crt"
			cfg.MeterClientKeyFile = "/state/meter-tls/client.key"
			cfg.MeterServerCAFile = "/state/meter-tls/ingress-ca.crt"
		} else {
			for _, path := range paths {
				if path.value == "" {
					return Config{}, fmt.Errorf("%s is required when CONFIDENTIAL_MODE is enabled", path.name)
				}
			}
		}
		meterURL, err := url.Parse(cfg.MeterURL)
		if err != nil || meterURL.Scheme != "https" || meterURL.Host == "" || meterURL.User != nil || meterURL.RawQuery != "" || meterURL.Fragment != "" || (meterURL.Path != "" && meterURL.Path != "/") {
			return Config{}, fmt.Errorf("METER_URL must be an exact https://host URL")
		}
		if cfg.ConfidentialActivation != "pre-activation" && cfg.ConfidentialActivation != "active" {
			return Config{}, fmt.Errorf("CONFIDENTIAL_ACTIVATION must be pre-activation or active")
		}
	}
	if (cfg.ChatHost == "") != (cfg.ChatDocroot == "") {
		return Config{}, fmt.Errorf("CHAT_HOST and CHAT_DOCROOT must be set together")
	}

	dev, err := parseBool(getenv("DEV_MODE"))
	if err != nil {
		return Config{}, fmt.Errorf("DEV_MODE: %w", err)
	}
	cfg.DevMode = dev
	if !canonicalModelID.MatchString(cfg.ModelID) {
		return Config{}, fmt.Errorf("MODEL_ID %q must use canonical publisher/model form", cfg.ModelID)
	}
	for _, id := range cfg.AttestedModels {
		if !canonicalModelID.MatchString(id) {
			return Config{}, fmt.Errorf("ATTESTED_MODELS entry %q must use canonical publisher/model form", id)
		}
	}

	u, err := url.Parse(cfg.Upstream)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return Config{}, fmt.Errorf("UPSTREAM %q must be an absolute http(s) URL", cfg.Upstream)
	}

	if hosts := getenv("TLS_HOSTNAMES"); hosts != "" {
		for _, h := range strings.Split(hosts, ",") {
			if h = strings.TrimSpace(h); h != "" {
				cfg.TLSHostnames = append(cfg.TLSHostnames, h)
			}
		}
	} else if eu, err := url.Parse(cfg.Endpoint); err == nil && eu.Hostname() != "" {
		cfg.TLSHostnames = []string{eu.Hostname(), "localhost"}
	} else {
		cfg.TLSHostnames = []string{"localhost"}
	}

	if len(cfg.ACMEDomains) > 0 {
		for _, required := range []struct{ name, value string }{
			{"ACME_EMAIL", cfg.ACMEEmail},
			{"GANDI_PAT", cfg.GandiPAT},
			{"GANDI_ZONE", cfg.GandiZone},
			{"CERT_DIR", cfg.CertDir},
		} {
			if required.value == "" {
				return Config{}, fmt.Errorf("%s is required when ACME_DOMAINS is set", required.name)
			}
		}
	}

	return cfg, nil
}

// ResolveModelManifest validates the one-time artifact measurement produced by
// the isolated model-measurer sidecar. The proxy never mounts model weights;
// it consumes only this JSON manifest from a separate read-only volume.
func ResolveModelManifest(cfg Config) (Config, error) {
	if cfg.ModelManifestFile == "" {
		return cfg, nil
	}
	raw, err := os.ReadFile(cfg.ModelManifestFile)
	if err != nil {
		return Config{}, fmt.Errorf("read MODEL_MANIFEST_FILE: %w", err)
	}
	var value struct {
		Version    int    `json:"version"`
		Algorithm  string `json:"algorithm"`
		ModelID    string `json:"model_id"`
		FileCount  int    `json:"file_count"`
		TotalBytes int64  `json:"total_bytes"`
		Digest     string `json:"digest"`
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return Config{}, fmt.Errorf("parse MODEL_MANIFEST_FILE: %w", err)
	}
	if value.Version != 1 || value.Algorithm != "sha256-tree-v1" || value.FileCount < 1 || value.TotalBytes < 1 {
		return Config{}, fmt.Errorf("MODEL_MANIFEST_FILE has an unsupported or empty artifact measurement")
	}
	if value.ModelID != cfg.ModelID || !canonicalModelID.MatchString(value.ModelID) {
		return Config{}, fmt.Errorf("MODEL_MANIFEST_FILE model ID does not match MODEL_ID")
	}
	if !sha256Digest.MatchString(value.Digest) {
		return Config{}, fmt.Errorf("MODEL_MANIFEST_FILE contains an invalid digest")
	}
	if cfg.ModelDigest != "" && cfg.ModelDigest != value.Digest {
		return Config{}, fmt.Errorf("MODEL_DIGEST does not match MODEL_MANIFEST_FILE")
	}
	cfg.ModelDigest = value.Digest
	return cfg, nil
}

func splitCSV(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func parseBool(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "false", "no", "off":
		return false, nil
	case "1", "true", "yes", "on":
		return true, nil
	default:
		return false, fmt.Errorf("invalid boolean value %q", v)
	}
}

// parseBoolDefault parses a boolean env value with an explicit default for
// the unset case.
func parseBoolDefault(v string, def bool) (bool, error) {
	if strings.TrimSpace(v) == "" {
		return def, nil
	}
	return parseBool(v)
}
