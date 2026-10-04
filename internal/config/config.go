// Package config loads attest-proxy configuration from environment variables.
package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// canonicalModelID intentionally accepts only publisher/model identifiers.
// Receipts, metering, and public discovery must not emit short aliases such
// as "cyberglm": aliases belong, if needed, at an external compatibility
// gateway before a request reaches the attested boundary.
var canonicalModelID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}/[a-z0-9][a-z0-9._-]{0,127}$`)

// Config is the runtime configuration of the proxy.
type Config struct {
	ListenAddr    string // LISTEN_ADDR, default :8443
	Upstream      string // UPSTREAM, default http://127.0.0.1:30000
	ModelID       string // MODEL_ID, default lordx64/cyberglm
	PolicyID      string // POLICY_ID
	Endpoint      string // ENDPOINT — public base URL, echoed into receipt claims
	ComposeDigest string // COMPOSE_DIGEST — sha256 of the dstack compose file
	ModelDigest   string // MODEL_DIGEST — sha256 of the model artifact
	RuntimeDigest string // RUNTIME_DIGEST — expected runtime measurement digest

	ReceiptIssuer   string // RECEIPT_ISSUER   → receipt claim iss
	ReceiptAudience string // RECEIPT_AUDIENCE → receipt claim aud

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
		ListenAddr:      orDefault(getenv("LISTEN_ADDR"), ":8443"),
		Upstream:        orDefault(getenv("UPSTREAM"), "http://127.0.0.1:30000"),
		ModelID:         orDefault(getenv("MODEL_ID"), "lordx64/cyberglm"),
		PolicyID:        orDefault(getenv("POLICY_ID"), "adverserial-policy/dev"),
		Endpoint:        orDefault(getenv("ENDPOINT"), "https://api.adverserial.ai"),
		ComposeDigest:   getenv("COMPOSE_DIGEST"),
		ModelDigest:     getenv("MODEL_DIGEST"),
		RuntimeDigest:   getenv("RUNTIME_DIGEST"),
		ReceiptIssuer:   orDefault(getenv("RECEIPT_ISSUER"), "https://verify.adverserial.ai"),
		ReceiptAudience: orDefault(getenv("RECEIPT_AUDIENCE"), "cc-chat.adverserial.ai"),
		DstackSocket:    orDefault(getenv("DSTACK_SOCKET"), "/var/run/dstack.sock"),
		CORSAllowOrigin: getenv("CORS_ALLOW_ORIGIN"),
		PublicBaseURL:   orDefault(getenv("PUBLIC_BASE_URL"), orDefault(getenv("ENDPOINT"), "https://api.adverserial.ai")),
		VerificationURL: orDefault(getenv("VERIFICATION_URL"), "https://verify.adverserial.ai"),
		AttestedModels:  splitCSV(getenv("ATTESTED_MODELS")),
		ACMEDomains:     splitCSV(getenv("ACME_DOMAINS")),
		ACMEEmail:       getenv("ACME_EMAIL"),
		ACMEDirectoryURL: orDefault(getenv("ACME_DIRECTORY_URL"),
			"https://acme-v02.api.letsencrypt.org/directory"),
		GandiPAT:  getenv("GANDI_PAT"),
		GandiZone: getenv("GANDI_ZONE"),
		CertDir:   getenv("CERT_DIR"),

		BillingURL:          getenv("BILLING_URL"),
		BillingWriterSecret: getenv("BILLING_WRITER_SECRET"),
		ChatHost:            strings.ToLower(getenv("CHAT_HOST")),
		ChatDocroot:         getenv("CHAT_DOCROOT"),
		GPUEvidenceFile:     orDefault(getenv("GPU_EVIDENCE_FILE"), "/data/gpu-evidence.json"),
	}

	authRequired, err := parseBoolDefault(getenv("AUTH_REQUIRED"), true)
	if err != nil {
		return Config{}, fmt.Errorf("AUTH_REQUIRED: %w", err)
	}
	cfg.AuthRequired = authRequired
	if cfg.AuthRequired && (cfg.BillingURL == "" || cfg.BillingWriterSecret == "") {
		return Config{}, fmt.Errorf("BILLING_URL and BILLING_WRITER_SECRET are required when AUTH_REQUIRED is on (set AUTH_REQUIRED=0 to disable)")
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
