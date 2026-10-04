package config

import (
	"encoding/base64"
	"testing"
)

// noAuth disables the default-on auth gate for tests that predate it.
func noAuth(next func(string) string) func(string) string {
	return func(k string) string {
		if k == "AUTH_REQUIRED" {
			return "0"
		}
		return next(k)
	}
}

func TestDefaults(t *testing.T) {
	cfg, err := FromEnv(noAuth(func(string) string { return "" }))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	checks := map[string]string{
		"ListenAddr":      cfg.ListenAddr,
		"Upstream":        cfg.Upstream,
		"ModelID":         cfg.ModelID,
		"ReceiptIssuer":   cfg.ReceiptIssuer,
		"ReceiptAudience": cfg.ReceiptAudience,
		"DstackSocket":    cfg.DstackSocket,
	}
	want := map[string]string{
		"ListenAddr":      ":8443",
		"Upstream":        "http://127.0.0.1:30000",
		"ModelID":         "lordx64/cyberglm",
		"ReceiptIssuer":   "https://verify.adverserial.ai",
		"ReceiptAudience": "cc-chat.adverserial.ai",
		"DstackSocket":    "/var/run/dstack.sock",
	}
	for k, got := range checks {
		if got != want[k] {
			t.Errorf("%s = %q, want %q", k, got, want[k])
		}
	}
	if cfg.DevMode {
		t.Error("DevMode should default to false")
	}
	if len(cfg.TLSHostnames) == 0 || cfg.TLSHostnames[0] != "api.adverserial.ai" {
		t.Errorf("TLSHostnames should derive from ENDPOINT, got %v", cfg.TLSHostnames)
	}
}

func TestOverrides(t *testing.T) {
	env := map[string]string{
		"LISTEN_ADDR":   ":9443",
		"UPSTREAM":      "http://10.0.0.2:8000",
		"DEV_MODE":      "true",
		"MODEL_DIGEST":  "sha256:abc",
		"TLS_HOSTNAMES": "a.example, b.example",
	}
	cfg, err := FromEnv(noAuth(func(k string) string { return env[k] }))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.ListenAddr != ":9443" || cfg.Upstream != "http://10.0.0.2:8000" {
		t.Errorf("overrides not applied: %+v", cfg)
	}
	if !cfg.DevMode {
		t.Error("DevMode should be true")
	}
	if cfg.ModelDigest != "sha256:abc" {
		t.Errorf("ModelDigest = %q", cfg.ModelDigest)
	}
	if len(cfg.TLSHostnames) != 2 || cfg.TLSHostnames[1] != "b.example" {
		t.Errorf("TLSHostnames = %v", cfg.TLSHostnames)
	}
}

func TestParseBoolMatrix(t *testing.T) {
	for _, v := range []string{"", "0", "false", "NO", "off"} {
		cfg, err := FromEnv(noAuth(func(k string) string {
			if k == "DEV_MODE" {
				return v
			}
			return ""
		}))
		if err != nil || cfg.DevMode {
			t.Errorf("DEV_MODE=%q: got (%v, %v), want (false, nil)", v, cfg.DevMode, err)
		}
	}
	for _, v := range []string{"1", "true", "YES", "on"} {
		cfg, err := FromEnv(noAuth(func(k string) string {
			if k == "DEV_MODE" {
				return v
			}
			return ""
		}))
		if err != nil || !cfg.DevMode {
			t.Errorf("DEV_MODE=%q: got (%v, %v), want (true, nil)", v, cfg.DevMode, err)
		}
	}
	if _, err := FromEnv(noAuth(func(k string) string {
		if k == "DEV_MODE" {
			return "maybe"
		}
		return ""
	})); err == nil {
		t.Error("DEV_MODE=maybe should fail")
	}
}

func TestBadUpstream(t *testing.T) {
	for _, bad := range []string{"127.0.0.1:30000", "ftp://x", "://nope"} {
		_, err := FromEnv(noAuth(func(k string) string {
			if k == "UPSTREAM" {
				return bad
			}
			return ""
		}))
		if err == nil {
			t.Errorf("UPSTREAM=%q should fail", bad)
		}
	}
}

func TestCanonicalModelIDsRequired(t *testing.T) {
	for _, env := range []map[string]string{
		{"MODEL_ID": "cyberglm"},
		{"MODEL_ID": "LordX64/cyberglm"},
		{"ATTESTED_MODELS": "lordx64/cyberglm,cyberkimi"},
	} {
		if _, err := FromEnv(noAuth(func(k string) string { return env[k] })); err == nil {
			t.Errorf("env %v should reject non-canonical model ids", env)
		}
	}
	if _, err := FromEnv(noAuth(func(k string) string {
		if k == "ATTESTED_MODELS" {
			return "lordx64/cyberglm,lordx64/cyberkimi"
		}
		return ""
	})); err != nil {
		t.Fatalf("canonical model ids should parse: %v", err)
	}
}

func TestNewFieldDefaults(t *testing.T) {
	cfg, err := FromEnv(noAuth(func(string) string { return "" }))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.PublicBaseURL != cfg.Endpoint {
		t.Errorf("PublicBaseURL = %q, want default %q", cfg.PublicBaseURL, cfg.Endpoint)
	}
	if cfg.VerificationURL != "https://verify.adverserial.ai" {
		t.Errorf("VerificationURL = %q", cfg.VerificationURL)
	}
	if len(cfg.AttestedModels) != 0 {
		t.Errorf("AttestedModels = %v", cfg.AttestedModels)
	}
	if len(cfg.ACMEDomains) != 0 {
		t.Errorf("ACMEDomains = %v", cfg.ACMEDomains)
	}
	if cfg.ACMEDirectoryURL != "https://acme-v02.api.letsencrypt.org/directory" {
		t.Errorf("ACMEDirectoryURL = %q", cfg.ACMEDirectoryURL)
	}
}

func TestACMEValidation(t *testing.T) {
	withDomains := func(env map[string]string) func(string) string {
		if env == nil {
			env = map[string]string{}
		}
		env["ACME_DOMAINS"] = "cc-api.adverserial.ai,cc-chat.adverserial.ai"
		return noAuth(func(k string) string { return env[k] })
	}

	// Each missing prerequisite must fail.
	for _, missing := range []string{"ACME_EMAIL", "GANDI_PAT", "GANDI_ZONE", "CERT_DIR"} {
		env := map[string]string{
			"ACME_EMAIL": "ops@adverserial.ai",
			"GANDI_PAT":  "pat",
			"GANDI_ZONE": "adverserial.ai",
			"CERT_DIR":   "/data/certs",
		}
		delete(env, missing)
		if _, err := FromEnv(withDomains(env)); err == nil {
			t.Errorf("missing %s should fail", missing)
		}
	}

	// Complete config parses the domain list.
	full := map[string]string{
		"ACME_EMAIL": "ops@adverserial.ai",
		"GANDI_PAT":  "pat",
		"GANDI_ZONE": "adverserial.ai",
		"CERT_DIR":   "/data/certs",
	}
	cfg, err := FromEnv(withDomains(full))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if len(cfg.ACMEDomains) != 2 || cfg.ACMEDomains[0] != "cc-api.adverserial.ai" {
		t.Errorf("ACMEDomains = %v", cfg.ACMEDomains)
	}

	// ATTESTED_MODELS parsing.
	env := map[string]string{"ATTESTED_MODELS": " a/model , b/model ,,"}
	cfg, err = FromEnv(noAuth(func(k string) string { return env[k] }))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AttestedModels) != 2 || cfg.AttestedModels[0] != "a/model" || cfg.AttestedModels[1] != "b/model" {
		t.Errorf("AttestedModels = %v", cfg.AttestedModels)
	}
}

// TestAuthRequiredDefaultOn: auth is on by default and demands billing config.
func TestAuthRequiredDefaultOn(t *testing.T) {
	// Default on, billing missing → error.
	if _, err := FromEnv(func(string) string { return "" }); err == nil {
		t.Error("empty env should fail: AUTH_REQUIRED defaults on and needs billing config")
	}
	// Default on + billing config → ok.
	env := map[string]string{
		"BILLING_URL":           "https://billing.adverserial.ai",
		"BILLING_WRITER_SECRET": "s3cret",
	}
	cfg, err := FromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if !cfg.AuthRequired {
		t.Error("AuthRequired should default to true")
	}
	// Explicit off works without billing config.
	cfg, err = FromEnv(noAuth(func(string) string { return "" }))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthRequired {
		t.Error("AUTH_REQUIRED=0 should disable")
	}
	// On without secret fails.
	if _, err := FromEnv(func(k string) string {
		if k == "BILLING_URL" {
			return "https://billing.adverserial.ai"
		}
		return ""
	}); err == nil {
		t.Error("AUTH_REQUIRED on without BILLING_WRITER_SECRET should fail")
	}
}

func TestChatHostValidation(t *testing.T) {
	// Only one of the pair set → error.
	for _, env := range []map[string]string{
		{"CHAT_HOST": "cc-chat.adverserial.ai"},
		{"CHAT_DOCROOT": "/data/chat-dist"},
	} {
		if _, err := FromEnv(noAuth(func(k string) string { return env[k] })); err == nil {
			t.Errorf("env %v should fail (pair required)", env)
		}
	}
	// Both set → ok; host lowercased.
	env := map[string]string{
		"CHAT_HOST":    "CC-Chat.Adverserial.AI",
		"CHAT_DOCROOT": "/data/chat-dist",
	}
	cfg, err := FromEnv(noAuth(func(k string) string { return env[k] }))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ChatHost != "cc-chat.adverserial.ai" || cfg.ChatDocroot != "/data/chat-dist" {
		t.Errorf("chat vhost = %q %q", cfg.ChatHost, cfg.ChatDocroot)
	}
}

func TestConfidentialModeRequiresIsolatedAuthorization(t *testing.T) {
	seed := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	base := map[string]string{
		"CONFIDENTIAL_MODE":      "1",
		"AUTH_REQUIRED":          "0",
		"BILLING_URL":            "https://billing.adverserial.ai",
		"ENTITLEMENT_JWKS_JSON":  `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}`,
		"ENTITLEMENT_REPLAY_DIR": "/data/used-entitlements",
		"METER_SIGNING_SEED":     seed,
		"METER_OUTBOX_DIR":       "/data/meter-outbox",
	}
	if _, err := FromEnv(func(k string) string { return base[k] }); err != nil {
		t.Fatalf("complete confidential config: %v", err)
	}
	for _, missing := range []string{"BILLING_URL", "ENTITLEMENT_JWKS_JSON", "ENTITLEMENT_REPLAY_DIR", "METER_SIGNING_SEED", "METER_OUTBOX_DIR"} {
		env := make(map[string]string, len(base))
		for k, v := range base {
			env[k] = v
		}
		delete(env, missing)
		if _, err := FromEnv(func(k string) string { return env[k] }); err == nil {
			t.Errorf("missing %s accepted", missing)
		}
	}
	env := make(map[string]string, len(base))
	for k, v := range base {
		env[k] = v
	}
	env["AUTH_REQUIRED"] = "1"
	if _, err := FromEnv(func(k string) string { return env[k] }); err == nil {
		t.Error("legacy raw-key gate accepted in confidential mode")
	}
}
