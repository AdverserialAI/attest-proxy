package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
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
		"ReceiptAudience": "https://chat.adverserial.ai",
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
		env["ACME_DOMAINS"] = "api.adverserial.ai,chat.adverserial.ai"
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
	if len(cfg.ACMEDomains) != 2 || cfg.ACMEDomains[0] != "api.adverserial.ai" {
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

func TestACMEDNSProviderSelection(t *testing.T) {
	withDomains := func(env map[string]string) func(string) string {
		base := map[string]string{
			"ACME_DOMAINS": "api.adverserial.ai",
			"ACME_EMAIL":   "ops@adverserial.ai",
			"CERT_DIR":     "/data/certs",
		}
		for k, v := range env {
			base[k] = v
		}
		return noAuth(func(k string) string { return base[k] })
	}

	// Default provider is gandi and keeps requiring GANDI_*.
	cfg, err := FromEnv(withDomains(map[string]string{
		"GANDI_PAT":  "pat",
		"GANDI_ZONE": "adverserial.ai",
	}))
	if err != nil {
		t.Fatalf("gandi default: %v", err)
	}
	if cfg.DNSProvider != "gandi" {
		t.Errorf("DNSProvider = %q, want gandi", cfg.DNSProvider)
	}

	// Cloudflare requires its own credentials, not GANDI_*.
	for _, missing := range []string{"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ZONE"} {
		env := map[string]string{
			"DNS_PROVIDER":         "cloudflare",
			"CLOUDFLARE_API_TOKEN": "token",
			"CLOUDFLARE_ZONE":      "adverserial.ai",
		}
		delete(env, missing)
		if _, err := FromEnv(withDomains(env)); err == nil {
			t.Errorf("missing %s should fail", missing)
		}
	}
	cfg, err = FromEnv(withDomains(map[string]string{
		"DNS_PROVIDER":         "cloudflare",
		"CLOUDFLARE_API_TOKEN": "token",
		"CLOUDFLARE_ZONE":      "adverserial.ai",
	}))
	if err != nil {
		t.Fatalf("cloudflare: %v", err)
	}
	if cfg.DNSProvider != "cloudflare" || cfg.CloudflareZone != "adverserial.ai" {
		t.Errorf("cloudflare config not retained: %+v", cfg)
	}

	// Unknown providers fail with a clear error.
	if _, err := FromEnv(withDomains(map[string]string{
		"DNS_PROVIDER": "route53",
		"GANDI_PAT":    "pat",
		"GANDI_ZONE":   "adverserial.ai",
	})); err == nil {
		t.Error("unsupported DNS_PROVIDER should fail")
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
		{"CHAT_HOST": "chat.adverserial.ai"},
		{"CHAT_DOCROOT": "/data/chat-dist"},
	} {
		if _, err := FromEnv(noAuth(func(k string) string { return env[k] })); err == nil {
			t.Errorf("env %v should fail (pair required)", env)
		}
	}
	// Both set → ok; host lowercased.
	env := map[string]string{
		"CHAT_HOST":    "Chat.Adverserial.AI",
		"CHAT_DOCROOT": "/data/chat-dist",
	}
	cfg, err := FromEnv(noAuth(func(k string) string { return env[k] }))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ChatHost != "chat.adverserial.ai" || cfg.ChatDocroot != "/data/chat-dist" {
		t.Errorf("chat vhost = %q %q", cfg.ChatHost, cfg.ChatDocroot)
	}
}

func TestConfidentialModeRequiresIsolatedAuthorization(t *testing.T) {
	base := map[string]string{
		"CONFIDENTIAL_MODE":          "1",
		"EHBP_REQUIRED":              "1",
		"AUTH_REQUIRED":              "0",
		"ENTITLEMENT_JWKS_JSON":      `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}`,
		"ENTITLEMENT_REPLAY_DIR":     "/data/used-entitlements",
		"METER_OUTBOX_DIR":           "/data/meter-outbox",
		"METER_URL":                  "https://meter-ingress.adverserial.ai",
		"METER_CLIENT_CERT_FILE":     "/state/meter-tls/client.crt",
		"METER_CLIENT_KEY_FILE":      "/state/meter-tls/client.key",
		"METER_SERVER_CA_FILE":       "/state/meter-tls/ingress-ca.crt",
		"ENCLAVE_KEY_DIR":            "/state/keys",
		"UPSTREAM_BEARER_TOKEN_FILE": "/run/upstream/token",
		"MODEL_DIGEST":               "sha256:" + strings.Repeat("a", 64),
	}
	if _, err := FromEnv(func(k string) string { return base[k] }); err != nil {
		t.Fatalf("complete confidential config: %v", err)
	}
	for _, missing := range []string{"ENTITLEMENT_JWKS_JSON", "ENTITLEMENT_REPLAY_DIR", "METER_OUTBOX_DIR", "METER_URL", "METER_CLIENT_CERT_FILE", "METER_CLIENT_KEY_FILE", "METER_SERVER_CA_FILE", "ENCLAVE_KEY_DIR", "UPSTREAM_BEARER_TOKEN_FILE"} {
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

func TestResolveModelManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	digest := "sha256:" + strings.Repeat("a", 64)
	if err := os.WriteFile(path, []byte(`{"version":1,"algorithm":"sha256-tree-v1","model_id":"lordx64/cyberglm","file_count":2,"total_bytes":3,"digest":"`+digest+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := ResolveModelManifest(Config{ModelID: "lordx64/cyberglm", ModelManifestFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ModelDigest != digest {
		t.Fatalf("ModelDigest = %q, want %q", cfg.ModelDigest, digest)
	}
}

func TestResolveModelManifestRejectsMismatchedModel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"algorithm":"sha256-tree-v1","model_id":"lordx64/cyberkimi","file_count":1,"total_bytes":1,"digest":"sha256:`+strings.Repeat("a", 64)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveModelManifest(Config{ModelID: "lordx64/cyberglm", ModelManifestFile: path}); err == nil {
		t.Fatal("ResolveModelManifest accepted a mismatched model")
	}
}

func TestConfidentialModeDirectSignedMetering(t *testing.T) {
	env := map[string]string{
		"CONFIDENTIAL_MODE":           "1",
		"EHBP_REQUIRED":               "1",
		"AUTH_REQUIRED":               "0",
		"ENTITLEMENT_JWKS_JSON":       `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}`,
		"ENTITLEMENT_REPLAY_DIR":      "/data/used-entitlements",
		"METER_OUTBOX_DIR":            "/data/meter-outbox",
		"METER_URL":                   "https://billing.adverserial.ai",
		"METER_DELIVERY_MODE":         "direct-signed",
		"METER_INGRESS_SHARED_SECRET": "dedicated-meter-capability",
		"ENCLAVE_KEY_DIR":             "/state/keys",
		"UPSTREAM_BEARER_TOKEN_FILE":  "/run/upstream/token",
		"MODEL_DIGEST":                "sha256:" + strings.Repeat("a", 64),
	}
	cfg, err := FromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("direct-signed config: %v", err)
	}
	if cfg.MeterDeliveryMode != "direct-signed" || cfg.MeterIngressSecret == "" {
		t.Fatalf("direct-signed settings were not retained: %+v", cfg)
	}
	delete(env, "METER_INGRESS_SHARED_SECRET")
	if _, err := FromEnv(func(k string) string { return env[k] }); err == nil {
		t.Fatal("direct-signed config accepted without meter capability")
	}
	env["METER_INGRESS_SHARED_SECRET"] = "dedicated-meter-capability"
	env["METER_URL"] = "https://other.example"
	if _, err := FromEnv(func(k string) string { return env[k] }); err == nil {
		t.Fatal("direct-signed config accepted a non-billing destination")
	}
}

// confidentialEnv is a complete, valid confidential configuration.
func confidentialEnv() map[string]string {
	return map[string]string{
		"CONFIDENTIAL_MODE":           "1",
		"EHBP_REQUIRED":               "1",
		"AUTH_REQUIRED":               "0",
		"ENTITLEMENT_JWKS_JSON":       `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}`,
		"ENTITLEMENT_REPLAY_DIR":      "/state/used-entitlements",
		"METER_OUTBOX_DIR":            "/state/meter-outbox",
		"METER_URL":                   "https://billing.adverserial.ai",
		"METER_DELIVERY_MODE":         "direct-signed",
		"METER_INGRESS_SHARED_SECRET": "dedicated-meter-capability",
		"ENCLAVE_KEY_DIR":             "/state/keys",
		"UPSTREAM_BEARER_TOKEN_FILE":  "/run/upstream/token",
		"MODEL_DIGEST":                "sha256:" + strings.Repeat("a", 64),
	}
}

func TestConfidentialModeRefusesExternallySuppliedSecrets(t *testing.T) {
	const marker = "SECRET-VALUE-MUST-NOT-APPEAR"
	if _, err := FromEnv(func(k string) string { return confidentialEnv()[k] }); err != nil {
		t.Fatalf("baseline confidential config: %v", err)
	}
	for _, name := range []string{"RECEIPT_SIGNING_SEED", "METER_SIGNING_SEED", "EHBP_IDENTITY_B64", "UPSTREAM_BEARER_TOKEN"} {
		env := confidentialEnv()
		env[name] = marker
		_, err := FromEnv(func(k string) string { return env[k] })
		if err == nil {
			t.Errorf("%s accepted in confidential mode", name)
			continue
		}
		if !strings.Contains(err.Error(), name) {
			t.Errorf("refusal for %s does not name the variable: %v", name, err)
		}
		if strings.Contains(err.Error(), marker) {
			t.Errorf("refusal for %s leaks the value: %v", name, err)
		}
		// Whitespace-only is treated as unset, not as a secret.
		env[name] = "  "
		if _, err := FromEnv(func(k string) string { return env[k] }); err != nil {
			t.Errorf("blank %s refused: %v", name, err)
		}
	}
}

func TestConfidentialModeKeyDirAndTokenFileValidation(t *testing.T) {
	for name, mutate := range map[string]func(map[string]string){
		"relative key dir":       func(e map[string]string) { e["ENCLAVE_KEY_DIR"] = "state/keys" },
		"relative token file":    func(e map[string]string) { e["UPSTREAM_BEARER_TOKEN_FILE"] = "token" },
		"key dir is replay dir":  func(e map[string]string) { e["ENCLAVE_KEY_DIR"] = e["ENTITLEMENT_REPLAY_DIR"] },
		"key dir is outbox dir":  func(e map[string]string) { e["ENCLAVE_KEY_DIR"] = e["METER_OUTBOX_DIR"] },
		"missing key dir":        func(e map[string]string) { delete(e, "ENCLAVE_KEY_DIR") },
		"missing token file":     func(e map[string]string) { delete(e, "UPSTREAM_BEARER_TOKEN_FILE") },
		"dev mode with enclave":  func(e map[string]string) { e["DEV_MODE"] = "1" },
		"plaintext without EHBP": func(e map[string]string) { e["EHBP_REQUIRED"] = "0" },
	} {
		env := confidentialEnv()
		mutate(env)
		if _, err := FromEnv(func(k string) string { return env[k] }); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestConfidentialUpstreamAddress(t *testing.T) {
	for _, ok := range []string{
		"http://127.0.0.1:30000", "http://localhost:30000", "http://[::1]:30000",
		"http://sglang:30000", "http://model-runtime-2:8000", "http://a:1",
	} {
		env := confidentialEnv()
		env["UPSTREAM"] = ok
		if _, err := FromEnv(func(k string) string { return env[k] }); err != nil {
			t.Errorf("UPSTREAM=%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://sglang",                                // no explicit port
		"https://sglang:30000",                         // only plain http on the internal network
		"http://sglang.internal:30000",                 // dotted: resolvable outside the VM
		"http://sglang.:30000",                         // trailing dot
		"http://SGLang:30000",                          // not normalized
		"http://10.0.0.2:30000",                        // address on some other network
		"http://169.254.169.254:80",                    // metadata service
		"http://-sglang:30000",                         // not a valid label
		"http://2sglang:30000",                         // must start with a letter
		"http://sg_lang:30000",                         // underscore
		"http://example.com:30000",                     // public host
		"http://" + strings.Repeat("a", 64) + ":30000", // label too long
		"http://user@sglang:30000",                     // userinfo
		"http://sglang:30000/v1",                       // path
	} {
		env := confidentialEnv()
		env["UPSTREAM"] = bad
		if _, err := FromEnv(func(k string) string { return env[k] }); err == nil {
			t.Errorf("UPSTREAM=%q accepted in confidential mode", bad)
		}
	}
}

func TestLegacyModeKeepsEnvSecretsAndRejectsBothTokenSources(t *testing.T) {
	seed := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	env := map[string]string{"RECEIPT_SIGNING_SEED": seed, "UPSTREAM_BEARER_TOKEN": "dev-token"}
	cfg, err := FromEnv(noAuth(func(k string) string { return env[k] }))
	if err != nil {
		t.Fatalf("non-confidential seed config: %v", err)
	}
	if cfg.ReceiptSigningSeed != seed || cfg.UpstreamBearer != "dev-token" {
		t.Error("development seed or token was not retained")
	}
	env["UPSTREAM_BEARER_TOKEN_FILE"] = "/run/upstream/token"
	if _, err := FromEnv(noAuth(func(k string) string { return env[k] })); err == nil {
		t.Error("both upstream token sources accepted")
	}
}
