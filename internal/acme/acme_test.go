package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// stubDNS records SetTXT/DeleteTXT calls.
type stubDNS struct {
	sets    map[string]string
	deletes []string
	setErr  error
}

func (s *stubDNS) SetTXT(_ context.Context, name, value string) error {
	if s.setErr != nil {
		return s.setErr
	}
	if s.sets == nil {
		s.sets = map[string]string{}
	}
	s.sets[name] = value
	return nil
}

func (s *stubDNS) DeleteTXT(_ context.Context, name, value string) error {
	s.deletes = append(s.deletes, name)
	return nil
}

// mockACME is a minimal but honest RFC 8555 server: it verifies every JWS
// signature (jwk on new-account, kid afterwards), enforces nonce chaining,
// and issues a real certificate from a test CA after checking the CSR.
type mockACME struct {
	t          *testing.T
	base       string
	nonce      int
	lastNonce  string
	accountKey *ecdsa.PublicKey
	accountURL string
	domains    []string
	tokens     []string // per-authz challenge tokens
	authzValid []bool
	orderValid bool
	issuedPEM  []byte
	caKey      *ecdsa.PrivateKey
	caCert     *x509.Certificate
	caPEM      []byte
}

func newMockACME(t *testing.T, domains []string) *mockACME {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mock acme ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	return &mockACME{
		t:      t,
		caKey:  caKey,
		caCert: caCert,
		caPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
	}
}

func (m *mockACME) nextNonce(w http.ResponseWriter) {
	m.nonce++
	m.lastNonce = fmt.Sprintf("nonce-%d", m.nonce)
	w.Header().Set("Replay-Nonce", m.lastNonce)
}

type jwsEnvelope struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// verifyJWS checks the envelope and returns the decoded payload.
func (m *mockACME) verifyJWS(r *http.Request, fullURL string) []byte {
	m.t.Helper()
	var env jwsEnvelope
	if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
		m.t.Fatalf("jws envelope: %v", err)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/jose+json" {
		m.t.Errorf("Content-Type = %q, want application/jose+json", ct)
	}

	protectedRaw, err := base64.RawURLEncoding.DecodeString(env.Protected)
	if err != nil {
		m.t.Fatalf("protected b64: %v", err)
	}
	var protected map[string]any
	if err := json.Unmarshal(protectedRaw, &protected); err != nil {
		m.t.Fatalf("protected json: %v", err)
	}

	if protected["alg"] != "ES256" {
		m.t.Errorf("alg = %v", protected["alg"])
	}
	if protected["nonce"] != m.lastNonce {
		m.t.Errorf("nonce = %v, want %v (chaining broken)", protected["nonce"], m.lastNonce)
	}
	if protected["url"] != fullURL {
		m.t.Errorf("protected url = %v, want %v", protected["url"], fullURL)
	}

	// Key selection: jwk for new-account (which registers it), kid afterwards.
	var key *ecdsa.PublicKey
	if jwkAny, ok := protected["jwk"]; ok {
		if protected["kid"] != nil {
			m.t.Error("protected must not carry both jwk and kid")
		}
		jwk, ok := jwkAny.(map[string]any)
		if !ok {
			m.t.Fatalf("jwk is %T", jwkAny)
		}
		key = jwkToPublicKey(m.t, jwk)
		m.accountKey = key // account registration
	} else {
		kid, _ := protected["kid"].(string)
		if kid != m.accountURL {
			m.t.Errorf("kid = %q, want account %q", kid, m.accountURL)
		}
		key = m.accountKey
	}

	sig, err := base64.RawURLEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != 64 {
		m.t.Fatalf("signature decode: %v (len %d)", err, len(sig))
	}
	digest := sha256.Sum256([]byte(env.Protected + "." + env.Payload))
	rInt := new(big.Int).SetBytes(sig[:32])
	sInt := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(key, digest[:], rInt, sInt) {
		m.t.Fatal("JWS signature verification failed")
	}

	if env.Payload == "" {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		m.t.Fatalf("payload b64: %v", err)
	}
	return payload
}

func jwkToPublicKey(t *testing.T, jwk map[string]any) *ecdsa.PublicKey {
	t.Helper()
	xs, _ := jwk["x"].(string)
	ys, _ := jwk["y"].(string)
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" || xs == "" || ys == "" {
		t.Fatalf("bad jwk: %v", jwk)
	}
	x, err := base64.RawURLEncoding.DecodeString(xs)
	if err != nil {
		t.Fatal(err)
	}
	y, err := base64.RawURLEncoding.DecodeString(ys)
	if err != nil {
		t.Fatal(err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
}

func (m *mockACME) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /directory", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`,
			m.base+"/nonce", m.base+"/new-account", m.base+"/new-order")
	})
	mux.HandleFunc("HEAD /nonce", func(w http.ResponseWriter, r *http.Request) {
		m.nextNonce(w)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /new-account", func(w http.ResponseWriter, r *http.Request) {
		payload := m.verifyJWS(r, m.base+"/new-account")
		var req struct {
			TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
			Contact              []string `json:"contact"`
		}
		if err := json.Unmarshal(payload, &req); err != nil || !req.TermsOfServiceAgreed {
			m.t.Fatalf("new-account payload: %v (%s)", err, payload)
		}
		if len(req.Contact) != 1 || !strings.HasPrefix(req.Contact[0], "mailto:") {
			m.t.Errorf("contact = %v", req.Contact)
		}
		m.accountURL = m.base + "/accounts/1"
		m.nextNonce(w)
		w.Header().Set("Location", m.accountURL)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"status":"valid","contact":%q}`, req.Contact)
	})
	mux.HandleFunc("POST /new-order", func(w http.ResponseWriter, r *http.Request) {
		payload := m.verifyJWS(r, m.base+"/new-order")
		var req struct {
			Identifiers []identifier `json:"identifiers"`
		}
		if err := json.Unmarshal(payload, &req); err != nil || len(req.Identifiers) == 0 {
			m.t.Fatalf("new-order payload: %v (%s)", err, payload)
		}
		for _, id := range req.Identifiers {
			if id.Type != "dns" {
				m.t.Errorf("identifier type = %q", id.Type)
			}
			m.domains = append(m.domains, id.Value)
			m.tokens = append(m.tokens, fmt.Sprintf("token-%d", len(m.tokens)))
			m.authzValid = append(m.authzValid, false)
		}
		m.nextNonce(w)
		w.Header().Set("Location", m.base+"/orders/1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		var authzs []string
		for i := range m.domains {
			authzs = append(authzs, fmt.Sprintf("%s/authz/%d", m.base, i))
		}
		authzJSON, _ := json.Marshal(authzs)
		fmt.Fprintf(w, `{"status":"pending","authorizations":%s,"finalize":%q}`,
			authzJSON, m.base+"/orders/1/finalize")
	})
	mux.HandleFunc("POST /authz/", func(w http.ResponseWriter, r *http.Request) {
		m.verifyJWS(r, m.base+r.URL.Path)
		var n int
		if _, err := fmt.Sscanf(r.URL.Path, "/authz/%d", &n); err != nil {
			m.t.Fatalf("authz path %s", r.URL.Path)
		}
		status := "pending"
		if m.authzValid[n] {
			status = "valid"
		}
		m.nextNonce(w)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":%q,"identifier":{"type":"dns","value":%q},`+
			`"challenges":[{"type":"http-01","url":%q,"token":"no"},`+
			`{"type":"dns-01","url":%q,"token":%q,"status":%q}]}`,
			status, m.domains[n], m.base+"/ignore",
			fmt.Sprintf("%s/chal/%d", m.base, n), m.tokens[n], status)
	})
	mux.HandleFunc("POST /chal/", func(w http.ResponseWriter, r *http.Request) {
		payload := m.verifyJWS(r, m.base+r.URL.Path)
		if string(payload) != "{}" {
			m.t.Errorf("challenge notify payload = %s, want {}", payload)
		}
		var n int
		if _, err := fmt.Sscanf(r.URL.Path, "/chal/%d", &n); err != nil {
			m.t.Fatalf("chal path %s", r.URL.Path)
		}
		m.authzValid[n] = true
		m.nextNonce(w)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"type":"dns-01","status":"valid","url":%q,"token":%q}`,
			m.base+r.URL.Path, m.tokens[n])
	})
	mux.HandleFunc("POST /orders/1/finalize", func(w http.ResponseWriter, r *http.Request) {
		payload := m.verifyJWS(r, m.base+"/orders/1/finalize")
		var req struct {
			CSR string `json:"csr"`
		}
		if err := json.Unmarshal(payload, &req); err != nil || req.CSR == "" {
			m.t.Fatalf("finalize payload: %v (%s)", err, payload)
		}
		csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
		if err != nil {
			m.t.Fatalf("csr b64: %v", err)
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			m.t.Fatalf("csr parse: %v", err)
		}
		if err := csr.CheckSignature(); err != nil {
			m.t.Fatalf("csr signature: %v", err)
		}
		if len(csr.DNSNames) != len(m.domains) {
			m.t.Fatalf("csr SANs = %v, want %v", csr.DNSNames, m.domains)
		}
		for i, d := range m.domains {
			if csr.DNSNames[i] != d {
				m.t.Fatalf("csr SAN %d = %q, want %q", i, csr.DNSNames[i], d)
			}
		}

		// Issue a real leaf from the mock CA.
		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: csr.Subject.CommonName},
			DNSNames:     csr.DNSNames,
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(90 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, m.caCert, csr.PublicKey, m.caKey)
		if err != nil {
			m.t.Fatalf("issue: %v", err)
		}
		m.issuedPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
		m.orderValid = true
		m.nextNonce(w)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"processing"}`)
	})
	mux.HandleFunc("POST /orders/1", func(w http.ResponseWriter, r *http.Request) {
		m.verifyJWS(r, m.base+"/orders/1")
		m.nextNonce(w)
		w.Header().Set("Content-Type", "application/json")
		if m.orderValid {
			fmt.Fprintf(w, `{"status":"valid","certificate":%q}`, m.base+"/orders/1/cert")
		} else {
			fmt.Fprintf(w, `{"status":"processing"}`)
		}
	})
	mux.HandleFunc("POST /orders/1/cert", func(w http.ResponseWriter, r *http.Request) {
		payload := m.verifyJWS(r, m.base+"/orders/1/cert")
		if payload != nil {
			m.t.Errorf("certificate download must be POST-as-GET, got %s", payload)
		}
		m.nextNonce(w)
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(append(m.issuedPEM, m.caPEM...))
	})
	return mux
}

func TestFullOrderFlow(t *testing.T) {
	domains := []string{"api.adverserial.ai", "chat.adverserial.ai"}
	mock := newMockACME(t, domains)
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()
	mock.base = ts.URL

	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dns := &stubDNS{}
	client := NewClient(Config{
		DirectoryURL: ts.URL + "/directory",
		Email:        "ops@adverserial.ai",
		Zone:         "adverserial.ai",
		DNS:          dns,
		PollInterval: time.Millisecond,
		PollTimeout:  10 * time.Second,
	}, accountKey)

	cert, chainPEM, keyPEM, err := client.Obtain(context.Background(), domains)
	if err != nil {
		t.Fatalf("Obtain: %v", err)
	}

	// Certificate sanity: SANs, chain parses, verifies against the mock CA.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 2 || leaf.DNSNames[0] != domains[0] || leaf.DNSNames[1] != domains[1] {
		t.Errorf("leaf SANs = %v", leaf.DNSNames)
	}
	roots := x509.NewCertPool()
	roots.AddCert(mock.caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: domains[0], Roots: roots}); err != nil {
		t.Errorf("issued chain does not verify against CA: %v", err)
	}
	if len(chainPEM) == 0 || len(keyPEM) == 0 {
		t.Error("PEM outputs empty")
	}

	// DNS provisioning: correct relative names and TXT values derived from
	// the mock's tokens and the account key thumbprint (RFC 8555 §8.1/§8.4).
	thumb := jwkThumbprint(accountKey.Public().(*ecdsa.PublicKey))
	for i, d := range domains {
		name, err := ChallengeName(d, "adverserial.ai")
		if err != nil {
			t.Fatal(err)
		}
		got, ok := dns.sets[name]
		if !ok {
			t.Errorf("SetTXT never called for %s", name)
			continue
		}
		want := txtValue(mock.tokens[i], thumb)
		if got != want {
			t.Errorf("TXT %s = %q, want %q", name, got, want)
		}
	}
	// Cleanup ran for every challenge.
	if len(dns.deletes) != len(domains) {
		t.Errorf("DeleteTXT calls = %v, want %d", dns.deletes, len(domains))
	}
}

// TestOrderFailsWhenDNSSetFails: a provider error aborts the order before any
// challenge is notified.
func TestOrderFailsWhenDNSSetFails(t *testing.T) {
	domains := []string{"api.adverserial.ai"}
	mock := newMockACME(t, domains)
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()
	mock.base = ts.URL

	accountKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dns := &stubDNS{setErr: fmt.Errorf("gandi: 401 unauthorized")}
	client := NewClient(Config{
		DirectoryURL: ts.URL + "/directory",
		Email:        "ops@adverserial.ai",
		Zone:         "adverserial.ai",
		DNS:          dns,
		PollInterval: time.Millisecond,
	}, accountKey)

	_, _, _, err := client.Obtain(context.Background(), domains)
	if err == nil || !strings.Contains(err.Error(), "401 unauthorized") {
		t.Fatalf("Obtain error = %v", err)
	}
}

// TestAccountReuseAcrossClients: two Client instances sharing one account key
// hit newAccount twice but register the same account URL (idempotent reuse).
func TestAccountReuseAcrossClients(t *testing.T) {
	mock := newMockACME(t, nil)
	ts := httptest.NewServer(mock.handler())
	defer ts.Close()
	mock.base = ts.URL

	accountKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for i := 0; i < 2; i++ {
		client := NewClient(Config{
			DirectoryURL: ts.URL + "/directory",
			Email:        "ops@adverserial.ai",
			DNS:          &stubDNS{},
			Zone:         "adverserial.ai",
		}, accountKey)
		if err := client.fetchNonce(context.Background(), ts.URL+"/nonce"); err != nil {
			t.Fatal(err)
		}
		if err := client.newAccount(context.Background(), ts.URL+"/new-account"); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if client.accountURL != ts.URL+"/accounts/1" {
			t.Errorf("accountURL = %q", client.accountURL)
		}
	}
}
