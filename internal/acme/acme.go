// Package acme implements a minimal RFC 8555 (ACME v2) client supporting
// dns-01 challenges only, plus the Gandi LiveDNS and Cloudflare DNS providers
// and certificate persistence used by attest-proxy.
//
// Stdlib-only by invariant: JWS (ES256), CSR creation, and chain handling are
// built directly on crypto/x509 and encoding/json.
package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// DefaultRenewBefore is the renewal threshold: certificates with less
// remaining validity are re-issued.
const DefaultRenewBefore = 30 * 24 * time.Hour

// DNSProvider provisions the _acme-challenge TXT records.
type DNSProvider interface {
	// SetTXT creates/replaces the TXT rrset at name with the given value.
	SetTXT(ctx context.Context, name, value string) error
	// DeleteTXT removes the TXT rrset at name.
	DeleteTXT(ctx context.Context, name, value string) error
}

// Config configures the ACME client.
type Config struct {
	DirectoryURL string // ACME v2 directory URL
	Email        string // account contact (mailto:)
	Zone         string // DNS zone for computing relative challenge names
	DNS          DNSProvider
	HTTP         *http.Client // optional; defaults to a 30s-timeout client

	PollInterval     time.Duration // default 2s
	PollTimeout      time.Duration // default 2m
	PropagationDelay time.Duration // wait after TXT provisioning before notifying the CA
}

// Client is an ACME v2 client bound to one account key.
type Client struct {
	cfg        Config
	http       *http.Client
	key        *ecdsa.PrivateKey
	jwk        map[string]any
	thumbprint string

	nonce      string
	accountURL string
}

// NewClient returns a client using accountKey (persist/reuse it via Store so
// the ACME account survives restarts).
func NewClient(cfg Config, accountKey *ecdsa.PrivateKey) *Client {
	httpc := cfg.HTTP
	if httpc == nil {
		httpc = &http.Client{Timeout: 30 * time.Second}
	}
	pub := accountKey.Public().(*ecdsa.PublicKey)
	return &Client{
		cfg:        cfg,
		http:       httpc,
		key:        accountKey,
		jwk:        publicJWK(pub),
		thumbprint: jwkThumbprint(pub),
	}
}

// Obtain runs the full order flow for domains and returns the certificate
// plus its PEM encodings for persistence. DNS records are always cleaned up,
// including on failure.
func (c *Client) Obtain(ctx context.Context, domains []string) (tls.Certificate, []byte, []byte, error) {
	dir, err := c.directory(ctx)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	if err := c.fetchNonce(ctx, dir.NewNonce); err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	if err := c.newAccount(ctx, dir.NewAccount); err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	order, orderURL, err := c.newOrder(ctx, dir.NewOrder, domains)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}

	type pending struct {
		authzURL string
		chalURL  string
	}
	var pend []pending
	for _, authzURL := range order.Authorizations {
		authz, err := c.getAuthz(ctx, authzURL)
		if err != nil {
			return tls.Certificate{}, nil, nil, err
		}
		chal := authz.dns01()
		if chal == nil {
			return tls.Certificate{}, nil, nil, fmt.Errorf("acme: no dns-01 challenge offered for %s", authz.Identifier.Value)
		}
		name, err := ChallengeName(authz.Identifier.Value, c.cfg.Zone)
		if err != nil {
			return tls.Certificate{}, nil, nil, err
		}
		txt := txtValue(chal.Token, c.thumbprint)
		if err := c.cfg.DNS.SetTXT(ctx, name, txt); err != nil {
			return tls.Certificate{}, nil, nil, fmt.Errorf("dns set %s: %w", name, err)
		}
		defer func() {
			// Best-effort challenge cleanup; failures here are not fatal.
			_ = c.cfg.DNS.DeleteTXT(context.Background(), name, txt)
		}()
		pend = append(pend, pending{authzURL: authzURL, chalURL: chal.URL})
	}

	if c.cfg.PropagationDelay > 0 {
		select {
		case <-ctx.Done():
			return tls.Certificate{}, nil, nil, ctx.Err()
		case <-time.After(c.cfg.PropagationDelay):
		}
	}

	// Tell the CA the challenges are ready (RFC 8555 §7.5.1: empty object),
	// then poll each authorization until valid.
	for _, p := range pend {
		if _, err := c.post(ctx, p.chalURL, []byte("{}")); err != nil {
			return tls.Certificate{}, nil, nil, fmt.Errorf("acme: challenge notify: %w", err)
		}
	}
	for _, p := range pend {
		if err := c.pollAuthz(ctx, p.authzURL); err != nil {
			return tls.Certificate{}, nil, nil, err
		}
	}

	// Finalize with a fresh certificate key.
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	keyPEM, err := marshalKeyPKCS8(certKey)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}, certKey)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("acme: csr: %w", err)
	}
	finPayload, _ := json.Marshal(map[string]any{"csr": b64url(csrDER)})
	if _, err := c.post(ctx, order.Finalize, finPayload); err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("acme: finalize: %w", err)
	}

	certURL, err := c.pollOrder(ctx, orderURL)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	chainPEM, err := c.download(ctx, certURL)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	cert, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("acme: issued chain does not match key: %w", err)
	}
	return cert, chainPEM, keyPEM, nil
}

// --- directory & account ---

type directoryURLs struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
}

func (c *Client) directory(ctx context.Context) (*directoryURLs, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.DirectoryURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("acme: directory: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("acme: directory status %d", resp.StatusCode)
	}
	var dir directoryURLs
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		return nil, fmt.Errorf("acme: directory decode: %w", err)
	}
	if dir.NewNonce == "" || dir.NewAccount == "" || dir.NewOrder == "" {
		return nil, fmt.Errorf("acme: directory missing endpoints")
	}
	return &dir, nil
}

func (c *Client) fetchNonce(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("acme: newNonce: %w", err)
	}
	resp.Body.Close()
	c.noteNonce(resp.Header)
	if c.nonce == "" {
		return fmt.Errorf("acme: server returned no Replay-Nonce")
	}
	return nil
}

func (c *Client) newAccount(ctx context.Context, url string) error {
	payload, _ := json.Marshal(map[string]any{
		"termsOfServiceAgreed": true,
		"contact":              []string{"mailto:" + c.cfg.Email},
	})
	resp, body, err := c.postFull(ctx, url, payload)
	if err != nil {
		return fmt.Errorf("acme: newAccount: %w", err)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("acme: newAccount status %d: %s", resp.StatusCode, problemString(body))
	}
	c.accountURL = resp.Header.Get("Location")
	if c.accountURL == "" {
		return fmt.Errorf("acme: newAccount returned no account Location")
	}
	return nil
}

// --- order & authorization ---

type orderObject struct {
	Status         string       `json:"status"`
	Identifiers    []identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate"`
}

type identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (c *Client) newOrder(ctx context.Context, url string, domains []string) (*orderObject, string, error) {
	ids := make([]identifier, len(domains))
	for i, d := range domains {
		ids[i] = identifier{Type: "dns", Value: d}
	}
	payload, _ := json.Marshal(map[string]any{"identifiers": ids})
	resp, body, err := c.postFull(ctx, url, payload)
	if err != nil {
		return nil, "", fmt.Errorf("acme: newOrder: %w", err)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("acme: newOrder status %d: %s", resp.StatusCode, problemString(body))
	}
	var order orderObject
	if err := json.Unmarshal(body, &order); err != nil {
		return nil, "", fmt.Errorf("acme: newOrder decode: %w", err)
	}
	orderURL := resp.Header.Get("Location")
	if orderURL == "" || order.Finalize == "" || len(order.Authorizations) == 0 {
		return nil, "", fmt.Errorf("acme: newOrder incomplete (location=%q finalize=%q authz=%d)",
			orderURL, order.Finalize, len(order.Authorizations))
	}
	return &order, orderURL, nil
}

type authorization struct {
	Status     string      `json:"status"`
	Identifier identifier  `json:"identifier"`
	Challenges []challenge `json:"challenges"`
}

type challenge struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Token  string `json:"token"`
	Status string `json:"status"`
	Error  *struct {
		Type   string `json:"type"`
		Detail string `json:"detail"`
	} `json:"error"`
}

func (a *authorization) dns01() *challenge {
	for i := range a.Challenges {
		if a.Challenges[i].Type == "dns-01" {
			return &a.Challenges[i]
		}
	}
	return nil
}

func (c *Client) getAuthz(ctx context.Context, url string) (*authorization, error) {
	resp, body, err := c.postFull(ctx, url, nil) // POST-as-GET
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("acme: authorization status %d: %s", resp.StatusCode, problemString(body))
	}
	var authz authorization
	if err := json.Unmarshal(body, &authz); err != nil {
		return nil, fmt.Errorf("acme: authorization decode: %w", err)
	}
	return &authz, nil
}

func (c *Client) pollAuthz(ctx context.Context, url string) error {
	return c.poll(ctx, func() (bool, error) {
		authz, err := c.getAuthz(ctx, url)
		if err != nil {
			return false, err
		}
		switch authz.Status {
		case "valid":
			return true, nil
		case "invalid":
			for _, ch := range authz.Challenges {
				if ch.Error != nil {
					return false, fmt.Errorf("acme: authorization invalid: %s: %s", ch.Error.Type, ch.Error.Detail)
				}
			}
			return false, fmt.Errorf("acme: authorization invalid")
		case "pending", "processing":
			return false, nil
		default:
			return false, fmt.Errorf("acme: unexpected authorization status %q", authz.Status)
		}
	})
}

func (c *Client) pollOrder(ctx context.Context, orderURL string) (string, error) {
	var certURL string
	err := c.poll(ctx, func() (bool, error) {
		resp, body, err := c.postFull(ctx, orderURL, nil)
		if err != nil {
			return false, err
		}
		if resp.StatusCode != http.StatusOK {
			return false, fmt.Errorf("acme: order poll status %d: %s", resp.StatusCode, problemString(body))
		}
		var order orderObject
		if err := json.Unmarshal(body, &order); err != nil {
			return false, err
		}
		switch order.Status {
		case "valid":
			if order.Certificate == "" {
				return false, fmt.Errorf("acme: order valid but no certificate URL")
			}
			certURL = order.Certificate
			return true, nil
		case "invalid":
			return false, fmt.Errorf("acme: order invalid")
		case "pending", "processing", "ready":
			return false, nil
		default:
			return false, fmt.Errorf("acme: unexpected order status %q", order.Status)
		}
	})
	return certURL, err
}

func (c *Client) download(ctx context.Context, certURL string) ([]byte, error) {
	resp, body, err := c.postFull(ctx, certURL, nil) // POST-as-GET
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("acme: certificate download status %d: %s", resp.StatusCode, problemString(body))
	}
	if block, _ := pem.Decode(body); block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("acme: certificate response is not a PEM chain")
	}
	return body, nil
}

// --- JWS plumbing (RFC 8555 §6.2, ES256) ---

// post signs payload and posts it, returning the decoded body. A nil payload
// produces a POST-as-GET (empty payload field). >=400 becomes an error
// carrying the ACME problem detail.
func (c *Client) post(ctx context.Context, url string, payload []byte) ([]byte, error) {
	resp, body, err := c.postFull(ctx, url, payload)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("acme: POST %s status %d: %s", url, resp.StatusCode, problemString(body))
	}
	return body, nil
}

// postFull issues one signed POST, retrying exactly once on a badNonce error
// (servers attach a fresh Replay-Nonce to the error, RFC 8555 §6.5).
func (c *Client) postFull(ctx context.Context, url string, payload []byte) (*http.Response, []byte, error) {
	resp, body, err := c.postOnce(ctx, url, payload)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode == http.StatusBadRequest && strings.Contains(problemType(body), "badNonce") && c.nonce != "" {
		return c.postOnce(ctx, url, payload)
	}
	return resp, body, nil
}

// postOnce signs and posts, reads the body fully, and captures the response
// Replay-Nonce for the next request.
func (c *Client) postOnce(ctx context.Context, url string, payload []byte) (*http.Response, []byte, error) {
	if c.nonce == "" {
		return nil, nil, fmt.Errorf("acme: no nonce; fetch one first")
	}
	jwsBody, err := c.signJWS(url, payload)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(jwsBody))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("acme: POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	c.noteNonce(resp.Header)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("acme: read response: %w", err)
	}
	return resp, body, nil
}

func (c *Client) noteNonce(h http.Header) {
	if n := h.Get("Replay-Nonce"); n != "" {
		c.nonce = n
	}
}

// signJWS builds a flattened JWS JSON body: base64url(protected) + "." +
// base64url(payload) signed ES256 with the account key. The protected header
// carries jwk until the account URL is known (newAccount), kid afterwards.
func (c *Client) signJWS(url string, payload []byte) (string, error) {
	protected := map[string]any{
		"alg":   "ES256",
		"nonce": c.nonce,
		"url":   url,
	}
	if c.accountURL == "" {
		protected["jwk"] = c.jwk
	} else {
		protected["kid"] = c.accountURL
	}
	protectedJSON, err := json.Marshal(protected)
	if err != nil {
		return "", err
	}
	p64 := b64url(protectedJSON)
	var pay64 string
	if payload != nil {
		pay64 = b64url(payload)
	}
	digest := sha256.Sum256([]byte(p64 + "." + pay64))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, digest[:])
	if err != nil {
		return "", err
	}
	sig := append(pad32(r), pad32(s)...)
	env, err := json.Marshal(map[string]any{
		"protected": p64,
		"payload":   pay64,
		"signature": b64url(sig),
	})
	if err != nil {
		return "", err
	}
	return string(env), nil
}

func (c *Client) poll(ctx context.Context, fn func() (bool, error)) error {
	interval := c.cfg.PollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	timeout := c.cfg.PollTimeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		done, err := fn()
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return fmt.Errorf("acme: poll timed out after %s", timeout)
		case <-time.After(interval):
		}
	}
}

// --- helpers ---

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// txtValue computes the dns-01 TXT value: base64url(SHA-256(keyAuthorization))
// where keyAuthorization = token || '.' || base64url(account key thumbprint)
// (RFC 8555 §8.1, §8.4).
func txtValue(token, thumbprint string) string {
	sum := sha256.Sum256([]byte(token + "." + thumbprint))
	return b64url(sum[:])
}

// publicJWK returns the RFC 7517 public JWK for a P-256 key (no kid; the
// ACME jwk header member must contain exactly the public key).
func publicJWK(pub *ecdsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   b64url(pad32(pub.X)),
		"y":   b64url(pad32(pub.Y)),
	}
}

// jwkThumbprint is the RFC 7638 SHA-256 thumbprint, base64url-encoded.
func jwkThumbprint(pub *ecdsa.PublicKey) string {
	canonical := `{"crv":"P-256","kty":"EC","x":"` + b64url(pad32(pub.X)) + `","y":"` + b64url(pad32(pub.Y)) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return b64url(sum[:])
}

func pad32(i *big.Int) []byte {
	out := make([]byte, 32)
	b := i.Bytes()
	copy(out[32-len(b):], b)
	return out
}

func marshalKeyPKCS8(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// problem is an RFC 7807 ACME error body.
type problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

func problemType(body []byte) string {
	var p problem
	_ = json.Unmarshal(body, &p)
	return p.Type
}

func problemString(body []byte) string {
	var p problem
	if err := json.Unmarshal(body, &p); err == nil && (p.Type != "" || p.Detail != "") {
		return p.Type + " " + p.Detail
	}
	s := string(body)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
