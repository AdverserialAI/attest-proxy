// Package billing is the client for the Adverserial billing service (FastAPI
// on Heroku). It implements the two-call contract:
//
//	POST {BILLING_URL}/auth/check   Bearer BILLING_WRITER_SECRET
//	POST {BILLING_URL}/usage        Bearer BILLING_WRITER_SECRET
//
// The billing boundary is strict (WP-9): it receives api_key_prefix, token
// counts, model, request_id, and a timestamp — never prompt or completion
// content, never full API keys.
package billing

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Client talks to the billing service.
type Client struct {
	BaseURL string // legacy billing URL, e.g. https://billing.adverserial.ai
	// MeterURL is the distinct mTLS meter-ingress URL in confidential mode.
	// It must terminate TLS at an ingress that verifies the CVM client cert.
	MeterURL           string
	MeterIngressSecret string // direct-signed meter capability, never used for prompt traffic
	WriterSecret       string
	HTTP               *http.Client // optional; default 15s timeout
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// Verdict is the /auth/check response.
type Verdict struct {
	Authenticated bool   `json:"authenticated"`
	Allowed       bool   `json:"allowed"`
	Reason        string `json:"reason"`
	Message       string `json:"message"`
}

// authCheckRequest is the /auth/check request body (keys are contractual).
type authCheckRequest struct {
	APIKey string `json:"api_key"`
	Model  string `json:"model"`
}

// CheckAuth asks billing whether apiKey may use model. Any non-200 status or
// transport failure is an error; callers must fail closed (503).
func (c *Client) CheckAuth(ctx context.Context, apiKey, model string) (Verdict, error) {
	body, err := json.Marshal(authCheckRequest{APIKey: apiKey, Model: model})
	if err != nil {
		return Verdict{}, err
	}
	resp, err := c.post(ctx, "/auth/check", body)
	if err != nil {
		return Verdict{}, fmt.Errorf("billing auth check: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Verdict{}, fmt.Errorf("billing auth check status %d", resp.StatusCode)
	}
	var v Verdict
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v); err != nil {
		return Verdict{}, fmt.Errorf("billing auth check decode: %w", err)
	}
	return v, nil
}

// UsageEvent is the /usage request body. Keys match the billing schema
// exactly; billing is idempotent on RequestID.
type UsageEvent struct {
	Source       string `json:"source"` // always "attest-proxy"
	Model        string `json:"model"`
	APIKeyPrefix string `json:"api_key_prefix"` // first 8 chars of the client key
	InputTokens  int    `json:"input_tokens"`
	CachedTokens int    `json:"cached_tokens"`
	OutputTokens int    `json:"output_tokens"`
	RequestID    string `json:"request_id"` // uuid
	TS           string `json:"ts"`         // RFC 3339
}

// PostUsage writes one usage event. Callers treat it as fire-and-forget:
// errors are logged by the caller and never fail a user request.
func (c *Client) PostUsage(ctx context.Context, ev UsageEvent) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	resp, err := c.post(ctx, "/usage", body)
	if err != nil {
		return fmt.Errorf("billing usage write: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("billing usage write status %d", resp.StatusCode)
	}
	return nil
}

// PostMeter sends a proxy-signed, count-only confidential meter JWS through
// either the separately deployed mTLS meter ingress or the explicitly selected
// direct-signed billing route. Billing independently verifies the Ed25519 JWS.
func (c *Client) PostMeter(ctx context.Context, token string) error {
	body, err := json.Marshal(map[string]string{"meter": token})
	if err != nil {
		return err
	}
	baseURL := c.MeterURL
	if baseURL == "" {
		baseURL = c.BaseURL // retained only for non-confidential backwards compatibility
	}
	url := strings.TrimRight(baseURL, "/") + "/cc/meter"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.MeterIngressSecret != "" {
		req.Header.Set("X-Adverserial-Meter-Ingress", c.MeterIngressSecret)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("billing confidential meter write: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("billing confidential meter write status %d", resp.StatusCode)
	}
	return nil
}

// StartResult is the /cc/start response. Stored=false means billing no
// longer holds the reservation (released or expired); Started=true means the
// reservation was already dispatched once.
type StartResult struct {
	Stored  bool   `json:"stored"`
	Started bool   `json:"started"`
	Ignored string `json:"ignored"`
}

// PostStart registers the start of a reservation's dispatch with billing
// before any inference runs. It uses the same meter ingress (or direct-signed
// route) and Ed25519 JWS authentication as PostMeter, and is the fail-closed
// dispatch precondition: callers must treat any error as fatal to the
// request. Any 2xx response decodes into a StartResult; non-2xx and transport
// failures are errors.
func (c *Client) PostStart(ctx context.Context, token string) (StartResult, error) {
	body, err := json.Marshal(map[string]string{"start": token})
	if err != nil {
		return StartResult{}, err
	}
	baseURL := c.MeterURL
	if baseURL == "" {
		baseURL = c.BaseURL // retained only for non-confidential backwards compatibility
	}
	url := strings.TrimRight(baseURL, "/") + "/cc/start"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return StartResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.MeterIngressSecret != "" {
		req.Header.Set("X-Adverserial-Meter-Ingress", c.MeterIngressSecret)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return StartResult{}, fmt.Errorf("billing confidential start write: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return StartResult{}, fmt.Errorf("billing confidential start write status %d", resp.StatusCode)
	}
	var res StartResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&res); err != nil {
		return StartResult{}, fmt.Errorf("billing confidential start decode: %w", err)
	}
	return res, nil
}

func (c *Client) post(ctx context.Context, path string, body []byte) (*http.Response, error) {
	url := strings.TrimRight(c.BaseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.WriterSecret)
	req.Header.Set("Content-Type", "application/json")
	return c.httpClient().Do(req)
}

// NewMutualTLSHTTPClient constructs the client used only for confidential
// meter delivery. It validates the ingress server against the supplied CA and
// presents a dedicated CVM certificate. The caller must use it only for the
// fixed METER_URL; it is intentionally not a global transport.
func NewMutualTLSHTTPClient(certFile, keyFile, serverCAFile string) (*http.Client, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load meter client certificate: %w", err)
	}
	pemBytes, err := os.ReadFile(serverCAFile)
	if err != nil {
		return nil, fmt.Errorf("read meter ingress CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("meter ingress CA contains no PEM certificate")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      roots,
		MinVersion:   tls.VersionTLS13,
	}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second}, nil
}

// NewTLS13HTTPClient is used for direct signed count-only meter delivery.
// It relies on the platform trust store for billing's public certificate and
// deliberately has no client credential; the meter JWS plus dedicated
// capability authenticate the event at the application boundary.
func NewTLS13HTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second}
}
