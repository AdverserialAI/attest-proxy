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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to the billing service.
type Client struct {
	BaseURL      string // e.g. https://billing.adverserial.ai
	WriterSecret string
	HTTP         *http.Client // optional; default 15s timeout
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

// PostMeter sends a proxy-signed, count-only confidential meter JWS. This
// intentionally uses a separate endpoint and no shared bearer credential:
// billing verifies the Ed25519 signature against its configured proxy JWKS.
func (c *Client) PostMeter(ctx context.Context, token string) error {
	body, err := json.Marshal(map[string]string{"meter": token})
	if err != nil {
		return err
	}
	url := strings.TrimRight(c.BaseURL, "/") + "/cc/meter"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
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
