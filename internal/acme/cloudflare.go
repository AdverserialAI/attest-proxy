package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// cloudflareDefaultBaseURL is the Cloudflare API v4 root.
const cloudflareDefaultBaseURL = "https://api.cloudflare.com/client/v4"

// CloudflareProvider implements DNSProvider against the Cloudflare API v4
// using an API token with Edit-zone-DNS permission on the zone.
type CloudflareProvider struct {
	Token string // Cloudflare API token
	Zone  string // e.g. adverserial.ai

	// BaseURL and HTTP are test hooks; defaults are the production API and a
	// 30s-timeout client.
	BaseURL string
	HTTP    *http.Client

	mu     sync.Mutex
	zoneID string // cached zone ID resolved from Zone
}

func (c *CloudflareProvider) base() string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return cloudflareDefaultBaseURL
}

func (c *CloudflareProvider) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// fqdn maps a relative challenge name to the absolute record name: the zone
// API matches on fully qualified names.
func (c *CloudflareProvider) fqdn(name string) string {
	return name + "." + strings.TrimSuffix(c.Zone, ".")
}

// resolveZoneID resolves and caches the zone ID for the configured zone name.
func (c *CloudflareProvider) resolveZoneID(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.zoneID != "" {
		return c.zoneID, nil
	}
	u := fmt.Sprintf("%s/zones?name=%s&status=active", c.base(), url.QueryEscape(c.Zone))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	var zones []struct {
		ID string `json:"id"`
	}
	if err := c.do(req, &zones); err != nil {
		return "", err
	}
	if len(zones) == 0 {
		return "", fmt.Errorf("cloudflare: no active zone named %q", c.Zone)
	}
	c.zoneID = zones[0].ID
	return c.zoneID, nil
}

// cfDNSRecord is the subset of a Cloudflare DNS record the provider needs.
type cfDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

// listTXT returns the TXT records at fqdn in the zone.
func (c *CloudflareProvider) listTXT(ctx context.Context, zoneID, fqdn string) ([]cfDNSRecord, error) {
	u := fmt.Sprintf("%s/zones/%s/dns_records?type=TXT&name=%s",
		c.base(), url.PathEscape(zoneID), url.QueryEscape(fqdn))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	var records []cfDNSRecord
	if err := c.do(req, &records); err != nil {
		return nil, err
	}
	return records, nil
}

// SetTXT creates or replaces the TXT record (Cloudflare upsert semantics)
// with a short TTL so challenges converge and disappear quickly.
func (c *CloudflareProvider) SetTXT(ctx context.Context, name, value string) error {
	zoneID, err := c.resolveZoneID(ctx)
	if err != nil {
		return err
	}
	fqdn := c.fqdn(name)
	records, err := c.listTXT(ctx, zoneID, fqdn)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{
		"type":    "TXT",
		"name":    fqdn,
		"content": value,
		"ttl":     120,
	})
	if err != nil {
		return err
	}
	method := http.MethodPost
	u := fmt.Sprintf("%s/zones/%s/dns_records", c.base(), url.PathEscape(zoneID))
	if len(records) > 0 {
		method = http.MethodPut
		u += "/" + url.PathEscape(records[0].ID)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

// DeleteTXT removes the TXT records at name, restricted to value when it is
// non-empty. Already-gone records (empty list or 404) are success.
func (c *CloudflareProvider) DeleteTXT(ctx context.Context, name, value string) error {
	zoneID, err := c.resolveZoneID(ctx)
	if err != nil {
		return err
	}
	records, err := c.listTXT(ctx, zoneID, c.fqdn(name))
	if err != nil {
		return err
	}
	for _, rec := range records {
		if value != "" && rec.Content != value {
			continue
		}
		u := fmt.Sprintf("%s/zones/%s/dns_records/%s",
			c.base(), url.PathEscape(zoneID), url.PathEscape(rec.ID))
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
		if err != nil {
			return err
		}
		if err := c.do(req, nil, http.StatusNotFound); err != nil {
			return err
		}
	}
	return nil
}

// cfEnvelope is the Cloudflare API v4 response wrapper.
type cfEnvelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

// detail renders the envelope errors, falling back to the truncated raw body.
func (e *cfEnvelope) detail(body []byte) string {
	if len(e.Errors) > 0 {
		parts := make([]string, len(e.Errors))
		for i, cfErr := range e.Errors {
			parts[i] = fmt.Sprintf("%d: %s", cfErr.Code, cfErr.Message)
		}
		return strings.Join(parts, "; ")
	}
	s := strings.TrimSpace(string(body))
	if len(s) > 512 {
		s = s[:512]
	}
	return s
}

// do executes one API request and decodes the success envelope's result into
// out (may be nil). extraOK lists additional acceptable HTTP statuses (e.g.
// 404 on delete). HTTP >= 400 or a success:false envelope is an error.
func (c *CloudflareProvider) do(req *http.Request, out any, extraOK ...int) error {
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if req.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	for _, ok := range extraOK {
		if resp.StatusCode == ok {
			return nil
		}
	}
	var env cfEnvelope
	_ = json.Unmarshal(body, &env)
	if resp.StatusCode >= 400 || !env.Success {
		return fmt.Errorf("cloudflare %s %s: status %d: %s",
			req.Method, req.URL.Path, resp.StatusCode, env.detail(body))
	}
	if out != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("cloudflare %s %s: decode result: %w", req.Method, req.URL.Path, err)
		}
	}
	return nil
}
