package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// gandiDefaultBaseURL is the Gandi LiveDNS REST API root.
const gandiDefaultBaseURL = "https://api.gandi.net"

// ChallengeName computes the relative _acme-challenge TXT record name for
// domain inside zone: cc-api.adverserial.ai in zone adverserial.ai →
// "_acme-challenge.cc-api". The apex maps to "_acme-challenge". Matching is
// case-insensitive and ignores a trailing dot.
func ChallengeName(domain, zone string) (string, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	if domain == "" || zone == "" {
		return "", fmt.Errorf("acme: empty domain or zone")
	}
	if domain == zone {
		return "_acme-challenge", nil
	}
	suffix := "." + zone
	if !strings.HasSuffix(domain, suffix) {
		return "", fmt.Errorf("acme: domain %q is not inside zone %q", domain, zone)
	}
	return "_acme-challenge." + strings.TrimSuffix(domain, suffix), nil
}

// GandiProvider implements DNSProvider against the Gandi LiveDNS REST API
// using a personal access token.
type GandiProvider struct {
	PAT  string // Gandi personal access token
	Zone string // e.g. adverserial.ai

	// BaseURL and HTTP are test hooks; defaults are the production API and a
	// 30s-timeout client.
	BaseURL string
	HTTP    *http.Client
}

func (g *GandiProvider) base() string {
	if g.BaseURL != "" {
		return strings.TrimRight(g.BaseURL, "/")
	}
	return gandiDefaultBaseURL
}

func (g *GandiProvider) httpClient() *http.Client {
	if g.HTTP != nil {
		return g.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// recordURL builds /v5/livedns/domains/{zone}/records/{name}/TXT.
func (g *GandiProvider) recordURL(name string) string {
	return fmt.Sprintf("%s/v5/livedns/domains/%s/records/%s/TXT",
		g.base(), url.PathEscape(g.Zone), url.PathEscape(name))
}

// SetTXT creates or replaces the TXT rrset (Gandi PUT semantics) with a
// short TTL so challenges converge and disappear quickly.
func (g *GandiProvider) SetTXT(ctx context.Context, name, value string) error {
	body, err := json.Marshal(map[string]any{
		"rrset_values": []string{value},
		"rrset_ttl":    300,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, g.recordURL(name),
		strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	return g.do(req, http.StatusCreated, http.StatusOK)
}

// DeleteTXT removes the TXT rrset. A 404 (already gone) is success.
func (g *GandiProvider) DeleteTXT(ctx context.Context, name, value string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, g.recordURL(name), nil)
	if err != nil {
		return err
	}
	return g.do(req, http.StatusNoContent, http.StatusOK, http.StatusNotFound)
}

func (g *GandiProvider) do(req *http.Request, okStatuses ...int) error {
	req.Header.Set("Authorization", "Bearer "+g.PAT)
	if req.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("gandi livedns: %w", err)
	}
	defer resp.Body.Close()
	for _, ok := range okStatuses {
		if resp.StatusCode == ok {
			return nil
		}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("gandi livedns %s %s: status %d: %s",
		req.Method, req.URL.Path, resp.StatusCode, strings.TrimSpace(string(body)))
}
