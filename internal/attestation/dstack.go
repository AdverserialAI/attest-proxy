package attestation

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Quote is a TDX attestation quote plus the dstack event log (RTMR replay
// material). Both must be published: a quote signature alone does not let a
// verifier reconstruct the measured workload.
type Quote struct {
	QuoteHex string
	EventLog any
}

// QuoteSource produces a TDX quote binding the given 64-byte report_data.
// The production implementation is DstackClient; tests and DEV_MODE use
// DevQuoteSource. The interface keeps the transport swappable (e.g. a future
// TEE-guest-api implementation or a KMS-backed variant).
type QuoteSource interface {
	Quote(ctx context.Context, reportData [64]byte) (Quote, error)
}

// DstackClient calls the dstack guest agent over its unix socket using the
// prpc-style HTTP API (endpoints /Info, /Quote, /GetKey).
type DstackClient struct {
	http *http.Client
}

// NewDstackClient returns a QuoteSource talking to the dstack guest agent at
// socketPath (default /var/run/dstack.sock).
func NewDstackClient(socketPath string) *DstackClient {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	return &DstackClient{http: &http.Client{Transport: tr, Timeout: 15 * time.Second}}
}

// quoteRequest is the dstack /Quote request body.
type quoteRequest struct {
	ReportData string `json:"report_data"` // hex-encoded, up to 64 bytes
}

// quoteResponse is the dstack /Quote response body.
type quoteResponse struct {
	Quote    string          `json:"quote"`
	EventLog json.RawMessage `json:"event_log"`
	Error    string          `json:"error"`
}

// Quote implements QuoteSource: POST http://dstack/GetQuote with the hex-encoded
// report_data, per the dstack guest-agent frozen v0 API (also served at
// /v0/GetQuote; /Quote is the retired prpc path and returns
// "Service not found" on dstack 0.5.x).
func (c *DstackClient) Quote(ctx context.Context, reportData [64]byte) (Quote, error) {
	body, err := json.Marshal(quoteRequest{ReportData: hex.EncodeToString(reportData[:])})
	if err != nil {
		return Quote{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://dstack/GetQuote", bytes.NewReader(body))
	if err != nil {
		return Quote{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return Quote{}, fmt.Errorf("dstack quote request: %w", err)
	}
	defer resp.Body.Close()

	var qr quoteResponse
	if err := json.NewDecoder(resp.Body).Decode(&qr); err != nil {
		return Quote{}, fmt.Errorf("dstack quote response: %w", err)
	}
	if qr.Error != "" {
		return Quote{}, fmt.Errorf("dstack quote error: %s", qr.Error)
	}
	if resp.StatusCode != http.StatusOK {
		return Quote{}, fmt.Errorf("dstack quote status %d", resp.StatusCode)
	}
	if qr.Quote == "" {
		return Quote{}, fmt.Errorf("dstack returned an empty quote")
	}
	if len(qr.EventLog) == 0 || string(qr.EventLog) == "null" {
		return Quote{}, fmt.Errorf("dstack returned no event log")
	}
	var eventLog any
	if err := json.Unmarshal(qr.EventLog, &eventLog); err != nil {
		return Quote{}, fmt.Errorf("dstack returned an invalid event log: %w", err)
	}
	return Quote{QuoteHex: qr.Quote, EventLog: eventLog}, nil
}

// DevQuoteSource synthesizes a deterministic-binding, non-hardware quote for
// DEV_MODE. The output embeds the report_data verbatim so freshness/binding
// tests behave like production, but it proves nothing about a TEE and is
// always accompanied by "dev": true in the evidence.
type DevQuoteSource struct{}

// Quote implements QuoteSource.
func (DevQuoteSource) Quote(_ context.Context, reportData [64]byte) (Quote, error) {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return Quote{}, err
	}
	buf := make([]byte, 0, 8+64+16)
	buf = append(buf, []byte("DEVQTE00")...)
	buf = append(buf, reportData[:]...)
	buf = append(buf, entropy[:]...)
	return Quote{
		QuoteHex: hex.EncodeToString(buf),
		EventLog: "dev-mode-synthetic-event-log",
	}, nil
}
