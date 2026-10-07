package attestation

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// serveFakeAgent runs an HTTP server on a unix socket and returns its path.
func serveFakeAgent(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	// macOS has a short Unix-domain socket path limit; Go's long test temp
	// directory names otherwise make an unrelated test name change fail here.
	dir, err := os.MkdirTemp("/tmp", "dstack-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "dstack.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return sock
}

func TestDstackClientQuote(t *testing.T) {
	var gotBody quoteRequest
	sock := serveFakeAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/GetQuote" {
			http.Error(w, "wrong route", http.StatusNotFound)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"quote":"deadbeefcafe","event_log":"el"}`))
	})

	client := NewDstackClient(sock)
	var rd [64]byte
	for i := range rd {
		rd[i] = byte(i)
	}
	q, err := client.Quote(context.Background(), rd)
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	if q.QuoteHex != "deadbeefcafe" {
		t.Errorf("QuoteHex = %q", q.QuoteHex)
	}
	if q.EventLog != "el" {
		t.Errorf("EventLog = %#v", q.EventLog)
	}

	// The request must carry the hex of the full 64-byte report_data.
	raw, err := hex.DecodeString(gotBody.ReportData)
	if err != nil {
		t.Fatalf("report_data not hex: %v", err)
	}
	if len(raw) != 64 || !strings.EqualFold(hex.EncodeToString(rd[:]), gotBody.ReportData) {
		t.Errorf("report_data = %q", gotBody.ReportData)
	}
}

func TestDstackClientErrors(t *testing.T) {
	sock := serveFakeAgent(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"tdx module unavailable"}`))
	})
	client := NewDstackClient(sock)
	if _, err := client.Quote(context.Background(), [64]byte{}); err == nil ||
		!strings.Contains(err.Error(), "tdx module unavailable") {
		t.Fatalf("expected agent error, got %v", err)
	}
}

func TestDstackClientRejectsMissingEventLog(t *testing.T) {
	sock := serveFakeAgent(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"quote":"deadbeefcafe"}`))
	})
	if _, err := NewDstackClient(sock).Quote(context.Background(), [64]byte{}); err == nil ||
		!strings.Contains(err.Error(), "no event log") {
		t.Fatalf("expected missing event log rejection, got %v", err)
	}
}

func TestDevQuoteSource(t *testing.T) {
	var rd [64]byte
	rd[0] = 0x42
	q1, err := DevQuoteSource{}.Quote(context.Background(), rd)
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	raw, err := hex.DecodeString(q1.QuoteHex)
	if err != nil {
		t.Fatalf("quote not hex: %v", err)
	}
	if !strings.HasPrefix(q1.QuoteHex, hex.EncodeToString([]byte("DEVQTE00"))) {
		t.Errorf("quote missing DEVQTE00 magic")
	}
	// report_data is embedded verbatim at offset 8.
	if hex.EncodeToString(raw[8:72]) != hex.EncodeToString(rd[:]) {
		t.Errorf("quote does not embed report_data verbatim")
	}
	q2, err := DevQuoteSource{}.Quote(context.Background(), rd)
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	if q1.QuoteHex == q2.QuoteHex {
		t.Error("dev quotes should carry fresh entropy")
	}
}

func TestReportDataLayout(t *testing.T) {
	rd := ReportData([]byte{1, 2, 3}, []byte{4, 5}, []byte{6})
	// sha256(010203040506) — binding hash in the first 32 bytes.
	if rd[0] == 0 && rd[31] == 0 {
		t.Error("report_data hash half looks zero")
	}
	for i := 32; i < 64; i++ {
		if rd[i] != 0 {
			t.Fatalf("report_data[%d] = %d, want zero padding", i, rd[i])
		}
	}
	// Sensitivity to each input.
	base := rd
	if ReportData([]byte{9, 2, 3}, []byte{4, 5}, []byte{6}) == base {
		t.Error("report_data ignores nonce")
	}
	if ReportData([]byte{1, 2, 3}, []byte{9, 5}, []byte{6}) == base {
		t.Error("report_data ignores TLS SPKI")
	}
	if ReportData([]byte{1, 2, 3}, []byte{4, 5}, []byte{9}) == base {
		t.Error("report_data ignores receipt pubkey")
	}
}
