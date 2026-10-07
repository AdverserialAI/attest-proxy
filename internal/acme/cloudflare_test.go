package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// cfStub emulates the Cloudflare v4 endpoints the provider uses: zone
// resolution plus the DNS record collection, backed by an in-memory table.
type cfStub struct {
	records   []cfDNSRecord
	zoneCalls int
	requests  []string // "METHOD /path" log, in order
}

func (s *cfStub) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests = append(s.requests, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			s.zoneCalls++
			if r.URL.Query().Get("name") != "adverserial.ai" || r.URL.Query().Get("status") != "active" {
				t.Errorf("zone query = %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":[{"id":"zone-1","name":"adverserial.ai"}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-1/dns_records":
			q := r.URL.Query()
			if q.Get("type") != "TXT" {
				t.Errorf("record list type = %q", q.Get("type"))
			}
			var out []cfDNSRecord
			for _, rec := range s.records {
				if rec.Name == q.Get("name") {
					out = append(out, rec)
				}
			}
			if out == nil {
				out = []cfDNSRecord{}
			}
			result, _ := json.Marshal(out)
			fmt.Fprintf(w, `{"success":true,"errors":[],"result":%s}`, result)
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-1/dns_records":
			var rec cfDNSRecord
			if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
				t.Errorf("body decode: %v", err)
			}
			rec.ID = "rec-new"
			s.records = append(s.records, rec)
			fmt.Fprintf(w, `{"success":true,"errors":[],"result":{"id":"rec-new","name":%q,"content":%q}}`, rec.Name, rec.Content)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/zones/zone-1/dns_records/"):
			id := strings.TrimPrefix(r.URL.Path, "/zones/zone-1/dns_records/")
			var rec cfDNSRecord
			if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
				t.Errorf("body decode: %v", err)
			}
			rec.ID = id
			replaced := false
			for i := range s.records {
				if s.records[i].ID == id {
					s.records[i] = rec
					replaced = true
				}
			}
			if !replaced {
				t.Errorf("PUT for unknown record %q", id)
			}
			fmt.Fprintf(w, `{"success":true,"errors":[],"result":{"id":%q}}`, id)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/zones/zone-1/dns_records/"):
			id := strings.TrimPrefix(r.URL.Path, "/zones/zone-1/dns_records/")
			kept := s.records[:0]
			for _, rec := range s.records {
				if rec.ID != id {
					kept = append(kept, rec)
				}
			}
			s.records = kept
			fmt.Fprintf(w, `{"success":true,"errors":[],"result":{"id":%q}}`, id)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":7003,"message":"No route for that URI"}],"result":null}`))
		}
	})
}

func newCloudflareStub(t *testing.T, records []cfDNSRecord) (*httptest.Server, *cfStub) {
	t.Helper()
	stub := &cfStub{records: records}
	srv := httptest.NewServer(stub.handler(t))
	t.Cleanup(srv.Close)
	return srv, stub
}

// TestCloudflareSetTXTCreates: no existing record → POST to the collection.
func TestCloudflareSetTXTCreates(t *testing.T) {
	srv, stub := newCloudflareStub(t, nil)
	p := &CloudflareProvider{Token: "test-token", Zone: "adverserial.ai", BaseURL: srv.URL}
	if err := p.SetTXT(context.Background(), "_acme-challenge.cc-api", "txt-value-123"); err != nil {
		t.Fatalf("SetTXT: %v", err)
	}
	if len(stub.records) != 1 {
		t.Fatalf("records = %v", stub.records)
	}
	rec := stub.records[0]
	if rec.Type != "TXT" || rec.Name != "_acme-challenge.cc-api.adverserial.ai" || rec.Content != "txt-value-123" {
		t.Errorf("created record = %+v", rec)
	}
	last := stub.requests[len(stub.requests)-1]
	if last != "POST /zones/zone-1/dns_records" {
		t.Errorf("last request = %q, want POST to the collection", last)
	}
}

// TestCloudflareSetTXTUpdates: an existing record at the name → PUT to its URL.
func TestCloudflareSetTXTUpdates(t *testing.T) {
	existing := []cfDNSRecord{{ID: "rec-9", Type: "TXT", Name: "_acme-challenge.cc-api.adverserial.ai", Content: "stale"}}
	srv, stub := newCloudflareStub(t, existing)
	p := &CloudflareProvider{Token: "test-token", Zone: "adverserial.ai", BaseURL: srv.URL}
	if err := p.SetTXT(context.Background(), "_acme-challenge.cc-api", "txt-value-123"); err != nil {
		t.Fatalf("SetTXT: %v", err)
	}
	if len(stub.records) != 1 || stub.records[0].ID != "rec-9" || stub.records[0].Content != "txt-value-123" {
		t.Errorf("records = %+v", stub.records)
	}
	last := stub.requests[len(stub.requests)-1]
	if last != "PUT /zones/zone-1/dns_records/rec-9" {
		t.Errorf("last request = %q, want PUT to the record", last)
	}
}

// TestCloudflareSetTXTRequestShape checks headers and the exact JSON body.
func TestCloudflareSetTXTRequestShape(t *testing.T) {
	var gotAuth, gotCT string
	var gotBody map[string]any
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/zones":
			_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":[{"id":"zone-1"}]}`))
		case r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":[]}`))
		default:
			gotAuth = r.Header.Get("Authorization")
			gotCT = r.Header.Get("Content-Type")
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Errorf("body decode: %v", err)
			}
			_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"rec-1"}}`))
		}
	}))
	defer stub.Close()

	p := &CloudflareProvider{Token: "test-token", Zone: "adverserial.ai", BaseURL: stub.URL}
	if err := p.SetTXT(context.Background(), "_acme-challenge.cc-api", "txt-value-123"); err != nil {
		t.Fatalf("SetTXT: %v", err)
	}
	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q", gotCT)
	}
	want := map[string]any{"type": "TXT", "name": "_acme-challenge.cc-api.adverserial.ai", "content": "txt-value-123", "ttl": float64(120)}
	for k, v := range want {
		if gotBody[k] != v {
			t.Errorf("body[%s] = %v, want %v", k, gotBody[k], v)
		}
	}
}

// TestCloudflareZoneIDCached: the zone lookup runs once across operations.
func TestCloudflareZoneIDCached(t *testing.T) {
	srv, stub := newCloudflareStub(t, nil)
	p := &CloudflareProvider{Token: "test-token", Zone: "adverserial.ai", BaseURL: srv.URL}
	for _, value := range []string{"v1", "v2"} {
		if err := p.SetTXT(context.Background(), "_acme-challenge.cc-api", value); err != nil {
			t.Fatalf("SetTXT: %v", err)
		}
		if err := p.DeleteTXT(context.Background(), "_acme-challenge.cc-api", value); err != nil {
			t.Fatalf("DeleteTXT: %v", err)
		}
	}
	if stub.zoneCalls != 1 {
		t.Errorf("zone calls = %d, want 1 (cached)", stub.zoneCalls)
	}
}

// TestCloudflareDeleteTXT: only content-matching records are deleted; an
// already-empty name is success.
func TestCloudflareDeleteTXT(t *testing.T) {
	fqdn := "_acme-challenge.cc-api.adverserial.ai"
	records := []cfDNSRecord{
		{ID: "rec-1", Type: "TXT", Name: fqdn, Content: "txt-value-123"},
		{ID: "rec-2", Type: "TXT", Name: fqdn, Content: "other-value"},
	}
	srv, stub := newCloudflareStub(t, records)
	p := &CloudflareProvider{Token: "test-token", Zone: "adverserial.ai", BaseURL: srv.URL}
	if err := p.DeleteTXT(context.Background(), "_acme-challenge.cc-api", "txt-value-123"); err != nil {
		t.Fatalf("DeleteTXT: %v", err)
	}
	if len(stub.records) != 1 || stub.records[0].ID != "rec-2" {
		t.Errorf("records = %+v, want only rec-2 kept", stub.records)
	}
	// Deleting again (name now absent from the value filter) is a no-op success.
	if err := p.DeleteTXT(context.Background(), "_acme-challenge.cc-api", "txt-value-123"); err != nil {
		t.Fatalf("DeleteTXT (idempotent): %v", err)
	}
	// Empty value deletes every record at the name.
	if err := p.DeleteTXT(context.Background(), "_acme-challenge.cc-api", ""); err != nil {
		t.Fatalf("DeleteTXT (all values): %v", err)
	}
	if len(stub.records) != 0 {
		t.Errorf("records = %+v, want empty", stub.records)
	}
}

// TestCloudflareDeleteTXTTolerates404: a record gone before its DELETE is success.
func TestCloudflareDeleteTXTTolerates404(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/zones":
			_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":[{"id":"zone-1"}]}`))
		case r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":[{"id":"rec-1","type":"TXT","name":"_acme-challenge.cc-api.adverserial.ai","content":"v"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":81044,"message":"Record does not exist."}],"result":null}`))
		}
	}))
	defer stub.Close()
	p := &CloudflareProvider{Token: "test-token", Zone: "adverserial.ai", BaseURL: stub.URL}
	if err := p.DeleteTXT(context.Background(), "_acme-challenge.cc-api", "v"); err != nil {
		t.Fatalf("DeleteTXT (404): %v", err)
	}
}

// TestCloudflareErrorPropagates: API errors surface the envelope errors array.
func TestCloudflareErrorPropagates(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}],"result":null}`))
	}))
	defer stub.Close()
	p := &CloudflareProvider{Token: "bad", Zone: "adverserial.ai", BaseURL: stub.URL}
	err := p.SetTXT(context.Background(), "_acme-challenge.x", "v")
	if err == nil {
		t.Fatal("expected error on 403")
	}
	if !strings.Contains(err.Error(), "9109") || !strings.Contains(err.Error(), "Invalid access token") {
		t.Errorf("error = %q, want the envelope errors", err)
	}
}

// TestCloudflareSuccessFalsePropagates: HTTP 200 with success:false is an error.
func TestCloudflareSuccessFalsePropagates(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Auth error"}],"result":null}`))
	}))
	defer stub.Close()
	p := &CloudflareProvider{Token: "bad", Zone: "adverserial.ai", BaseURL: stub.URL}
	if err := p.SetTXT(context.Background(), "_acme-challenge.x", "v"); err == nil {
		t.Fatal("expected error on success:false envelope")
	}
}

// TestCloudflareUnknownZone: an empty zone lookup result is an error.
func TestCloudflareUnknownZone(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":[]}`))
	}))
	defer stub.Close()
	p := &CloudflareProvider{Token: "test-token", Zone: "adverserial.ai", BaseURL: stub.URL}
	if err := p.SetTXT(context.Background(), "_acme-challenge.x", "v"); err == nil {
		t.Fatal("expected error for unknown zone")
	}
}
