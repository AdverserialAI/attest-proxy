package acme

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestChallengeName(t *testing.T) {
	cases := []struct {
		domain, zone, want string
	}{
		{"cc-api.adverserial.ai", "adverserial.ai", "_acme-challenge.cc-api"},
		{"cc-chat.adverserial.ai", "adverserial.ai", "_acme-challenge.cc-chat"},
		{"adverserial.ai", "adverserial.ai", "_acme-challenge"},
		{"a.b.adverserial.ai", "adverserial.ai", "_acme-challenge.a.b"},
		{"CC-API.Adverserial.AI.", "Adverserial.AI.", "_acme-challenge.cc-api"}, // case + trailing dot
	}
	for _, c := range cases {
		got, err := ChallengeName(c.domain, c.zone)
		if err != nil {
			t.Errorf("ChallengeName(%q, %q): %v", c.domain, c.zone, err)
			continue
		}
		if got != c.want {
			t.Errorf("ChallengeName(%q, %q) = %q, want %q", c.domain, c.zone, got, c.want)
		}
	}
}

func TestChallengeNameZoneMismatch(t *testing.T) {
	for _, pair := range [][2]string{
		{"cc-api.example.com", "adverserial.ai"},
		{"notadverserial.ai", "adverserial.ai"}, // suffix without label boundary
		{"", "adverserial.ai"},
	} {
		if _, err := ChallengeName(pair[0], pair[1]); err == nil {
			t.Errorf("ChallengeName(%q, %q) should fail", pair[0], pair[1])
		}
	}
}

// TestGandiSetTXT checks the exact request shape against a stub LiveDNS.
func TestGandiSetTXT(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotCT string
	var gotBody map[string]any
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("body decode: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	}))
	defer stub.Close()

	p := &GandiProvider{PAT: "test-pat", Zone: "adverserial.ai", BaseURL: stub.URL}
	err := p.SetTXT(context.Background(), "_acme-challenge.cc-api", "txt-value-123")
	if err != nil {
		t.Fatalf("SetTXT: %v", err)
	}

	if gotMethod != http.MethodPut {
		t.Errorf("method = %s, want PUT", gotMethod)
	}
	wantPath := "/v5/livedns/domains/adverserial.ai/records/_acme-challenge.cc-api/TXT"
	if gotPath != wantPath {
		t.Errorf("path = %s, want %s", gotPath, wantPath)
	}
	if gotAuth != "Bearer test-pat" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q", gotCT)
	}
	values, ok := gotBody["rrset_values"].([]any)
	if !ok || len(values) != 1 || values[0] != "txt-value-123" {
		t.Errorf("rrset_values = %v", gotBody["rrset_values"])
	}
	if gotBody["rrset_ttl"] != float64(300) {
		t.Errorf("rrset_ttl = %v", gotBody["rrset_ttl"])
	}
}

// TestGandiDeleteTXT: DELETE to the same record URL; 204 and 404 are success.
func TestGandiDeleteTXT(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusNotFound} {
		var gotMethod, gotPath, gotAuth string
		stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotMethod, gotPath = r.Method, r.URL.Path
			gotAuth = r.Header.Get("Authorization")
			w.WriteHeader(status)
		}))
		p := &GandiProvider{PAT: "test-pat", Zone: "adverserial.ai", BaseURL: stub.URL}
		err := p.DeleteTXT(context.Background(), "_acme-challenge.cc-api", "txt-value-123")
		stub.Close()
		if err != nil {
			t.Fatalf("DeleteTXT (status %d): %v", status, err)
		}
		if gotMethod != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", gotMethod)
		}
		if gotPath != "/v5/livedns/domains/adverserial.ai/records/_acme-challenge.cc-api/TXT" {
			t.Errorf("path = %s", gotPath)
		}
		if gotAuth != "Bearer test-pat" {
			t.Errorf("Authorization = %q", gotAuth)
		}
	}
}

func TestGandiErrorPropagates(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"invalid token"}`))
	}))
	defer stub.Close()
	p := &GandiProvider{PAT: "bad", Zone: "adverserial.ai", BaseURL: stub.URL}
	if err := p.SetTXT(context.Background(), "_acme-challenge.x", "v"); err == nil {
		t.Fatal("expected error on 401")
	}
}
