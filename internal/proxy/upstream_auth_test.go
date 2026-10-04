package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestUpstreamBearerReplacesClientAuthorization(t *testing.T) {
	var got string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	front := httptest.NewServer(New(u, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, "sealed-loopback"))
	defer front.Close()
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer customer-entitlement")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got != "Bearer sealed-loopback" {
		t.Errorf("upstream authorization=%q", got)
	}
}
