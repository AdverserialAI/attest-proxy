package attestation

import "testing"

// The attestation epoch must not rotate on routine GPU evidence refreshes:
// fresh_at changes on every collector round, while present/stale flip only on
// real freshness transitions. Clients hold cached proofs across requests; a
// rotating epoch breaks every WP-7 receipt they verify.
func TestAttestationStateDigestIgnoresGPURefreshTimestamp(t *testing.T) {
	w := Workload{PolicyID: "p", ModelID: "m", ProxyVersion: "0", ComposeDigest: "c", ModelDigest: "d"}
	base := GPUEvidence{Bundle: map[string]any{"nonce": "a"}, FreshAt: "2026-10-07T00:00:00Z", Stale: false}
	refreshed := GPUEvidence{Bundle: map[string]any{"nonce": "a"}, FreshAt: "2026-10-07T00:05:00Z", Stale: false}

	d1, err := AttestationStateDigest(w, "rt", "spki", "kid", "ehbp", base)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := AttestationStateDigest(w, "rt", "spki", "kid", "ehbp", refreshed)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Errorf("digest rotated on a routine GPU refresh: %s != %s", d1, d2)
	}

	stale := refreshed
	stale.Stale = true
	d3, err := AttestationStateDigest(w, "rt", "spki", "kid", "ehbp", stale)
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d3 {
		t.Error("digest must rotate when GPU evidence goes stale")
	}

	absent := GPUEvidence{}
	d4, err := AttestationStateDigest(w, "rt", "spki", "kid", "ehbp", absent)
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d4 {
		t.Error("digest must rotate when GPU evidence disappears")
	}
}
