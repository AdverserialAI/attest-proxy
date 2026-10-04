package attestation

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

// newTestCache returns a cache whose clock the test controls.
func newTestCache(path string) (*GPUBundleCache, *time.Time) {
	now := testNow
	c := &GPUBundleCache{Path: path, Now: func() time.Time { return now }}
	return c, &now
}

func writeBundle(t *testing.T, path, generatedAt, marker string) {
	t.Helper()
	body := `{"version":1,"generated_at":"` + generatedAt + `","nonce":"ab12",` +
		`"gpus_attested":8,"verdict":"successful","eat_jwts":["eyJ.x.sig0"],` +
		`"source":"nv_attestation_sdk remote NRAS","marker":"` + marker + `"}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestGPUBundleAbsent(t *testing.T) {
	c, _ := newTestCache(filepath.Join(t.TempDir(), "missing.json"))
	ev := c.Snapshot()
	if ev.Bundle != nil || ev.FreshAt != "" || ev.Stale {
		t.Errorf("absent file → %+v, want zero value", ev)
	}

	// And through BuildEvidence: gpu_evidence null, no ref/stale/fresh_at.
	built := BuildEvidence(EvidenceInput{GPU: ev})
	if v, ok := built["gpu_evidence"]; !ok || v != nil {
		t.Errorf("gpu_evidence = %v (present=%v)", v, ok)
	}
	if built["gpu_evidence_ref"] != nil {
		t.Errorf("gpu_evidence_ref = %v", built["gpu_evidence_ref"])
	}
	if _, ok := built["gpu_evidence_stale"]; ok {
		t.Error("stale flag must be absent when no bundle")
	}
	if _, ok := built["gpu_evidence_fresh_at"]; ok {
		t.Error("fresh_at must be absent when no bundle")
	}
}

func TestGPUBundleEmbedded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gpu-evidence.json")
	writeBundle(t, path, testNow.Format(time.RFC3339), "first")

	c, _ := newTestCache(path)
	ev := c.Snapshot()
	if ev.Bundle == nil {
		t.Fatal("bundle not loaded")
	}
	if ev.Bundle["gpus_attested"] != float64(8) || ev.Bundle["marker"] != "first" {
		t.Errorf("bundle = %v", ev.Bundle)
	}
	if ev.FreshAt != testNow.Format(time.RFC3339) {
		t.Errorf("FreshAt = %q", ev.FreshAt)
	}
	if ev.Stale {
		t.Error("fresh bundle marked stale")
	}

	built := BuildEvidence(EvidenceInput{GPU: ev})
	if built["gpu_evidence_ref"] != "nras-eat-bundle" {
		t.Errorf("gpu_evidence_ref = %v", built["gpu_evidence_ref"])
	}
	if built["gpu_evidence_fresh_at"] != testNow.Format(time.RFC3339) {
		t.Errorf("gpu_evidence_fresh_at = %v", built["gpu_evidence_fresh_at"])
	}
	if _, ok := built["gpu_evidence_stale"]; ok {
		t.Error("stale flag present on fresh bundle")
	}
	embedded, ok := built["gpu_evidence"].(map[string]any)
	if !ok || embedded["verdict"] != "successful" {
		t.Errorf("gpu_evidence = %v", built["gpu_evidence"])
	}
}

func TestGPUBundleStale(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gpu-evidence.json")
	writeBundle(t, path, testNow.Add(-20*time.Minute).Format(time.RFC3339), "old")

	c, _ := newTestCache(path)
	ev := c.Snapshot()
	if ev.Bundle == nil {
		t.Fatal("bundle not loaded")
	}
	if !ev.Stale {
		t.Error("20-minute-old bundle must be marked stale")
	}
	built := BuildEvidence(EvidenceInput{GPU: ev})
	if built["gpu_evidence_stale"] != true {
		t.Errorf("gpu_evidence_stale = %v", built["gpu_evidence_stale"])
	}
	// Stale evidence is still served (availability) with its fresh_at marker.
	if built["gpu_evidence"] == nil || built["gpu_evidence_fresh_at"] == nil {
		t.Error("stale bundle must still be embedded with fresh_at")
	}
}

// TestGPUBundleRefreshWithin30s: an updated bundle is picked up after the
// reload interval elapses, and not before.
func TestGPUBundleRefreshWithin30s(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gpu-evidence.json")
	writeBundle(t, path, testNow.Format(time.RFC3339), "first")

	c, now := newTestCache(path)
	if ev := c.Snapshot(); ev.Bundle["marker"] != "first" {
		t.Fatalf("initial marker = %v", ev.Bundle["marker"])
	}

	// Collector writes a new bundle (mtime bumped explicitly).
	writeBundle(t, path, testNow.Add(time.Minute).Format(time.RFC3339), "second")
	later := testNow.Add(time.Minute)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}

	// Within the reload interval: still the cached bundle.
	*now = testNow.Add(10 * time.Second)
	if ev := c.Snapshot(); ev.Bundle["marker"] != "first" {
		t.Errorf("marker changed before reload interval: %v", ev.Bundle["marker"])
	}

	// Past the interval: refreshed.
	*now = testNow.Add(31 * time.Second)
	ev := c.Snapshot()
	if ev.Bundle["marker"] != "second" {
		t.Errorf("marker after interval = %v, want second", ev.Bundle["marker"])
	}
	if ev.Stale {
		t.Error("refreshed bundle must be fresh")
	}
}

func TestGPUBundleMalformedTreatedAsAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gpu-evidence.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, _ := newTestCache(path)
	if ev := c.Snapshot(); ev.Bundle != nil {
		t.Errorf("malformed bundle must be treated as absent, got %v", ev.Bundle)
	}
}

func TestGPUBundleMissingGeneratedAtIsStale(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gpu-evidence.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"eat_jwts":["eyJ.x.y"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c, _ := newTestCache(path)
	if ev := c.Snapshot(); ev.Bundle == nil || !ev.Stale {
		t.Errorf("bundle without generated_at: %+v, want stale", ev)
	}
}
