package attestation

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// GPUBundleCache loads the NVIDIA NRAS EAT bundle written by the collector
// sidecar (collector/gpu_evidence_collector.py) and hands it to evidence
// building. NRAS round-trips take seconds, so the proxy never collects at
// request time: the file is re-stat'ed at most once per ReloadInterval and
// re-read only when its mtime changed.
type GPUBundleCache struct {
	Path string

	// ReloadInterval bounds stat() frequency (default 30s); StaleAfter is the
	// staleness threshold measured from the bundle's generated_at (default
	// 10min). Now is a test hook; production uses time.Now.
	ReloadInterval time.Duration
	StaleAfter     time.Duration
	Now            func() time.Time

	mu            sync.Mutex
	lastCheck     time.Time
	modTime       time.Time
	bundle        map[string]any // nil = absent/invalid
	generatedAt   time.Time
	generatedAtOK bool
}

// GPUEvidence is the per-request snapshot merged into the evidence object.
type GPUEvidence struct {
	Bundle  map[string]any // nil → gpu_evidence: null
	FreshAt string         // bundle generated_at, echoed verbatim
	Stale   bool           // bundle older than StaleAfter
}

// Snapshot returns the current bundle state, refreshing from disk at most
// once per ReloadInterval.
func (c *GPUBundleCache) Snapshot() GPUEvidence {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if now.Sub(c.lastCheck) >= c.reloadInterval() {
		c.lastCheck = now
		c.reload()
	}
	return c.evidence(now)
}

func (c *GPUBundleCache) reload() {
	fi, err := os.Stat(c.Path)
	if err != nil {
		c.bundle = nil
		c.modTime = time.Time{}
		return
	}
	if fi.ModTime().Equal(c.modTime) {
		return // unchanged since last load
	}
	data, err := os.ReadFile(c.Path)
	if err != nil {
		c.bundle = nil
		return
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		c.bundle = nil // malformed bundle: treat as absent, never serve garbage
		return
	}
	c.bundle = parsed
	c.modTime = fi.ModTime()
	c.generatedAt, c.generatedAtOK = parseGeneratedAt(parsed)
}

func (c *GPUBundleCache) evidence(now time.Time) GPUEvidence {
	if c.bundle == nil {
		return GPUEvidence{}
	}
	ev := GPUEvidence{Bundle: c.bundle}
	if ts, ok := c.bundle["generated_at"].(string); ok {
		ev.FreshAt = ts
	}
	// A bundle whose freshness cannot be established is marked stale — the
	// client must never mistake unverifiable GPU evidence for fresh evidence.
	if !c.generatedAtOK || now.Sub(c.generatedAt) > c.staleAfter() {
		ev.Stale = true
	}
	return ev
}

func (c *GPUBundleCache) reloadInterval() time.Duration {
	if c.ReloadInterval > 0 {
		return c.ReloadInterval
	}
	return 30 * time.Second
}

func (c *GPUBundleCache) staleAfter() time.Duration {
	if c.StaleAfter > 0 {
		return c.StaleAfter
	}
	return 10 * time.Minute
}

func (c *GPUBundleCache) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func parseGeneratedAt(bundle map[string]any) (time.Time, bool) {
	ts, ok := bundle["generated_at"].(string)
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
