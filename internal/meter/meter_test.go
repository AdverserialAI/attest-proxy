package meter

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/adverserial/attest-proxy/internal/billing"
)

type poster struct {
	tokens []string
	err    error
}

func (p *poster) PostMeter(_ context.Context, token string) error {
	p.tokens = append(p.tokens, token)
	return p.err
}
func TestOutboxDurableRetry(t *testing.T) {
	s, err := NewTestSigner()
	if err != nil {
		t.Fatal(err)
	}
	token, claims, err := Build(s, "r", "q", "lordx64/cyberglm", "issuer", "aud", 2, 1, 1, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	p := &poster{}
	o := Outbox{Dir: filepath.Join(t.TempDir(), "outbox"), Poster: p}
	if err := o.Enqueue(token, claims); err != nil {
		t.Fatal(err)
	}
	if err := o.Enqueue(token, claims); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(o.Dir); len(entries) != 1 {
		t.Fatalf("records=%d", len(entries))
	}
	if err := o.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(p.tokens) != 1 {
		t.Fatalf("posts=%d", len(p.tokens))
	}
	if entries, _ := os.ReadDir(o.Dir); len(entries) != 0 {
		t.Fatalf("records after flush=%d", len(entries))
	}
}

// rc.21: a permanently-rejected record (billing 4xx) must be quarantined to
// dead/ and the flush must continue — the 2026-10-09 incident had one expired
// record jam every later settlement head-of-line.
type statusPoster struct {
	seen   []string
	status int
}

func (p *statusPoster) PostMeter(_ context.Context, token string) error {
	p.seen = append(p.seen, token)
	if p.status == 0 {
		return nil
	}
	return &billing.StatusError{Status: p.status}
}

func TestOutboxDeadLettersPermanentRejections(t *testing.T) {
	s, err := NewTestSigner()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "outbox")
	p := &statusPoster{status: 401}
	o := Outbox{Dir: dir, Poster: p}
	for _, id := range []string{"r1", "r2", "r3"} {
		token, claims, err := Build(s, id, "q-"+id, "lordx64/cyberglm", "issuer", "aud", 1, 0, 1, time.Unix(1, 0))
		if err != nil {
			t.Fatal(err)
		}
		if err := o.Enqueue(token, claims); err != nil {
			t.Fatal(err)
		}
	}
	if err := o.Flush(context.Background()); err != nil {
		t.Fatalf("permanent rejections must not fail the flush: %v", err)
	}
	if len(p.seen) != 3 {
		t.Fatalf("poster saw %d records, want all 3 (no head-of-line abort)", len(p.seen))
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 || entries[0].Name() != "dead" {
		t.Fatalf("outbox should hold only the dead/ dir, got %v", entries)
	}
	dead, _ := os.ReadDir(filepath.Join(dir, "dead"))
	if len(dead) != 3 {
		t.Fatalf("dead-lettered records = %d, want 3", len(dead))
	}
}

func TestOutboxRetriesTransientFailuresWithoutDeadLettering(t *testing.T) {
	s, err := NewTestSigner()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "outbox")
	p := &statusPoster{status: 503}
	o := Outbox{Dir: dir, Poster: p}
	token, claims, err := Build(s, "r1", "q-r1", "lordx64/cyberglm", "issuer", "aud", 1, 0, 1, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Enqueue(token, claims); err != nil {
		t.Fatal(err)
	}
	if err := o.Flush(context.Background()); err == nil {
		t.Fatal("transient failure must abort the flush for a later retry")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("record must stay queued for retry, got %v", entries)
	}
}
