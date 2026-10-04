package meter

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
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
