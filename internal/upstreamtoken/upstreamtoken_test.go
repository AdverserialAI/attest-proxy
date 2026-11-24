package upstreamtoken

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	tokenA = strings.Repeat("a", 32)
	tokenB = strings.Repeat("B", 43) + "_-"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func TestWaitAcceptsValidTokenWithOneTrailingNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	for _, content := range []string{tokenA, tokenA + "\n", strings.Repeat("x", 128) + "\n"} {
		write(t, path, content)
		s, err := Wait(context.Background(), path, time.Second)
		if err != nil {
			t.Fatalf("valid token refused: %v", err)
		}
		if got := s.Token(); got != strings.TrimSuffix(content, "\n") {
			t.Fatal("token does not match file content")
		}
	}
}

func TestWaitRejectsInvalidContentWithoutLeakingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	for name, content := range map[string]string{
		"empty":            "",
		"too short":        strings.Repeat("a", 31),
		"too long":         strings.Repeat("a", 129),
		"two newlines":     tokenA + "\n\n",
		"crlf":             tokenA + "\r\n",
		"leading space":    " " + tokenA,
		"inner whitespace": tokenA[:16] + " " + tokenA[16:],
		"bad alphabet":     strings.Repeat("a", 31) + "!",
		"two lines":        tokenA + "\n" + tokenA,
	} {
		write(t, path, content)
		_, err := Wait(context.Background(), path, 50*time.Millisecond)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if content != "" && strings.Contains(err.Error(), strings.TrimSpace(content)) {
			t.Errorf("%s: error leaks file content", name)
		}
	}
}

func TestWaitBlocksUntilTheFileAppears(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	go func() {
		time.Sleep(700 * time.Millisecond)
		tmp := path + ".tmp"
		_ = os.WriteFile(tmp, []byte(tokenA+"\n"), 0o440)
		_ = os.Rename(tmp, path)
	}()
	s, err := Wait(context.Background(), path, 10*time.Second)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if s.Token() != tokenA {
		t.Fatal("wrong token after wait")
	}
}

func TestWaitTimesOutAndHonorsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent")
	start := time.Now()
	if _, err := Wait(context.Background(), path, 100*time.Millisecond); err == nil {
		t.Fatal("Wait succeeded without a file")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("Wait overran its timeout")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Wait(ctx, path, time.Minute); err == nil {
		t.Fatal("Wait ignored cancellation")
	}
}

func TestTokenFollowsRegeneratedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	write(t, path, tokenA+"\n")
	s, err := Wait(context.Background(), path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	s.now = func() time.Time { return clock }

	// Regenerated (different size): not observed until the stat interval
	// elapses, then picked up without a restart.
	write(t, path, tokenB+"\n")
	if s.Token() != tokenA {
		t.Fatal("stat was not cached within the interval")
	}
	clock = clock.Add(2 * statInterval)
	if s.Token() != tokenB {
		t.Fatal("regenerated token was not picked up")
	}

	// Same size, different mtime.
	tokenC := strings.Repeat("C", len(tokenB))
	write(t, path, tokenC+"\n")
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(2 * statInterval)
	if s.Token() != tokenC {
		t.Fatal("same-size regenerated token was not picked up")
	}

	// A broken rewrite keeps the last good token and retries later.
	write(t, path, "short")
	clock = clock.Add(2 * statInterval)
	if s.Token() != tokenC {
		t.Fatal("invalid file replaced the last good token")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(2 * statInterval)
	if s.Token() != tokenC {
		t.Fatal("missing file cleared the last good token")
	}
	write(t, path, tokenA)
	clock = clock.Add(2 * statInterval)
	if s.Token() != tokenA {
		t.Fatal("recovered file was not picked up")
	}
}
