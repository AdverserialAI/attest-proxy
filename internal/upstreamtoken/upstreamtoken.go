// Package upstreamtoken reads the bearer credential the proxy presents to the
// model runtime from a file. The credential is generated inside the VM on
// every boot by a one-shot init container and shared with the runtime through
// a volume, so it never appears in configuration and is known to nobody
// outside the VM. The value is never logged or included in an error.
package upstreamtoken

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)

// maxTokenFileBytes covers a 128-character token and one trailing newline.
const maxTokenFileBytes = 129

// statInterval bounds how often the file is stat'ed on the request path.
const statInterval = time.Second

// Source returns the current token and re-reads the file when its mtime or
// size changes, so a regenerated credential is picked up without a restart.
type Source struct {
	path string

	mu        sync.Mutex
	token     string
	modTime   time.Time
	size      int64
	lastCheck time.Time
	now       func() time.Time
}

// Wait blocks until path holds a valid token, for at most timeout.
func Wait(ctx context.Context, path string, timeout time.Duration) (*Source, error) {
	s := &Source{path: path, now: time.Now}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		err := s.reload()
		if err == nil {
			return s, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, fmt.Errorf("UPSTREAM_BEARER_TOKEN_FILE not ready after %s: %w", timeout, err)
		case <-tick.C:
		}
	}
}

// Token returns the most recent valid token. A file that changed but is
// momentarily unreadable or invalid (for example mid-rewrite) leaves the
// previous token in place and is retried on the next check.
func (s *Source) Token() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now := s.now(); now.Sub(s.lastCheck) >= statInterval {
		s.lastCheck = now
		if info, err := os.Stat(s.path); err == nil && (!info.ModTime().Equal(s.modTime) || info.Size() != s.size) {
			_ = s.reloadLocked()
		}
	}
	return s.token
}

func (s *Source) reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reloadLocked()
}

func (s *Source) reloadLocked() error {
	f, err := os.Open(s.path)
	if err != nil {
		// *PathError carries the path and errno only, never file content.
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("token file is not a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxTokenFileBytes+1))
	if err != nil {
		return err
	}
	token := strings.TrimSuffix(string(raw), "\n")
	if len(raw) > maxTokenFileBytes || !tokenPattern.MatchString(token) {
		return fmt.Errorf("token file content does not match the required token format")
	}
	s.token, s.modTime, s.size = token, info.ModTime(), info.Size()
	s.lastCheck = s.now()
	return nil
}
