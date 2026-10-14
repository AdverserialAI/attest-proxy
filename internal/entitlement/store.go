package entitlement

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// UsedStore persists one-use entitlement IDs. Consume intentionally happens
// before upstream inference: a crash may require billing to issue a new
// entitlement, but replay must never run a second inference request.
type UsedStore struct{ Dir string }

// Consume atomically marks claims.ID as used. It returns false on a replay.
// The file contains only opaque metadata and is mode 0600. The write is
// fsync'd (file and directory) so a crash cannot resurrect a consumed jti.
func (s UsedStore) Consume(claims Claims) (bool, error) {
	if s.Dir == "" || claims.ID == "" {
		return false, fmt.Errorf("entitlement replay store is not configured")
	}
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		return false, fmt.Errorf("create entitlement replay store: %w", err)
	}
	path := filepath.Join(s.Dir, IDHash(claims.ID)+".used")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("persist used entitlement: %w", err)
	}
	_, writeErr := fmt.Fprintf(f, "expires=%d\n", claims.Expires)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(path)
		for _, e := range []error{writeErr, syncErr, closeErr} {
			if e != nil {
				return false, e
			}
		}
	}
	if d, err := os.Open(s.Dir); err == nil {
		_ = d.Sync() // flush the new directory entry
		_ = d.Close()
	}
	return true, nil
}

// StartSweeper deletes expired replay markers hourly. Without it the store
// grows forever (every consumed entitlement leaves a permanent file) until
// the volume fills and Consume fails closed for all confidential inference.
// Expired markers can never be needed again: Validate rejects expired tokens
// before Consume is reached.
func (s UsedStore) StartSweeper(stop <-chan struct{}) {
	if s.Dir == "" {
		return
	}
	go func() {
		tick := time.NewTicker(time.Hour)
		defer tick.Stop()
		s.sweep()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				s.sweep()
			}
		}
	}()
}

func (s UsedStore) sweep() {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return
	}
	now := time.Now().Unix()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".used") {
			continue
		}
		path := filepath.Join(s.Dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var expires int64
		if _, err := fmt.Sscanf(string(raw), "expires=%d", &expires); err != nil {
			continue
		}
		if expires > 0 && expires < now {
			_ = os.Remove(path)
		}
	}
}
