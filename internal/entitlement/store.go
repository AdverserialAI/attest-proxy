package entitlement

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// UsedStore persists one-use entitlement IDs. Consume intentionally happens
// before upstream inference: a crash may require billing to issue a new
// entitlement, but replay must never run a second inference request.
type UsedStore struct{ Dir string }

// Consume atomically marks claims.ID as used. It returns false on a replay.
// The file contains only opaque metadata and is mode 0600.
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
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		if writeErr != nil {
			return false, writeErr
		}
		return false, closeErr
	}
	return true, nil
}
