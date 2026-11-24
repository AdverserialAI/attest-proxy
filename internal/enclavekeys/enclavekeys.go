// Package enclavekeys generates and persists the signing keys that must never
// exist outside the confidential VM: the P-256 receipt key and the Ed25519
// meter key. They are created from crypto/rand on first boot and reloaded on
// later boots from a directory on the CVM's encrypted state volume.
//
// The package fails closed. A key file that exists but cannot be trusted
// (wrong type, loose permissions, unparsable) stops the proxy; it is never
// replaced, because silently minting a new identity would hide tampering and
// invalidate every pin of the previous public key.
package enclavekeys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	// Origin is the keys_origin value published for keys from this package.
	Origin = "enclave-generated"

	receiptKeyFile = "receipt-p256.pem"
	meterKeyFile   = "meter-ed25519.pem"
	pemType        = "PRIVATE KEY" // PKCS#8

	// A PKCS#8 P-256 or Ed25519 key is under 300 bytes of PEM.
	maxKeyFileBytes = 4 << 10
)

// Keys are the persistent enclave signing keys.
type Keys struct {
	Receipt *ecdsa.PrivateKey
	Meter   ed25519.PrivateKey
}

// LoadOrCreate returns the keys stored under dir, generating whichever does
// not exist yet. dir is created with mode 0700 when missing.
func LoadOrCreate(dir string) (Keys, error) {
	if !filepath.IsAbs(dir) {
		return Keys{}, fmt.Errorf("enclave key directory must be an absolute path")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Keys{}, fmt.Errorf("create enclave key directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return Keys{}, fmt.Errorf("inspect enclave key directory: %w", err)
	}
	if !info.IsDir() {
		return Keys{}, fmt.Errorf("enclave key directory is not a directory")
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return Keys{}, fmt.Errorf("enclave key directory has mode %04o, want 0700", perm)
	}

	receiptKey, err := loadOrCreate(filepath.Join(dir, receiptKeyFile), func() (any, error) {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	})
	if err != nil {
		return Keys{}, fmt.Errorf("receipt signing key: %w", err)
	}
	receipt, ok := receiptKey.(*ecdsa.PrivateKey)
	if !ok || receipt.Curve != elliptic.P256() {
		return Keys{}, fmt.Errorf("receipt signing key: file does not hold a P-256 key")
	}

	meterKey, err := loadOrCreate(filepath.Join(dir, meterKeyFile), func() (any, error) {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		return private, err
	})
	if err != nil {
		return Keys{}, fmt.Errorf("meter signing key: %w", err)
	}
	meter, ok := meterKey.(ed25519.PrivateKey)
	if !ok {
		return Keys{}, fmt.Errorf("meter signing key: file does not hold an Ed25519 key")
	}
	return Keys{Receipt: receipt, Meter: meter}, nil
}

// loadOrCreate loads the PKCS#8 key at path, or generates and stores one when
// the path does not exist. Any other state of the path is an error.
func loadOrCreate(path string, generate func() (any, error)) (any, error) {
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		return load(path, info)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("inspect key file: %w", err)
	}
	key, err := generate()
	if err != nil {
		return nil, fmt.Errorf("generate: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}
	if err := writeAtomic(path, pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der})); err != nil {
		return nil, err
	}
	return key, nil
}

func load(path string, info fs.FileInfo) (any, error) {
	// Lstat: a symlink is refused, so the key can never be redirected to a
	// file outside the key directory.
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("key file is not a regular file")
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("key file has mode %04o, want 0600", perm)
	}
	if info.Size() == 0 || info.Size() > maxKeyFileBytes {
		return nil, fmt.Errorf("key file has an implausible size")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != pemType || len(rest) != 0 {
		return nil, fmt.Errorf("key file is not a single PKCS#8 PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// The parse error can describe key bytes; keep it out of the log.
		return nil, fmt.Errorf("key file does not parse as PKCS#8")
	}
	return key, nil
}

// writeAtomic stores data at path with mode 0600 so that a crash leaves
// either no file or the complete file: temp file in the same directory,
// fsync, link into place, fsync the directory. Linking (not renaming) makes
// the final step refuse an existing path instead of replacing it.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-key-*") // created with mode 0600
	if err != nil {
		return fmt.Errorf("create temporary key file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write key file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set key file mode: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close key file: %w", err)
	}
	if err := os.Link(tmpName, path); err != nil {
		return fmt.Errorf("publish key file: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open key directory: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync key directory: %w", err)
	}
	return nil
}
