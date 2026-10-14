package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// Store persists the ACME account key and issued certificates under Dir so
// renewals and account identity survive restarts (mount the dstack volume
// there). Layout:
//
//	<Dir>/account.key       PKCS#8 PEM, mode 0600
//	<Dir>/certificate.crt   full chain PEM, mode 0644
//	<Dir>/certificate.key   PKCS#8 PEM, mode 0600
type Store struct {
	Dir string
}

func (s Store) accountKeyPath() string { return filepath.Join(s.Dir, "account.key") }
func (s Store) certPath() string       { return filepath.Join(s.Dir, "certificate.crt") }
func (s Store) keyPath() string        { return filepath.Join(s.Dir, "certificate.key") }

// AccountKey loads the persisted account key, or generates, persists, and
// returns a fresh P-256 key on first use. Only a missing file triggers
// generation: a transient read error must never silently orphan the account.
func (s Store) AccountKey() (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(s.accountKeyPath())
	if err == nil {
		key, err := parsePrivateKeyPEM(data)
		if err != nil {
			return nil, fmt.Errorf("acme store: load account key: %w", err)
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("acme store: read account key: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pemBytes, err := marshalKeyPKCS8(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("acme store: mkdir: %w", err)
	}
	if err := os.WriteFile(s.accountKeyPath(), pemBytes, 0o600); err != nil {
		return nil, fmt.Errorf("acme store: save account key: %w", err)
	}
	_ = os.Chmod(s.accountKeyPath(), 0o600) // WriteFile keeps pre-existing looser modes
	return key, nil
}

// LoadCert returns the persisted certificate when it exists, covers all of
// domains, and stays valid for at least renewBefore past now. Anything else
// returns ok=false, signaling issuance/renewal.
func (s Store) LoadCert(domains []string, renewBefore time.Duration, now time.Time) (cert tls.Certificate, ok bool) {
	chainPEM, err := os.ReadFile(s.certPath())
	if err != nil {
		return tls.Certificate{}, false
	}
	keyPEM, err := os.ReadFile(s.keyPath())
	if err != nil {
		return tls.Certificate{}, false
	}
	cert, err = tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil || len(cert.Certificate) == 0 {
		return tls.Certificate{}, false
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, false
	}
	cert.Leaf = leaf
	for _, d := range domains {
		if err := leaf.VerifyHostname(d); err != nil {
			return tls.Certificate{}, false
		}
	}
	// Renew when fewer than renewBefore remain, and never serve a not-yet-valid
	// certificate (clock jump during issuance, restored backup).
	if !leaf.NotAfter.After(now.Add(renewBefore)) || now.Before(leaf.NotBefore) {
		return tls.Certificate{}, false
	}
	return cert, true
}

// SaveCert persists an issued chain and its key: atomically (tmp + rename), so
// a crash can never leave a mismatched or truncated pair that spirals into
// re-issuance and CA rate limits.
func (s Store) SaveCert(chainPEM, keyPEM []byte) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := writeAtomic(s.keyPath(), keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(s.certPath(), chainPEM, 0o644); err != nil {
		return err
	}
	if d, err := os.Open(s.Dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".atomic-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return os.Chmod(path, mode) // also tightens any pre-existing looser mode
}

// LoadOrIssue returns a usable certificate for domains: the persisted one
// when still comfortably valid, otherwise a fresh ACME order whose result is
// persisted. Persistence failures are logged but non-fatal — an in-memory
// cert is better than no cert.
func LoadOrIssue(ctx context.Context, store Store, client *Client, domains []string, renewBefore time.Duration, logger *slog.Logger) (tls.Certificate, error) {
	if cert, ok := store.LoadCert(domains, renewBefore, time.Now()); ok {
		return cert, nil
	}
	cert, chainPEM, keyPEM, err := client.Obtain(ctx, domains)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := store.SaveCert(chainPEM, keyPEM); err != nil && logger != nil {
		logger.Error("ACME certificate could not be persisted; renewal state will not survive restart",
			"error", err.Error())
	}
	return cert, nil
}

// parsePrivateKeyPEM accepts PKCS#8 ("PRIVATE KEY") and SEC1
// ("EC PRIVATE KEY") PEM blocks. Only P-256 is accepted: the JWS/thumbprint
// code hardcodes the P-256 size, and anything else would panic at startup.
func parsePrivateKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	var key *ecdsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is %T, want ECDSA", k)
		}
		key = ec
	} else {
		ec, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = ec
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("account key uses %s, want P-256", key.Curve.Params().Name)
	}
	return key, nil
}
