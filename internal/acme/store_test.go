package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestCert generates a self-signed certificate for domains with the
// given remaining validity and persists it via store.SaveCert.
func writeTestCert(t *testing.T, store Store, domains []string, validFor time.Duration) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domains[0]},
		DNSNames:     domains,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(validFor),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	chainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM, err := marshalKeyPKCS8(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCert(chainPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
}

func TestAccountKeyPersistence(t *testing.T) {
	store := Store{Dir: t.TempDir()}

	k1, err := store.AccountKey()
	if err != nil {
		t.Fatalf("AccountKey: %v", err)
	}
	k2, err := store.AccountKey()
	if err != nil {
		t.Fatalf("AccountKey reload: %v", err)
	}
	if !k1.Equal(k2) {
		t.Error("reloaded account key differs — account identity would change across restarts")
	}

	info, err := os.Stat(store.accountKeyPath())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("account.key mode = %o, want 600", perm)
	}
}

// TestLoadCertPickFromDiskVsReissue: the boot/renewal decision matrix.
func TestLoadCertPickFromDiskVsReissue(t *testing.T) {
	domains := []string{"cc-api.adverserial.ai", "cc-chat.adverserial.ai"}
	now := time.Now()

	t.Run("valid cert is picked from disk", func(t *testing.T) {
		store := Store{Dir: t.TempDir()}
		writeTestCert(t, store, domains, 90*24*time.Hour)
		cert, ok := store.LoadCert(domains, DefaultRenewBefore, now)
		if !ok {
			t.Fatal("90-day cert should be picked from disk")
		}
		if cert.Leaf == nil {
			t.Error("Leaf must be populated")
		}
	})

	t.Run("expiring cert triggers reissue", func(t *testing.T) {
		store := Store{Dir: t.TempDir()}
		writeTestCert(t, store, domains, 10*24*time.Hour) // < 30d threshold
		if _, ok := store.LoadCert(domains, DefaultRenewBefore, now); ok {
			t.Fatal("cert with 10 days left should be renewed")
		}
	})

	t.Run("expired cert triggers reissue", func(t *testing.T) {
		store := Store{Dir: t.TempDir()}
		writeTestCert(t, store, domains, 30*time.Minute)
		if _, ok := store.LoadCert(domains, DefaultRenewBefore, now); ok {
			t.Fatal("nearly-expired cert should be renewed")
		}
	})

	t.Run("domain mismatch triggers reissue", func(t *testing.T) {
		store := Store{Dir: t.TempDir()}
		writeTestCert(t, store, []string{"cc-api.adverserial.ai"}, 90*24*time.Hour)
		if _, ok := store.LoadCert(domains, DefaultRenewBefore, now); ok {
			t.Fatal("cert not covering all domains should be reissued")
		}
	})

	t.Run("missing files trigger reissue", func(t *testing.T) {
		store := Store{Dir: filepath.Join(t.TempDir(), "nonexistent")}
		if _, ok := store.LoadCert(domains, DefaultRenewBefore, now); ok {
			t.Fatal("missing files should trigger issuance")
		}
	})

	t.Run("corrupt key triggers reissue", func(t *testing.T) {
		store := Store{Dir: t.TempDir()}
		writeTestCert(t, store, domains, 90*24*time.Hour)
		if err := os.WriteFile(store.keyPath(), []byte("garbage"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok := store.LoadCert(domains, DefaultRenewBefore, now); ok {
			t.Fatal("corrupt key should trigger reissue")
		}
	})
}
