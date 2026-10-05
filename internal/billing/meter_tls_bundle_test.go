package billing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testPEM(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "meter.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func TestMaterializeMeterTLSBundle(t *testing.T) {
	cert, key := testPEM(t)
	payload, err := json.Marshal(meterTLSBundle{ClientCertPEM: cert, ClientKeyPEM: key, IngressCAPEM: cert})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "meter")
	if err := MaterializeMeterTLSBundle(base64.RawURLEncoding.EncodeToString(payload), dir); err != nil {
		t.Fatal(err)
	}
	if _, err := tlsLoad(filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")); err != nil {
		t.Fatalf("materialized pair: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "client.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("client key mode = %o, want 600", info.Mode().Perm())
	}
}

func TestMaterializeMeterTLSBundleRejectsInvalid(t *testing.T) {
	if err := MaterializeMeterTLSBundle("not-base64", t.TempDir()); err == nil {
		t.Fatal("invalid bundle accepted")
	}
}

func tlsLoad(cert, key string) (any, error) {
	return tls.LoadX509KeyPair(cert, key)
}
