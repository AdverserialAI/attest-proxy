package enclavekeys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func keyDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "keys")
}

func TestFirstBootGeneratesAndLaterBootsReload(t *testing.T) {
	dir := keyDir(t)
	first, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("first boot: %v", err)
	}
	if first.Receipt.Curve != elliptic.P256() || len(first.Meter) != ed25519.PrivateKeySize {
		t.Fatal("generated keys have the wrong type")
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("key directory mode = %v (%v), want 0700", info.Mode().Perm(), err)
	}
	for _, name := range []string{receiptKeyFile, meterKeyFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %04o, want 0600", name, info.Mode().Perm())
		}
		raw, _ := os.ReadFile(filepath.Join(dir, name))
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
			t.Errorf("%s is not a single PKCS#8 PEM block", name)
		} else if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			t.Errorf("%s does not parse as PKCS#8: %v", name, err)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Errorf("key directory holds %d entries, want 2 (no temp files left behind)", len(entries))
	}

	second, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("second boot: %v", err)
	}
	if !first.Receipt.Equal(second.Receipt) || !first.Meter.Equal(second.Meter) {
		t.Fatal("keys changed across boots")
	}

	other, err := LoadOrCreate(keyDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if first.Receipt.Equal(other.Receipt) || first.Meter.Equal(other.Meter) {
		t.Fatal("two enclaves generated the same key")
	}
}

func TestMissingKeyIsGeneratedWithoutTouchingTheOther(t *testing.T) {
	dir := keyDir(t)
	first, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, meterKeyFile)); err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Receipt.Equal(second.Receipt) {
		t.Error("existing receipt key was replaced")
	}
	if first.Meter.Equal(second.Meter) {
		t.Error("removed meter key was not regenerated")
	}
}

// TestFailsClosedWithoutRegenerating covers every untrustworthy on-disk
// state: the proxy must stop, and the offending file must be left untouched.
func TestFailsClosedWithoutRegenerating(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384DER, _ := x509.MarshalPKCS8PrivateKey(p384)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	edDER, _ := x509.MarshalPKCS8PrivateKey(edKey)
	pemOf := func(typ string, der []byte) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	}

	cases := []struct {
		name    string
		file    string
		content []byte
		mode    os.FileMode
	}{
		{"group-readable key", receiptKeyFile, nil, 0o640},
		{"world-readable key", meterKeyFile, nil, 0o604},
		{"empty file", receiptKeyFile, []byte{}, 0o600},
		{"garbage", receiptKeyFile, []byte("not a key\n"), 0o600},
		{"corrupt DER", meterKeyFile, pemOf("PRIVATE KEY", []byte{0x30, 0x03, 0x01, 0x02, 0x03}), 0o600},
		{"wrong PEM type", receiptKeyFile, pemOf("EC PRIVATE KEY", edDER), 0o600},
		{"trailing data", meterKeyFile, append(pemOf("PRIVATE KEY", edDER), []byte("extra")...), 0o600},
		{"RSA in receipt slot", receiptKeyFile, pemOf("PRIVATE KEY", rsaDER), 0o600},
		{"P-384 in receipt slot", receiptKeyFile, pemOf("PRIVATE KEY", p384DER), 0o600},
		{"Ed25519 in receipt slot", receiptKeyFile, pemOf("PRIVATE KEY", edDER), 0o600},
		{"RSA in meter slot", meterKeyFile, pemOf("PRIVATE KEY", rsaDER), 0o600},
		{"oversized file", meterKeyFile, []byte(strings.Repeat("A", maxKeyFileBytes+1)), 0o600},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := keyDir(t)
			if _, err := LoadOrCreate(dir); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, tc.file)
			if tc.content != nil {
				if err := os.WriteFile(path, tc.content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(path)
			if _, err := LoadOrCreate(dir); err == nil {
				t.Fatal("untrustworthy key file accepted")
			}
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Fatal("untrustworthy key file was overwritten")
			}
		})
	}
}

func TestRefusesSymlinkedKeyAndLooseDirectory(t *testing.T) {
	dir := keyDir(t)
	if _, err := LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, receiptKeyFile)
	moved := filepath.Join(t.TempDir(), "elsewhere.pem")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir); err == nil {
		t.Error("symlinked key file accepted")
	}

	loose := keyDir(t)
	if err := os.MkdirAll(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(loose); err == nil {
		t.Error("group/world-accessible key directory accepted")
	}
	if entries, _ := os.ReadDir(loose); len(entries) != 0 {
		t.Error("keys were written into a refused directory")
	}

	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(file); err == nil {
		t.Error("regular file accepted as key directory")
	}
	if _, err := LoadOrCreate("relative/keys"); err == nil {
		t.Error("relative key directory accepted")
	}
}

func TestErrorsNeverContainKeyMaterial(t *testing.T) {
	dir := keyDir(t)
	if _, err := LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, meterKeyFile)
	raw, _ := os.ReadFile(path)
	body := strings.Split(string(raw), "\n")[1] // base64 line of the PEM body
	if err := os.WriteFile(path, []byte("-----BEGIN PRIVATE KEY-----\n"+body[:len(body)-4]+"\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadOrCreate(dir)
	if err == nil {
		t.Fatal("truncated key accepted")
	}
	if strings.Contains(err.Error(), body[:16]) {
		t.Fatalf("error leaks key bytes: %v", err)
	}
}
