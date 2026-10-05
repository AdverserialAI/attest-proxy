package billing

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// meterTLSBundle is supplied only through the CVM's sealed environment. Its
// fields are PEM strings; the bundle itself is base64url-encoded JSON so it
// remains single-line and safe for deployment tools.
type meterTLSBundle struct {
	ClientCertPEM string `json:"client_cert_pem"`
	ClientKeyPEM  string `json:"client_key_pem"`
	IngressCAPEM  string `json:"ingress_ca_pem"`
}

// MaterializeMeterTLSBundle validates then atomically writes a sealed mTLS
// bundle to dir. The private key never appears in logs or the rendered compose.
// dir must be a private persistent volume owned by the proxy runtime user.
func MaterializeMeterTLSBundle(encoded, dir string) error {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("decode base64url bundle: %w", err)
	}
	var bundle meterTLSBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return fmt.Errorf("decode JSON bundle: %w", err)
	}
	if bundle.ClientCertPEM == "" || bundle.ClientKeyPEM == "" || bundle.IngressCAPEM == "" {
		return fmt.Errorf("bundle must include client_cert_pem, client_key_pem, and ingress_ca_pem")
	}
	if _, err := tls.X509KeyPair([]byte(bundle.ClientCertPEM), []byte(bundle.ClientKeyPEM)); err != nil {
		return fmt.Errorf("invalid client certificate/key: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(bundle.IngressCAPEM)) {
		return fmt.Errorf("invalid ingress CA certificate")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create meter TLS directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("protect meter TLS directory: %w", err)
	}
	for _, item := range []struct{ name, data string }{
		{"client.crt", bundle.ClientCertPEM},
		{"client.key", bundle.ClientKeyPEM},
		{"ingress-ca.crt", bundle.IngressCAPEM},
	} {
		if err := writePrivateFile(filepath.Join(dir, item.name), []byte(item.data)); err != nil {
			return err
		}
	}
	return nil
}

func writePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".sealed-")
	if err != nil {
		return fmt.Errorf("create sealed material: %w", err)
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return fmt.Errorf("protect sealed material: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write sealed material: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync sealed material: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close sealed material: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("activate sealed material: %w", err)
	}
	return nil
}
