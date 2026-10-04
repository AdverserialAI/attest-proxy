package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"sync/atomic"
	"time"
)

// GenerateSelfSigned creates an ECDSA P-256 keypair and a self-signed
// certificate entirely in process memory. Nothing touches disk.
//
// TODO(v1): seal/derive the TLS private key via the dstack KMS so the same
// key survives process restarts within the same measured workload, then pin
// rotation to policy.
func GenerateSelfSigned(hostnames []string) (tls.Certificate, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("generate TLS key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("certificate serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hostnames[0], Organization: []string{"Adverserial attest-proxy"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(7 * 24 * time.Hour), // regenerated at every boot until KMS sealing lands
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              append([]string(nil), hostnames...),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("create certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("parse certificate: %w", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
	return cert, leaf, nil
}

// CertHolder serves the active TLS certificate and exposes its leaf for the
// SPKI binding in attestation evidence. Swap replaces the serving certificate
// (ACME renewal) without dropping the listener; every new TLS handshake and
// every attestation response immediately reflects the new certificate.
type CertHolder struct {
	cur atomic.Pointer[certEntry]
}

type certEntry struct {
	cert tls.Certificate
	leaf *x509.Certificate
}

// NewCertHolder wraps cert; cert.Leaf may be nil and is parsed if needed.
func NewCertHolder(cert tls.Certificate) (*CertHolder, error) {
	leaf := cert.Leaf
	if leaf == nil {
		if len(cert.Certificate) == 0 {
			return nil, fmt.Errorf("certificate has no chain")
		}
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse leaf: %w", err)
		}
		leaf = parsed
		cert.Leaf = leaf
	}
	h := &CertHolder{}
	h.cur.Store(&certEntry{cert: cert, leaf: leaf})
	return h, nil
}

// Swap atomically replaces the active certificate.
func (h *CertHolder) Swap(cert tls.Certificate) error {
	fresh, err := NewCertHolder(cert)
	if err != nil {
		return err
	}
	h.cur.Store(fresh.cur.Load())
	return nil
}

// GetCertificate implements tls.Config.GetCertificate.
func (h *CertHolder) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := h.cur.Load().cert
	return &cert, nil
}

// Leaf returns the parsed leaf of the active certificate.
func (h *CertHolder) Leaf() *x509.Certificate {
	return h.cur.Load().leaf
}
