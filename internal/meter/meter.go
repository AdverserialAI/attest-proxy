// Package meter signs count-only confidential usage records and keeps a
// durable local outbox until billing acknowledges settlement.
package meter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/adverserial/attest-proxy/internal/billing"
)

type Claims struct {
	Issuer       string `json:"iss"`
	Audience     string `json:"aud"`
	Type         string `json:"typ"`
	Reservation  string `json:"jti"`
	RequestID    string `json:"request_id"`
	Model        string `json:"model"`
	InputTokens  int    `json:"input_tokens"`
	CachedTokens int    `json:"cached_tokens"`
	OutputTokens int    `json:"output_tokens"`
	IssuedAt     int64  `json:"iat"`
	Expires      int64  `json:"exp"`
}

type Signer struct {
	private ed25519.PrivateKey
	kid     string
}

// NewSigner parses the sealed 32-byte base64url seed. A proxy never accepts a
// generated production key: it must be provisioned deliberately so billing
// can pin the matching public JWK before the CVM is started.
func NewSigner(seed string) (*Signer, error) {
	seed = strings.TrimPrefix(seed, "ed25519:")
	b, err := base64.RawURLEncoding.DecodeString(seed)
	if err != nil || len(b) != ed25519.SeedSize {
		return nil, fmt.Errorf("METER_SIGNING_SEED must be a 32-byte base64url Ed25519 seed")
	}
	private := ed25519.NewKeyFromSeed(b)
	sum := sha256.Sum256(private.Public().(ed25519.PublicKey))
	return &Signer{private: private, kid: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

func NewTestSigner() (*Signer, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(private.Public().(ed25519.PublicKey))
	return &Signer{private: private, kid: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

func (s *Signer) PublicJWK() map[string]string {
	return map[string]string{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(s.private.Public().(ed25519.PublicKey)), "kid": s.kid, "use": "sig", "alg": "EdDSA"}
}

func (s *Signer) Sign(claims Claims) (string, error) {
	if claims.Reservation == "" || claims.RequestID == "" || claims.Model == "" || claims.InputTokens < 0 || claims.CachedTokens < 0 || claims.OutputTokens < 0 || claims.CachedTokens > claims.InputTokens {
		return "", fmt.Errorf("invalid meter claims")
	}
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "kid": s.kid, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.private, []byte(input))), nil
}

// Poster posts a compact JWS to billing. The body holds no inference content.
type Poster interface {
	PostMeter(context.Context, string) error
}

// Outbox writes each signed event atomically before any network attempt. A
// caller may Flush after every generation and invoke Flush on startup/timer.
// Failed records remain for retry; successful records are removed only after a
// 2xx billing acknowledgement. Files are named by a hash of the reservation
// and request IDs, never the IDs themselves.
type Outbox struct {
	Dir    string
	Poster Poster
}

func (o Outbox) Enqueue(token string, claims Claims) error {
	if o.Dir == "" {
		return fmt.Errorf("meter outbox is not configured")
	}
	if err := os.MkdirAll(o.Dir, 0700); err != nil {
		return fmt.Errorf("create meter outbox: %w", err)
	}
	sum := sha256.Sum256([]byte(claims.Reservation + "\x00" + claims.RequestID))
	name := base64.RawURLEncoding.EncodeToString(sum[:]) + ".jws"
	path := filepath.Join(o.Dir, name)
	// O_EXCL makes retries of the exact settled record harmless locally.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("write meter outbox: %w", err)
	}
	if _, err = f.WriteString(token + "\n"); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

func (o Outbox) Flush(ctx context.Context) error {
	if o.Poster == nil {
		return fmt.Errorf("meter poster is not configured")
	}
	entries, err := os.ReadDir(o.Dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jws") {
			continue
		}
		path := filepath.Join(o.Dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		token := strings.TrimSpace(string(b))
		if token == "" || len(token) > 16_384 {
			return fmt.Errorf("invalid meter outbox record %q", e.Name())
		}
		if err := o.Poster.PostMeter(ctx, token); err != nil {
			var se *billing.StatusError
			if errors.As(err, &se) && se.Status >= 400 && se.Status < 500 {
				// Permanent rejection (a record that outlived its signing
				// window, a malformed file, ...): quarantine it and keep
				// flushing — one bad record must never jam the durable queue
				// head-of-line, which is how settled reservations leak.
				dead := filepath.Join(o.Dir, "dead", e.Name())
				if mkErr := os.MkdirAll(filepath.Dir(dead), 0o755); mkErr != nil {
					return mkErr
				}
				if mvErr := os.Rename(path, dead); mvErr != nil {
					return mvErr
				}
				continue
			}
			return err
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// Build returns a signed one-hour meter event suitable for the billing v1
// confidential meter endpoint. The window is deliberately long: a record must
// outlive a CVM rebuild inside the durable outbox. Billing additionally accepts
// authentic-but-expired records (settlement is idempotent), so the expiry is
// hygiene, not a hard gate.
func Build(s *Signer, reservation, requestID, model, issuer, audience string, input, cached, output int, now time.Time) (string, Claims, error) {
	c := Claims{Issuer: issuer, Audience: audience, Type: "adverserial-confidential-meter/v1", Reservation: reservation, RequestID: requestID, Model: model, InputTokens: input, CachedTokens: cached, OutputTokens: output, IssuedAt: now.Unix(), Expires: now.Add(time.Hour).Unix()}
	token, err := s.Sign(c)
	return token, c, err
}

// BuildStart returns a signed one-hour start event announcing that dispatch
// of a reservation is beginning. Billing records it before any inference runs
// so a released reservation can never complete unbilled; the counts stay zero
// because settlement always arrives as a separate meter event.
func BuildStart(s *Signer, reservation, requestID, model, issuer, audience string, now time.Time) (string, Claims, error) {
	c := Claims{Issuer: issuer, Audience: audience, Type: "adverserial-confidential-start/v1", Reservation: reservation, RequestID: requestID, Model: model, IssuedAt: now.Unix(), Expires: now.Add(time.Hour).Unix()}
	token, err := s.Sign(c)
	return token, c, err
}
