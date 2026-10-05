// attest-proxy terminates TLS inside a Phala dstack confidential VM in front
// of the inference server, serves nonce-bound TDX attestation evidence with a
// signed ES256 verification receipt, and reverse-proxies everything else to
// the loopback model runtime. It never logs request or response content.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/adverserial/attest-proxy/internal/acme"
	"github.com/adverserial/attest-proxy/internal/attestation"
	"github.com/adverserial/attest-proxy/internal/billing"
	"github.com/adverserial/attest-proxy/internal/buildinfo"
	"github.com/adverserial/attest-proxy/internal/config"
	"github.com/adverserial/attest-proxy/internal/receipt"
	"github.com/adverserial/attest-proxy/internal/server"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if err := run(logger); err != nil {
		logger.Error("fatal", "error", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.FromEnv(os.Getenv)
	if err != nil {
		return err
	}
	cfg, err = config.ResolveModelManifest(cfg)
	if err != nil {
		return err
	}

	// Confidential deployments use a stable key from sealed configuration. Its
	// public JWK is pinned in the public policy, while every fresh TDX quote
	// binds that key to the active TLS certificate and workload. Development
	// keeps the short-lived in-memory key so it cannot be mistaken for a
	// production trust root.
	var signer *receipt.Signer
	if cfg.ReceiptSigningSeed != "" {
		signer, err = receipt.NewSignerFromSeed(cfg.ReceiptSigningSeed)
	} else {
		signer, err = receipt.NewSigner()
	}
	if err != nil {
		return err
	}
	if cfg.MeterTLSBundleB64 != "" {
		if err := billing.MaterializeMeterTLSBundle(cfg.MeterTLSBundleB64, "/state/meter-tls"); err != nil {
			return fmt.Errorf("materialize confidential meter TLS bundle: %w", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	holder, err := setupTLS(ctx, cfg, logger)
	if err != nil {
		return err
	}

	var quotes attestation.QuoteSource
	if cfg.DevMode {
		logger.Warn("DEV_MODE enabled: attestation evidence is synthetic and marked dev=true")
		quotes = attestation.DevQuoteSource{}
	} else {
		quotes = attestation.NewDstackClient(cfg.DstackSocket)
	}

	var ehbpReceiver *ehbpidentity.Identity
	if cfg.EHBPRequired {
		identityJSON, decodeErr := base64.RawURLEncoding.DecodeString(cfg.EHBPIdentityB64)
		if decodeErr != nil {
			return fmt.Errorf("decode EHBP_IDENTITY_B64: %w", decodeErr)
		}
		ehbpReceiver, err = ehbpidentity.Import(identityJSON)
		if err != nil {
			return fmt.Errorf("load EHBP identity: %w", err)
		}
	}

	srv := server.New(cfg, logger, quotes, signer, holder, ehbpReceiver)

	httpSrv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: srv.Handler(),
		// The certificate comes from the holder (in-memory; ACME material is
		// additionally persisted under CERT_DIR on the dstack volume).
		TLSConfig:         server.TLSConfig(holder),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No ReadTimeout/WriteTimeout: inference streams may stay open for
		// many minutes.
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return err
	}

	logger.Info("attest-proxy listening",
		"addr", cfg.ListenAddr,
		"upstream", cfg.Upstream,
		"model_id", cfg.ModelID,
		"policy_id", cfg.PolicyID,
		"dev_mode", cfg.DevMode,
		"acme", len(cfg.ACMEDomains) > 0,
		"version", buildinfo.Version,
		"receipt_kid", signer.KeyID(),
		"tls_spki_sha256", attestation.SPKIHash(holder.Leaf()),
	)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	err = httpSrv.ServeTLS(ln, "", "") // certificates from TLSConfig
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// setupTLS returns the certificate holder: an ACME DNS-01 certificate via
// Gandi LiveDNS when ACME_DOMAINS is configured (with a background renewal
// loop), otherwise the in-process self-signed certificate.
func setupTLS(ctx context.Context, cfg config.Config, logger *slog.Logger) (*server.CertHolder, error) {
	if len(cfg.ACMEDomains) == 0 {
		cert, _, err := server.GenerateSelfSigned(cfg.TLSHostnames)
		if err != nil {
			return nil, err
		}
		return server.NewCertHolder(cert)
	}

	store := acme.Store{Dir: cfg.CertDir}
	accountKey, err := store.AccountKey()
	if err != nil {
		return nil, err
	}
	client := acme.NewClient(acme.Config{
		DirectoryURL:     cfg.ACMEDirectoryURL,
		Email:            cfg.ACMEEmail,
		Zone:             cfg.GandiZone,
		DNS:              &acme.GandiProvider{PAT: cfg.GandiPAT, Zone: cfg.GandiZone},
		PropagationDelay: 10 * time.Second, // let LiveDNS converge before CA validation
	}, accountKey)

	cert, err := acme.LoadOrIssue(ctx, store, client, cfg.ACMEDomains, acme.DefaultRenewBefore, logger)
	if err != nil {
		return nil, fmt.Errorf("acme: %w", err)
	}
	holder, err := server.NewCertHolder(cert)
	if err != nil {
		return nil, err
	}
	logger.Info("ACME certificate active",
		"domains", strings.Join(cfg.ACMEDomains, ","),
		"not_after", holder.Leaf().NotAfter.Format(time.RFC3339),
	)

	go renewLoop(ctx, store, client, holder, cfg.ACMEDomains, logger)
	return holder, nil
}

// renewLoop re-issues and hot-swaps the certificate when fewer than
// DefaultRenewBefore remain. The attestation evidence's tls_spki_sha256 (and
// the quote binding) follow the swapped certificate automatically.
func renewLoop(ctx context.Context, store acme.Store, client *acme.Client, holder *server.CertHolder, domains []string, logger *slog.Logger) {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, ok := store.LoadCert(domains, acme.DefaultRenewBefore, time.Now()); ok {
				continue
			}
			logger.Info("certificate renewal due", "domains", strings.Join(domains, ","))
			cert, err := acme.LoadOrIssue(ctx, store, client, domains, acme.DefaultRenewBefore, logger)
			if err != nil {
				logger.Error("certificate renewal failed", "error", err.Error())
				continue
			}
			if err := holder.Swap(cert); err != nil {
				logger.Error("certificate swap failed", "error", err.Error())
				continue
			}
			logger.Info("certificate renewed",
				"not_after", holder.Leaf().NotAfter.Format(time.RFC3339),
				"tls_spki_sha256", attestation.SPKIHash(holder.Leaf()),
			)
		}
	}
}
