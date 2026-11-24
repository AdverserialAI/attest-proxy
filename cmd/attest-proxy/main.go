// attest-proxy terminates TLS inside a Phala dstack confidential VM in front
// of the inference server, serves nonce-bound TDX attestation evidence with a
// signed ES256 verification receipt, and reverse-proxies everything else to
// the model runtime inside the same VM. It never logs request or response
// content. In confidential mode every private key is generated inside the
// enclave; none is accepted from configuration.
package main

import (
	"context"
	"crypto/tls"
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
	"github.com/adverserial/attest-proxy/internal/enclavekeys"
	"github.com/adverserial/attest-proxy/internal/meter"
	"github.com/adverserial/attest-proxy/internal/receipt"
	"github.com/adverserial/attest-proxy/internal/server"
	"github.com/adverserial/attest-proxy/internal/upstreamtoken"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

// upstreamTokenWait is how long startup waits for the init container to write
// the per-boot upstream credential.
const upstreamTokenWait = 120 * time.Second

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

	// Confidential deployments generate the receipt and meter signing keys
	// inside the CVM on first boot and reload them from the encrypted state
	// volume afterwards; config validation has already refused any externally
	// supplied seed. Verifiers learn the public keys from quote-bound evidence
	// (/attestation and the key attestation), never from the operator.
	// Development keeps a short-lived in-memory key (or an explicit seed) so
	// it cannot be mistaken for a production trust root.
	var signer *receipt.Signer
	var opts server.Options
	switch {
	case cfg.ConfidentialMode:
		keys, keyErr := enclavekeys.LoadOrCreate(cfg.EnclaveKeyDir)
		if keyErr != nil {
			return fmt.Errorf("ENCLAVE_KEY_DIR: %w", keyErr)
		}
		if signer, err = receipt.NewSignerFromKey(keys.Receipt); err != nil {
			return err
		}
		if opts.MeterSigner, err = meter.NewSignerFromKey(keys.Meter); err != nil {
			return err
		}
		opts.KeysOrigin = enclavekeys.Origin
	case cfg.ReceiptSigningSeed != "":
		signer, err = receipt.NewSignerFromSeed(cfg.ReceiptSigningSeed)
		opts.KeysOrigin = "operator-seed"
	default:
		signer, err = receipt.NewSigner()
		opts.KeysOrigin = "process-ephemeral"
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

	// The HPKE receiver identity lives for one process lifetime: generated
	// here, held in memory, never written to disk. Each boot's public key is
	// bound to that boot's quotes, so clients re-verify after a restart.
	var ehbpReceiver *ehbpidentity.Identity
	if cfg.EHBPRequired {
		ehbpReceiver, err = ehbpidentity.NewIdentity()
		if err != nil {
			return fmt.Errorf("generate EHBP identity: %w", err)
		}
	}

	if cfg.UpstreamBearerFile != "" {
		logger.Info("waiting for upstream credential file", "timeout", upstreamTokenWait.String())
		token, tokenErr := upstreamtoken.Wait(ctx, cfg.UpstreamBearerFile, upstreamTokenWait)
		if tokenErr != nil {
			return tokenErr
		}
		opts.UpstreamBearer = token.Token
	}

	srv := server.New(cfg, logger, quotes, signer, holder, ehbpReceiver)
	srv.Configure(opts)

	httpSrv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: srv.Handler(),
		// The certificate comes from the holder (in-memory; ACME material is
		// additionally persisted under CERT_DIR on the dstack volume).
		TLSConfig:         server.TLSConfig(holder),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
		// Entitlements and EHBP configuration fit comfortably within 64 KiB.
		// The default 1 MiB header budget unnecessarily amplifies a concurrent
		// header flood before any application middleware can run.
		MaxHeaderBytes: 64 << 10,
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
		"meter_kid", meterKeyID(opts.MeterSigner),
		"keys_origin", opts.KeysOrigin,
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

func meterKeyID(s *meter.Signer) string {
	if s == nil {
		return ""
	}
	return s.KeyID()
}

// setupTLS returns the certificate holder: an ACME DNS-01 certificate via the
// configured DNS provider when ACME_DOMAINS is set (with a background renewal
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
	dns, zone := dnsProvider(cfg)
	client := acme.NewClient(acme.Config{
		DirectoryURL:     cfg.ACMEDirectoryURL,
		Email:            cfg.ACMEEmail,
		Zone:             zone,
		DNS:              dns,
		PropagationDelay: 30 * time.Second, // let DNS converge before CA validation
	}, accountKey)

	cert, err := issueWithBackoff(ctx, store, client, cfg.ACMEDomains, logger)
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

// dnsProvider constructs the ACME DNS-01 provider selected by DNS_PROVIDER
// and returns it with the DNS zone it manages. Config validation has already
// rejected unsupported providers and missing credentials.
func dnsProvider(cfg config.Config) (acme.DNSProvider, string) {
	switch cfg.DNSProvider {
	case "cloudflare":
		return &acme.CloudflareProvider{Token: cfg.CloudflareAPIToken, Zone: cfg.CloudflareZone}, cfg.CloudflareZone
	default: // "gandi"
		return &acme.GandiProvider{PAT: cfg.GandiPAT, Zone: cfg.GandiZone}, cfg.GandiZone
	}
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

// issueWithBackoff retries first-boot issuance in-process instead of exiting:
// a fatal exit hands pacing to the container restart policy (seconds apart),
// which exhausts the CA's 5-failed-validations-per-hour budget in minutes.
// The schedule (1m, 5m, then every 15m) stays inside that budget indefinitely.
func issueWithBackoff(ctx context.Context, store acme.Store, client *acme.Client, domains []string, logger *slog.Logger) (tls.Certificate, error) {
	delays := []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute}
	for attempt := 0; ; attempt++ {
		cert, err := acme.LoadOrIssue(ctx, store, client, domains, acme.DefaultRenewBefore, logger)
		if err == nil {
			return cert, nil
		}
		delay := delays[min(attempt, len(delays)-1)]
		logger.Error("ACME issuance failed; will retry",
			"attempt", attempt+1, "retry_in", delay.String(), "error", err.Error())
		select {
		case <-ctx.Done():
			return tls.Certificate{}, ctx.Err()
		case <-time.After(delay):
		}
	}
}
