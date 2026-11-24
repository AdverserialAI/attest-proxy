package server

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/adverserial/attest-proxy/internal/meter"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newMeterSigner(t *testing.T) *meter.Signer {
	t.Helper()
	signer, err := meter.NewTestSigner()
	if err != nil {
		t.Fatalf("NewTestSigner: %v", err)
	}
	return signer
}

// buildTestMeterEvent signs a meter event with the server's meter key.
func buildTestMeterEvent(srv *Server) (string, meter.Claims, error) {
	return meter.Build(srv.meterSigner, "reservation", "request", "lordx64/cyberglm",
		"https://api.adverserial.ai", "https://billing.adverserial.ai", 3, 1, 2, time.Unix(1759999000, 0))
}
