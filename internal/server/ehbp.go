package server

import (
	"net/http"
	"strings"

	ehbpprotocol "github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

// requireEHBP prevents a verified client from silently being downgraded to a
// plaintext inference request. The standards-based EHBP reference middleware
// immediately inside this wrapper decrypts/encrypts HTTP bodies and supports
// streaming responses. Attestation and quote binding publish the same EHBP
// receiver public key served at /.well-known/hpke-keys.
func (s *Server) requireEHBP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/") && r.Header.Get(ehbpprotocol.EncapsulatedKeyHeader) == "" {
			writeError(w, http.StatusUpgradeRequired, "encrypted EHBP requests are required for confidential inference")
			return
		}
		next.ServeHTTP(w, r)
	})
}
