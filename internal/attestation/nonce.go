package attestation

import (
	"encoding/base64"
	"fmt"
)

// ValidateNonce validates a client-supplied nonce: base64url (padding
// optional) decoding to 16–64 bytes. Shared by the /attestation endpoint and
// the per-request X-Adverserial-Nonce header (WP-7).
func ValidateNonce(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("empty nonce")
	}
	if len(s) > 96 { // 64 bytes → 88 chars padded; anything longer cannot be in range
		return nil, fmt.Errorf("nonce too long")
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("nonce is not valid base64url")
		}
	}
	if len(raw) < 16 {
		return nil, fmt.Errorf("nonce too short: need 16-64 bytes")
	}
	if len(raw) > 64 {
		return nil, fmt.Errorf("nonce too long: need 16-64 bytes")
	}
	return raw, nil
}
