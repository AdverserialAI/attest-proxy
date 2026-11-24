package gate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
)

// SGLang keys its radix prefix cache on the per-request cache_salt and
// extra_key fields: requests with equal keys share cached prefixes, and a
// cache hit is observable through latency and cached-token counts. Left to
// the client, those fields let one tenant probe whether another tenant has
// sent a given prefix. Confidential mode therefore owns both fields: extra_key
// is refused, and cache_salt is always replaced by a value derived from the
// billing-signed tenant identity under a key that exists only in this
// process.

// clientCacheSalt is the accepted shape of an optional client cache_salt. A
// client uses it to partition its own cache; it never reaches the model
// runtime verbatim.
var clientCacheSalt = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)

// validateCacheIsolationFields refuses client control of the prefix-cache
// key before any entitlement is consumed.
func validateCacheIsolationFields(doc map[string]json.RawMessage) error {
	if _, ok := doc["extra_key"]; ok {
		return errors.New("extra_key is not supported on this endpoint")
	}
	if raw, ok := doc["cache_salt"]; ok {
		var salt string
		if err := json.Unmarshal(raw, &salt); err != nil || !clientCacheSalt.MatchString(salt) {
			return errors.New("cache_salt must be a string of 32 to 128 characters from [A-Za-z0-9_-]")
		}
	}
	return nil
}

// tenantCacheSalt returns base64url-nopad(HMAC-SHA256(key, tenantID || 0x00
// || clientSalt)). clientSalt cannot contain 0x00 (see clientCacheSalt), so
// the last 0x00 always separates the two inputs and distinct (tenant, salt)
// pairs never produce the same message.
func tenantCacheSalt(key []byte, tenantID, clientSalt string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(tenantID))
	mac.Write([]byte{0})
	mac.Write([]byte(clientSalt))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// bindCacheSalt rewrites the upstream-bound body so cache_salt is the
// tenant-derived value, whatever the client sent. It fails rather than
// forwarding a body it could not rewrite. Callers must have captured the
// client's original bytes (receipt hash, entitlement input bound) first.
func bindCacheSalt(body, key []byte, tenantID string) ([]byte, error) {
	if len(key) == 0 || tenantID == "" {
		return nil, errors.New("cache isolation is not configured")
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, errors.New("request body must be a JSON object")
	}
	if err := validateCacheIsolationFields(doc); err != nil {
		return nil, err
	}
	var clientSalt string
	if raw, ok := doc["cache_salt"]; ok {
		_ = json.Unmarshal(raw, &clientSalt) // validated above
	}
	salt, err := json.Marshal(tenantCacheSalt(key, tenantID, clientSalt))
	if err != nil {
		return nil, err
	}
	doc["cache_salt"] = salt
	return json.Marshal(doc)
}
