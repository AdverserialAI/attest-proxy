package gate

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/adverserial/attest-proxy/internal/entitlement"
)

// bindCacheSalt runs only after entitlement signature/model/channel validation.
// A v1 token without the optional namespace gets a request-specific cache: it
// must not join a global shared cache. Callers cannot choose a cache scope.
// Receipt hashes continue to bind the original client bytes, before injection.
func bindCacheSalt(body []byte, claims entitlement.Claims) ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil || doc == nil {
		return nil, fmt.Errorf("invalid request object")
	}
	for key := range doc {
		if strings.EqualFold(key, "cache_salt") || strings.EqualFold(key, "cache_namespace") {
			return nil, fmt.Errorf("caller-selected cache namespace")
		}
	}
	kind, scope := "reservation", claims.ID
	if claims.CacheNamespace != "" {
		kind, scope = "tenant", claims.CacheNamespace
	}
	if scope == "" || claims.Model == "" {
		return nil, fmt.Errorf("missing verified cache scope")
	}
	// Authority/model domain separation also protects legacy request IDs that
	// happen to be equal in independent issuer/audience/model deployments.
	sum := sha256.Sum256([]byte("adverserial-vllm-prefix/v1\x00" + kind + "\x00" + claims.Issuer +
		"\x00" + claims.Audience + "\x00" + claims.Model + "\x00" + scope))
	encoded, _ := json.Marshal(base64.RawURLEncoding.EncodeToString(sum[:]))
	doc["cache_salt"] = encoded
	return json.Marshal(doc)
}
