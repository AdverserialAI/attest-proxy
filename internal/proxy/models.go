package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
)

// modelsPath is the exact route augmented for the browser-direct chat UI.
const modelsPath = "/v1/models"

// maxModelsBody caps how much of a /v1/models response the augmenter will
// buffer. Anything larger passes through untouched.
const maxModelsBody = 8 << 20

// ModelsAugmenter injects an info.meta.confidential_verification block into
// every (allowed) entry of the upstream GET /v1/models response, so the
// browser client can discover how to verify this endpoint (see
// confidentialVerificationConfig() in adverserial-webui). All other requests
// and responses pass through byte-identical.
type ModelsAugmenter struct {
	AttestationURL  string         // <public base>/attestation
	VerificationURL string         // public verifier site
	ReceiptIssuer   string         // receipt iss
	ReceiptAudience string         // receipt aud
	TrustedKeys     map[string]any // kid → receipt public JWK
	Endpoint        string         // public base URL (expected.endpoint)
	ModelDigest     string         // expected.model_digest, omitted when empty
	RuntimeDigest   string         // expected.runtime_digest, omitted when empty

	// Allowed filters which model IDs receive the block; nil means all.
	Allowed map[string]bool
}

// DirectorWrap strips Accept-Encoding on /v1/models requests so the augmenter
// always sees identity-encoded JSON. Wrap the reverse proxy's Director with
// it (see proxy.New).
func DirectorWrap(base func(*http.Request)) func(*http.Request) {
	return func(r *http.Request) {
		base(r)
		if r.Method == http.MethodGet && r.URL.Path == modelsPath {
			r.Header.Del("Accept-Encoding")
		}
	}
}

// ModifyResponse implements httputil.ReverseProxy.ModifyResponse. Only a
// 200 JSON response to GET /v1/models is touched; any failure restores the
// original body verbatim.
func (a *ModelsAugmenter) ModifyResponse(resp *http.Response) error {
	req := resp.Request
	if req == nil || req.Method != http.MethodGet || req.URL.Path != modelsPath {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxModelsBody+1))
	_ = resp.Body.Close()
	if err != nil || len(body) > maxModelsBody {
		restoreBody(resp, body)
		return nil
	}

	out := a.Augment(body)
	restoreBody(resp, out)
	if !bytes.Equal(out, body) {
		resp.Header.Del("ETag")
	}
	return nil
}

func restoreBody(resp *http.Response, body []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
}

// Augment returns the models document with confidential_verification blocks
// injected, or the input unchanged when the shape is unexpected or nothing
// was modified.
func (a *ModelsAugmenter) Augment(body []byte) []byte {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return body
	}
	data, ok := doc["data"].([]any)
	if !ok {
		return body
	}

	changed := false
	for _, item := range data {
		model, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id, _ := model["id"].(string)
		if id == "" || (a.Allowed != nil && !a.Allowed[id]) {
			continue
		}
		info, _ := model["info"].(map[string]any)
		if info == nil {
			info = map[string]any{}
		}
		meta, _ := info["meta"].(map[string]any)
		if meta == nil {
			meta = map[string]any{}
		}
		meta["confidential_verification"] = a.block(id)
		info["meta"] = meta
		model["info"] = info
		changed = true
	}
	if !changed {
		return body
	}

	// Re-encode without HTML escaping so unrelated string values (model IDs
	// containing '&' etc.) survive byte-identical.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return body
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// block builds the confidential_verification value for one model ID, in the
// shape the browser client's confidentialVerificationConfig() reads.
func (a *ModelsAugmenter) block(modelID string) map[string]any {
	expected := map[string]any{
		"model_id": modelID,
		"endpoint": a.Endpoint,
	}
	if a.ModelDigest != "" {
		expected["model_digest"] = a.ModelDigest
	}
	if a.RuntimeDigest != "" {
		expected["runtime_digest"] = a.RuntimeDigest
	}
	return map[string]any{
		"attestation_url":      a.AttestationURL,
		"verification_url":     a.VerificationURL,
		"receipt_issuer":       a.ReceiptIssuer,
		"receipt_audience":     a.ReceiptAudience,
		"trusted_receipt_keys": a.TrustedKeys,
		"expected":             expected,
	}
}
