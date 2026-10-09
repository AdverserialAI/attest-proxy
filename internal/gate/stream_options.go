package gate

import (
	"bytes"
	"encoding/json"
)

// injectIncludeUsage merges "stream_options": {"include_usage": true} into a
// buffered POST /v1/chat/completions streaming request so SGLang always
// terminates a completed stream with a usage chunk and terminal settlement
// can carry real counts. Existing stream_options keys are preserved;
// include_usage is forced true. It returns ok=false (body untouched) for
// every other route, non-streaming requests, and malformed bodies.
//
// Callers must invoke this only after capturing whatever binds the client's
// original bytes (the receipt request-body hash and the entitlement input
// bound): the rewritten body is upstream-bound only.
func injectIncludeUsage(path string, body []byte) ([]byte, bool) {
	if path != "/v1/chat/completions" {
		return nil, false
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false
	}
	var stream bool
	if raw, ok := doc["stream"]; !ok || json.Unmarshal(raw, &stream) != nil || !stream {
		return nil, false
	}
	opts := map[string]json.RawMessage{}
	if raw, ok := doc["stream_options"]; ok && len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
		if err := json.Unmarshal(raw, &opts); err != nil {
			return nil, false // malformed options: forward the request untouched
		}
	}
	opts["include_usage"] = json.RawMessage("true")
	merged, err := json.Marshal(opts)
	if err != nil {
		return nil, false
	}
	doc["stream_options"] = merged
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, false
	}
	return out, true
}
