package gate

import (
	"bytes"
	"encoding/json"
	"strings"
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
// jsonStreamTruthy reports whether a JSON value asks for streaming. The
// upstream (pydantic) coerces more than the JSON boolean: 1, "1", "true",
// "yes", "on" all stream — injection must cover exactly what upstream honors,
// otherwise a non-boolean truthy flag streams unmetered.
func jsonStreamTruthy(raw json.RawMessage) bool {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	var n float64
	if json.Unmarshal(raw, &n) == nil {
		return n != 0
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "", "0", "false", "no", "off":
			return false
		}
		return true
	}
	return false // null, arrays, objects
}

func injectIncludeUsage(path string, body []byte) ([]byte, bool) {
	if path != "/v1/chat/completions" {
		return nil, false
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false
	}
	raw, ok := doc["stream"]
	if !ok || !jsonStreamTruthy(raw) {
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
