package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// controlKeys are the request fields where a case-variant duplicate would let
// the gate and the upstream read different values (Go's encoding/json matches
// struct fields case-insensitively; pydantic is case-sensitive).
var controlKeys = map[string]bool{
	"model": true, "max_tokens": true, "max_completion_tokens": true,
	"max_output_tokens": true, "stream": true, "stream_options": true,
	"chat_template": true,
}

// limitKeys are every completion-limit spelling the upstream honors. The gate
// must bind the maximum of all of them: binding only max_tokens while the
// model obeys max_completion_tokens/max_output_tokens underbills by that
// multiple (R25-BILLCAP-001 OUTPUT cases).
var limitKeys = []string{"max_tokens", "max_completion_tokens", "max_output_tokens"}

// rejectDuplicateKeys scans the top level of a JSON object and refuses any
// exact duplicate key, any case-variant duplicate of a control key, and the
// presence of chat_template (a server-side template expansion field: ~190
// body bytes render 1000+ prompt tokens upstream, defeating the byte-length
// input bound — R25-BILLCAP-001 INPUT case).
func rejectDuplicateKeys(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil // not an object: the plain parse below reports the model error
	}
	seen := map[string]bool{}
	seenFold := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil
		}
		key, ok := t.(string)
		if !ok {
			return nil
		}
		if seen[key] {
			return fmt.Errorf("duplicate JSON key %q is not allowed", key)
		}
		seen[key] = true
		fold := strings.ToLower(key)
		if controlKeys[fold] {
			if seenFold[fold] {
				return fmt.Errorf("case-variant duplicate of %q is not allowed", fold)
			}
			seenFold[fold] = true
		}
		if fold == "chat_template" {
			return errors.New("chat_template is not supported on this endpoint")
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil
		}
	}
	return nil
}

// parseRequestLimits extracts the model id and the effective output bound.
// Confidential mode parses strictly (duplicate/case-variant keys rejected,
// all completion-limit spellings bound, chat_template refused); legacy mode
// keeps the historical lenient parse for compatibility.
func parseRequestLimits(confidential bool, body []byte) (model string, maxOut int, err error) {
	if !confidential {
		var parsed struct {
			Model     string `json:"model"`
			MaxTokens *int   `json:"max_tokens"`
		}
		_ = json.Unmarshal(body, &parsed) // malformed JSON → empty model
		maxOut = -1
		if parsed.MaxTokens != nil {
			maxOut = *parsed.MaxTokens
		}
		return parsed.Model, maxOut, nil
	}

	if err := rejectDuplicateKeys(body); err != nil {
		return "", 0, err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", 0, nil // malformed JSON → empty model, reported by the caller
	}
	if raw, ok := doc["model"]; ok {
		_ = json.Unmarshal(raw, &model) // non-string → empty model
	}
	maxOut = -1
	for _, k := range limitKeys {
		raw, ok := doc[k]
		if !ok {
			continue
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return "", 0, fmt.Errorf("%s must be a positive integer", k)
		}
		f, ok := v.(float64)
		if !ok || f != float64(int(f)) || f < 1 || f > 1<<31 {
			return "", 0, fmt.Errorf("%s must be a positive integer", k)
		}
		if int(f) > maxOut {
			maxOut = int(f)
		}
	}
	return model, maxOut, nil
}
