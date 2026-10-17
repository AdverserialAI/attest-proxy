package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// controlKeys are the request fields where a case-variant duplicate would let
// the gate and the upstream read different values (Go's encoding/json matches
// struct fields case-insensitively; pydantic is case-sensitive).
var controlKeys = map[string]bool{
	"model": true, "max_tokens": true, "max_completion_tokens": true,
	"max_output_tokens": true, "max_new_tokens": true, "stream": true,
	"stream_options": true, "chat_template": true, "n": true, "best_of": true,
	"parallel_sample_num": true, "logprobs": true, "top_logprobs": true,
	"top_logprobs_num": true, "top_k": true, "min_tokens": true,
	"min_new_tokens": true, "stop_token_ids": true, "token_ids_logprob": true,
	"input_ids": true, "return_hidden_states": true, "return_routed_experts": true,
	"routed_experts_start_len": true, "return_cached_tokens_details": true,
	"return_spec_tokens_details": true, "return_prompt_token_ids": true,
	"return_token_ids": true, "return_meta_info": true,
	"return_input_ids_in_sglext": true, "return_output_ids_in_sglext": true,
	"return_sampling_mask": true, "sampling_logprobs_mode": true,
	"return_flat_raw_output_top_logprobs": true,
	"return_flat_raw_top_logprobs_b64":    true, "lora_path": true,
	"custom_logit_processor": true, "priority": true, "routed_dp_rank": true,
	"data_parallel_rank": true, "bootstrap_host": true, "bootstrap_port": true,
	"bootstrap_room": true, "disagg_prefill_dp_rank": true,
	// rc.26: the remaining engine-stress payload classes
	"logit_bias": true, "response_format": true, "regex": true, "ebnf": true,
	"json_schema": true, "guided_json": true, "guided_regex": true,
	"guided_grammar": true, "stop": true, "tools": true, "tool_choice": true,
	"sampling_params": true,
}

// fanoutKeys multiply generation server-side: n parallel completions (or
// best_of candidates) each count toward output usage, but a single-sequence
// bound covers them only once — an unvalidated n=64 with max_tokens=64
// generated 4069 tokens against a 64-token bound (63x undercharge) and
// occupies one admission slot for 64 sequences. Confidential mode is
// single-sequence only.
var fanoutKeys = []string{"n", "best_of"}

// completionLimitKeys are endpoint-specific. Treating every spelling as
// interchangeable is unsafe: SGLang ignores a Chat-only key on Responses (or
// a Responses-only key on Chat), while the old gate would still bind the
// ignored small value into the entitlement. That made a default-length model
// completion appear metered as a one-token request.
var completionLimitKeys = map[string][]string{
	"/v1/chat/completions": {"max_tokens", "max_completion_tokens"},
	"/v1/responses":        {"max_output_tokens"},
}

var allCompletionLimitKeys = map[string]bool{
	"max_tokens": true, "max_completion_tokens": true, "max_output_tokens": true,
}

const (
	// Bound nesting before decoding arbitrary request JSON. A request's raw
	// body limit does not prevent a compact, deeply nested JSON value from
	// imposing disproportionate parser or downstream validation work.
	maxRequestJSONDepth = 32
	// Chat templates add control tokens for each message and tool call. Bound
	// cardinality as well as bytes so a compact JSON body cannot expand into an
	// disproportionately large model prompt after the entitlement is checked.
	// The ceiling must fit real agentic harness sessions: kimi-code, claude-code,
	// codex, and opencode carry the full message history on every turn, which
	// reaches a few hundred messages in ordinary use. The 8 MiB body cap remains
	// the real memory bound; this bound only prevents degenerate
	// many-tiny-messages expansion.
	maxConversationItems      = 512
	maxToolCallsPerMessage    = 16
	maxContentPartsPerMessage = 32
	// OpenAI specifies a maximum of 20 alternatives per generated token. This
	// deliberately stays below the model vocabulary and bounds both scheduler
	// work and response amplification.
	maxTopLogprobs = 20
	// top_k=-1 disables top-k sampling in SGLang. A fixed positive ceiling
	// avoids an attacker turning each generated token into an unbounded top-k
	// operation while still allowing useful non-default sampling.
	maxTopK = 1024
)

// unsafeConfidentialKeys are native/compatibility controls that must never
// reach confidential SGLang. They either bypass normal text tokenization or
// reach token-id operations without a vocabulary bound. The native endpoints
// are already fenced; this closes equivalent fields accepted by the OpenAI
// chat surface on different SGLang releases.
var unsafeConfidentialKeys = map[string]string{
	"input_ids":           "input_ids is not supported on this endpoint",
	"stop_token_ids":      "stop_token_ids is not supported on this endpoint",
	"token_ids_logprob":   "token_ids_logprob is not supported on this endpoint",
	"top_logprobs_num":    "top_logprobs_num is not supported on this endpoint",
	"min_new_tokens":      "min_new_tokens is not supported on this endpoint",
	"parallel_sample_num": "parallel_sample_num is not supported on this endpoint",
	"max_new_tokens":      "max_new_tokens is not supported on this endpoint",

	// SGLang debug/result-expansion controls can return tensors, token-id
	// vectors, and routing internals that are neither part of the OpenAI
	// contract nor covered by token metering. Confidential endpoints expose
	// ordinary text, reasoning, and tool-call responses only.
	"return_hidden_states":                "debug tensor output is not supported on this endpoint",
	"return_routed_experts":               "debug routing output is not supported on this endpoint",
	"routed_experts_start_len":            "debug routing controls are not supported on this endpoint",
	"return_cached_tokens_details":        "debug cache output is not supported on this endpoint",
	"return_spec_tokens_details":          "debug speculation output is not supported on this endpoint",
	"return_prompt_token_ids":             "debug token-id output is not supported on this endpoint",
	"return_token_ids":                    "debug token-id output is not supported on this endpoint",
	"return_meta_info":                    "debug metadata output is not supported on this endpoint",
	"return_input_ids_in_sglext":          "debug token-id output is not supported on this endpoint",
	"return_output_ids_in_sglext":         "debug token-id output is not supported on this endpoint",
	"return_sampling_mask":                "debug sampling output is not supported on this endpoint",
	"sampling_logprobs_mode":              "debug logprob output is not supported on this endpoint",
	"return_flat_raw_output_top_logprobs": "debug logprob output is not supported on this endpoint",
	"return_flat_raw_top_logprobs_b64":    "debug logprob output is not supported on this endpoint",

	// These extensions select runtime-controlled resources or a queue/routing
	// lane. Public callers must not select an adapter, custom processor, or a
	// particular worker/priority; the attested deployment owns those choices.
	"lora_path":              "dynamic adapter selection is not supported on this endpoint",
	"custom_logit_processor": "custom logit processors are not supported on this endpoint",
	"priority":               "request priority is not supported on this endpoint",
	"routed_dp_rank":         "internal routing controls are not supported on this endpoint",
	"data_parallel_rank":     "internal routing controls are not supported on this endpoint",
	"bootstrap_host":         "internal routing controls are not supported on this endpoint",
	"bootstrap_port":         "internal routing controls are not supported on this endpoint",
	"bootstrap_room":         "internal routing controls are not supported on this endpoint",
	"disagg_prefill_dp_rank": "internal routing controls are not supported on this endpoint",
}

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
// endpoint-specific completion-limit spellings bound, chat_template refused);
// legacy mode keeps the historical lenient parse for compatibility.
func parseRequestLimits(confidential bool, requestPath string, body []byte) (model string, maxOut int, err error) {
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
	if !jsonDepthAtMost(body, maxRequestJSONDepth) {
		return "", 0, fmt.Errorf("request JSON exceeds the %d-level nesting limit", maxRequestJSONDepth)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", 0, nil // malformed JSON → empty model, reported by the caller
	}
	// The upstream's field matching may differ from encoding/json's. Accepting
	// a single mixed-case control key would therefore make the admission parser
	// and model server disagree about a generation-affecting value. Confidential
	// requests use the documented lowercase spelling only.
	for key := range doc {
		fold := strings.ToLower(key)
		if controlKeys[fold] && key != fold {
			return "", 0, fmt.Errorf("control field %q must use lowercase spelling %q", key, fold)
		}
	}
	if raw, ok := doc["model"]; ok {
		_ = json.Unmarshal(raw, &model) // non-string → empty model
	}
	limitKeys, ok := completionLimitKeys[requestPath]
	if !ok {
		return "", 0, fmt.Errorf("unsupported confidential inference path %q", requestPath)
	}
	allowedLimits := make(map[string]bool, len(limitKeys))
	for _, k := range limitKeys {
		allowedLimits[k] = true
	}
	for k := range allCompletionLimitKeys {
		if _, present := doc[k]; present && !allowedLimits[k] {
			return "", 0, fmt.Errorf("%s is not supported on %s", k, requestPath)
		}
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
	for _, k := range fanoutKeys {
		raw, ok := doc[k]
		if !ok {
			continue
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return "", 0, fmt.Errorf("%s must be a positive integer", k)
		}
		f, ok := v.(float64)
		if !ok || f != float64(int(f)) || f < 1 {
			return "", 0, fmt.Errorf("%s must be a positive integer", k)
		}
		if int(f) != 1 {
			return "", 0, fmt.Errorf("%s > 1 is not supported on this endpoint (parallel generations are not metered per-request)", k)
		}
	}
	if err := validateSamplingControls(doc, maxOut); err != nil {
		return "", 0, err
	}
	if err := validateConversationLimits(requestPath, doc); err != nil {
		return "", 0, err
	}
	if err := validatePayloadBounds(doc); err != nil {
		return "", 0, err
	}
	return model, maxOut, nil
}

// validateConversationLimits keeps confidential inference to the text-and-
// tool-call shape emitted by the supported SDK gateways. In particular,
// content-part arrays can carry remote media references that make the model
// runtime fetch or expand data outside the entitlement's byte-bound prompt.
func validateConversationLimits(requestPath string, doc map[string]json.RawMessage) error {
	if requestPath == "/v1/responses" {
		raw, ok := doc["input"]
		if !ok {
			// Upstream remains responsible for rejecting a semantically incomplete
			// request. Do not turn the parser into a second API validator here.
			return nil
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return errors.New("input must not be null on /v1/responses")
		}
		var text string
		if json.Unmarshal(raw, &text) == nil {
			return nil
		}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil || len(items) > maxConversationItems {
			return fmt.Errorf("input must be text or an array of at most %d items", maxConversationItems)
		}
		return nil
	}

	raw, ok := doc["messages"]
	if !ok {
		// Upstream remains responsible for rejecting a semantically incomplete
		// request. The gate only bounds fields that can expand model work.
		return nil
	}
	var messages []json.RawMessage
	if err := json.Unmarshal(raw, &messages); err != nil || len(messages) == 0 || len(messages) > maxConversationItems {
		return fmt.Errorf("messages must be an array of 1 to %d items", maxConversationItems)
	}
	for _, rawMessage := range messages {
		var message map[string]json.RawMessage
		if err := json.Unmarshal(rawMessage, &message); err != nil {
			return errors.New("each message must be an object")
		}
		var role string
		if err := json.Unmarshal(message["role"], &role); err != nil {
			return errors.New("each message must have a text role")
		}
		switch role {
		case "system", "developer", "user", "assistant", "tool":
		default:
			return fmt.Errorf("message role %q is not supported on this endpoint", role)
		}
		if content, present := message["content"]; present {
			if err := validateMessageContent(content); err != nil {
				return err
			}
		}
		if calls, present := message["tool_calls"]; present {
			var toolCalls []json.RawMessage
			if err := json.Unmarshal(calls, &toolCalls); err != nil || len(toolCalls) > maxToolCallsPerMessage {
				return fmt.Errorf("message tool_calls must be an array of at most %d items", maxToolCallsPerMessage)
			}
		}
	}
	return nil
}

// validateMessageContent accepts the text shapes the supported SDK gateways
// emit: a plain string, null, or an array of text content parts
// ([{"type":"text","text":"..."}] — the shape kimi-code, claude-code, codex,
// and opencode send for nearly every message). Parts of any other type carry
// remote media references that make the model runtime fetch or expand data
// outside the entitlement's byte-bound prompt, and vision is unsupported on
// this deployment, so they stay rejected.
func validateMessageContent(raw json.RawMessage) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return nil
	}
	var parts []json.RawMessage
	if err := json.Unmarshal(raw, &parts); err != nil {
		return errors.New("message content must be text; media content is not supported on this endpoint")
	}
	if len(parts) > maxContentPartsPerMessage {
		return fmt.Errorf("message content exceeds the %d-part limit", maxContentPartsPerMessage)
	}
	for _, rawPart := range parts {
		var part map[string]json.RawMessage
		if err := json.Unmarshal(rawPart, &part); err != nil {
			return errors.New("message content parts must be objects")
		}
		var kind string
		if err := json.Unmarshal(part["type"], &kind); err != nil || kind != "text" {
			return errors.New("only text content parts are supported on this endpoint; media content is not supported")
		}
		var partText string
		if err := json.Unmarshal(part["text"], &partText); err != nil {
			return errors.New("text content parts must carry a text string")
		}
	}
	return nil
}

// validateSamplingControls constrains the SGLang controls whose accepted
// range is broader than the OpenAI chat contract. In particular, older and
// current SGLang releases have accepted values that can reach topk/scatter
// tensor operations without a vocabulary bound. Keep the check at the proxy
// boundary, rather than relying on the image version, so future image changes
// cannot reopen this availability boundary.
func validateSamplingControls(doc map[string]json.RawMessage, maxOut int) error {
	for key, message := range unsafeConfidentialKeys {
		if _, ok := doc[key]; ok {
			return errors.New(message)
		}
	}

	if raw, ok := doc["logprobs"]; ok {
		value := bytes.TrimSpace(raw)
		if !bytes.Equal(value, []byte("true")) && !bytes.Equal(value, []byte("false")) {
			return errors.New("logprobs must be a boolean")
		}
	}
	if raw, ok := doc["top_logprobs"]; ok {
		value, err := parseControlInt(raw, "top_logprobs")
		if err != nil || value < 0 || value > maxTopLogprobs {
			return fmt.Errorf("top_logprobs must be an integer from 0 to %d", maxTopLogprobs)
		}
	}
	if raw, ok := doc["top_k"]; ok {
		value, err := parseControlInt(raw, "top_k")
		if err != nil || value == 0 || value < -1 || value > maxTopK {
			return fmt.Errorf("top_k must be -1 or an integer from 1 to %d", maxTopK)
		}
	}
	if raw, ok := doc["min_tokens"]; ok {
		value, err := parseControlInt(raw, "min_tokens")
		if err != nil || value < 0 {
			return errors.New("min_tokens must be a non-negative integer")
		}
		// A positive minimum must fit the effective output limit that is bound
		// into the one-use entitlement. parseRequestLimits returns -1 when the
		// request has no bound; the gate will reject that request separately.
		if maxOut > 0 && value > maxOut {
			return errors.New("min_tokens must not exceed the requested output limit")
		}
	}
	return nil
}

func parseControlInt(raw json.RawMessage, field string) (int, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return 0, fmt.Errorf("%s must be an integer", field)
	}
	var value int
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, fmt.Errorf("%s must be an integer", field)
	}
	return value, nil
}

// rc.26 payload bounds: the remaining engine-stress classes. A pathological
// grammar (xgrammar compile explosion hangs the scheduler), a giant logit_bias
// map (per-token hot path + memory spike), a stop-sequence flood, or a huge
// tools array can each destabilize the SGLang engine from a single request.
const (
	maxLogitBiasEntries    = 100
	maxLogitBiasAbs        = 100.0
	maxLogitBiasTokenID    = 200_000
	maxResponseFormatBytes = 4 << 10
	maxStopSequences       = 8
	maxStopBytes           = 4 << 10
	maxTools               = 64
	maxToolsBytes          = 64 << 10
	maxToolChoiceBytes     = 4 << 10
	maxToolJSONDepth       = 20
)

// validatePayloadBounds caps every request field that can grow engine work
// independently of the token-metered path.
func validatePayloadBounds(doc map[string]json.RawMessage) error {
	// Grammar compilation lives inside the inference engine. A byte cap alone
	// does not prevent a compact but pathological schema or regex from tying up
	// that engine, so confidential inference accepts only OpenAI's simple JSON
	// object mode. The other grammar surfaces stay unavailable until they have
	// an isolated resource budget and load coverage.
	for _, k := range []string{"ebnf", "guided_grammar", "regex", "json_schema", "guided_json", "guided_regex"} {
		if _, ok := doc[k]; ok {
			return fmt.Errorf("%s is not supported on this endpoint", k)
		}
	}
	if raw, ok := doc["response_format"]; ok {
		if err := validateResponseFormat(raw); err != nil {
			return err
		}
	}
	// sampling_params is a native passthrough that could smuggle unchecked
	// fields past every top-level control above.
	if _, ok := doc["sampling_params"]; ok {
		return fmt.Errorf("sampling_params is not supported on this endpoint")
	}
	if raw, ok := doc["logit_bias"]; ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		var m map[string]float64
		if err := json.Unmarshal(raw, &m); err != nil {
			return fmt.Errorf("logit_bias must be an object of token-id to bias")
		}
		if len(m) > maxLogitBiasEntries {
			return fmt.Errorf("logit_bias exceeds the %d-entry limit", maxLogitBiasEntries)
		}
		for k, v := range m {
			id, err := strconv.ParseInt(k, 10, 32)
			if err != nil || id < 0 || id >= maxLogitBiasTokenID {
				return fmt.Errorf("logit_bias key %q is not a valid token id", k)
			}
			if v > maxLogitBiasAbs || v < -maxLogitBiasAbs {
				return fmt.Errorf("logit_bias value out of range")
			}
		}
	}
	if raw, ok := doc["stop"]; ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		var stops []string
		var single string
		if err := json.Unmarshal(raw, &stops); err != nil {
			if err := json.Unmarshal(raw, &single); err != nil {
				return fmt.Errorf("stop must be a string or an array of strings")
			}
			stops = []string{single}
		}
		if len(stops) > maxStopSequences {
			return fmt.Errorf("stop exceeds the %d-sequence limit", maxStopSequences)
		}
		total := 0
		for _, s := range stops {
			total += len(s)
		}
		if total > maxStopBytes {
			return fmt.Errorf("stop sequences exceed the %dKB total limit", maxStopBytes>>10)
		}
	}
	if raw, ok := doc["tools"]; ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if len(raw) > maxToolsBytes {
			return fmt.Errorf("tools exceed the %dKB limit", maxToolsBytes>>10)
		}
		if !jsonDepthAtMost(raw, maxToolJSONDepth) {
			return fmt.Errorf("tools exceed the %d-level nesting limit", maxToolJSONDepth)
		}
		var tools []json.RawMessage
		if err := json.Unmarshal(raw, &tools); err != nil {
			return fmt.Errorf("tools must be an array")
		}
		if len(tools) > maxTools {
			return fmt.Errorf("tools exceeds the %d-tool limit", maxTools)
		}
	}
	if raw, ok := doc["tool_choice"]; ok {
		if err := validateToolChoice(raw); err != nil {
			return err
		}
	}
	return nil
}

func validateResponseFormat(raw json.RawMessage) error {
	if len(raw) > maxResponseFormatBytes {
		return fmt.Errorf("response_format exceeds the %dKB limit", maxResponseFormatBytes>>10)
	}
	var format map[string]json.RawMessage
	if err := json.Unmarshal(raw, &format); err != nil {
		return errors.New("response_format must be an object")
	}
	typeRaw, ok := format["type"]
	if !ok || len(format) != 1 {
		return errors.New("response_format may contain only type")
	}
	var kind string
	if err := json.Unmarshal(typeRaw, &kind); err != nil || kind != "json_object" {
		return errors.New("only response_format type json_object is supported on this endpoint")
	}
	return nil
}

func validateToolChoice(raw json.RawMessage) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	if len(raw) > maxToolChoiceBytes || !jsonDepthAtMost(raw, maxToolJSONDepth) {
		return errors.New("tool_choice exceeds confidential endpoint limits")
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		if text == "auto" || text == "none" || text == "required" {
			return nil
		}
		return errors.New("tool_choice string must be auto, none, or required")
	}
	var choice map[string]json.RawMessage
	if err := json.Unmarshal(raw, &choice); err != nil || len(choice) != 2 {
		return errors.New("tool_choice must be a supported string or function selector")
	}
	var kind string
	var function map[string]json.RawMessage
	if err := json.Unmarshal(choice["type"], &kind); err != nil || kind != "function" || json.Unmarshal(choice["function"], &function) != nil || len(function) != 1 {
		return errors.New("tool_choice must select one named function")
	}
	var name string
	if err := json.Unmarshal(function["name"], &name); err != nil || name == "" || len(name) > 128 {
		return errors.New("tool_choice function name is invalid")
	}
	return nil
}

// jsonDepthAtMost is a byte-level preflight so deeply nested tool schemas do
// not reach a JSON decoder or the upstream runtime with unbounded recursion.
func jsonDepthAtMost(raw []byte, maximum int) bool {
	depth := 0
	inString, escaped := false, false
	for _, b := range raw {
		if inString {
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > maximum {
				return false
			}
		case '}', ']':
			depth--
		}
	}
	return depth == 0 && !inString
}
