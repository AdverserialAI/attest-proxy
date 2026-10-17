package gate

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseRequestLimitsConfidentialStrict(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
		maxOut  int
	}{
		{"plain max_tokens", `{"model":"m/x","max_tokens":64}`, false, 64},
		{"max_completion_tokens counts", `{"model":"m/x","max_tokens":1,"max_completion_tokens":128}`, false, 128},
		{"exact duplicate key", `{"model":"m/x","max_tokens":1,"max_tokens":64}`, true, 0},
		{"case-variant duplicate", `{"model":"m/x","max_tokens":64,"MAX_TOKENS":1}`, true, 0},
		{"case-variant model dup", `{"model":"m/x","Model":"m/x","max_tokens":1}`, true, 0},
		{"chat_template rejected", `{"model":"m/x","max_tokens":1,"chat_template":"{{ x }}"}`, true, 0},
		{"chat_template any case", `{"model":"m/x","max_tokens":1,"Chat_Template":"{{ x }}"}`, true, 0},
		{"string max rejected", `{"model":"m/x","max_tokens":"64"}`, true, 0},
		{"float max rejected", `{"model":"m/x","max_tokens":64.5}`, true, 0},
		{"zero max rejected", `{"model":"m/x","max_tokens":0}`, true, 0},
		{"negative max rejected", `{"model":"m/x","max_tokens":-3}`, true, 0},
		{"no limits = -1", `{"model":"m/x"}`, false, -1},
		{"nested dup unaffected", `{"model":"m/x","max_tokens":1,"messages":[{"role":"user","content":"a"},{"role":"user","content":"b"}]}`, false, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			model, maxOut, err := parseRequestLimits(true, "/v1/chat/completions", []byte(tc.body))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got model=%q maxOut=%d", model, maxOut)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if maxOut != tc.maxOut {
				t.Errorf("maxOut = %d, want %d", maxOut, tc.maxOut)
			}
			if model != "m/x" {
				t.Errorf("model = %q", model)
			}
		})
	}
}

func TestConfidentialConversationLimits(t *testing.T) {
	valid := `{"model":"m/x","max_tokens":8,"messages":[{"role":"system","content":"rules"},{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"f","arguments":"{}"}}]},{"role":"tool","tool_call_id":"call_1","content":"ok"}]}`
	if _, _, err := parseRequestLimits(true, "/v1/chat/completions", []byte(valid)); err != nil {
		t.Fatalf("supported text and tool-call conversation rejected: %v", err)
	}
	tooMany := `{"model":"m/x","max_tokens":8,"messages":[` + strings.Repeat(`{"role":"user","content":"x"},`, maxConversationItems) + `{"role":"user","content":"x"}]}`
	for name, body := range map[string]string{
		"too many messages": tooMany,
		"media content":     `{"model":"m/x","max_tokens":8,"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid/a"}}]}]}`,
		"unknown role":      `{"model":"m/x","max_tokens":8,"messages":[{"role":"operator","content":"x"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseRequestLimits(true, "/v1/chat/completions", []byte(body)); err == nil {
				t.Fatal("must reject unsafe conversation shape")
			}
		})
	}
}

func TestConfidentialResponsesInputLimits(t *testing.T) {
	for _, body := range []string{
		`{"model":"m/x","max_output_tokens":8,"input":"hello"}`,
		`{"model":"m/x","max_output_tokens":8,"input":[{"role":"user","content":"hello"}]}`,
	} {
		if _, _, err := parseRequestLimits(true, "/v1/responses", []byte(body)); err != nil {
			t.Errorf("must accept bounded responses input: %v", err)
		}
	}
	if _, _, err := parseRequestLimits(true, "/v1/responses", []byte(`{"model":"m/x","max_output_tokens":8,"input":null}`)); err == nil {
		t.Fatal("must reject null responses input")
	}
}

func TestParseRequestLimitsUsesEndpointSpecificOutputLimits(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
		want int
		bad  bool
	}{
		{"chat max tokens", "/v1/chat/completions", `{"model":"m/x","max_tokens":128}`, 128, false},
		{"chat max completion tokens", "/v1/chat/completions", `{"model":"m/x","max_completion_tokens":128}`, 128, false},
		{"responses max output tokens", "/v1/responses", `{"model":"m/x","max_output_tokens":128}`, 128, false},
		// SGLang ignores these cross-endpoint spellings. Reject them rather
		// than binding an ignored small number into the entitlement.
		{"chat rejects responses spelling", "/v1/chat/completions", `{"model":"m/x","max_output_tokens":1}`, 0, true},
		{"responses rejects chat max tokens", "/v1/responses", `{"model":"m/x","max_tokens":1}`, 0, true},
		{"responses rejects chat completion spelling", "/v1/responses", `{"model":"m/x","max_completion_tokens":1}`, 0, true},
		{"chat rejects native max new tokens", "/v1/chat/completions", `{"model":"m/x","max_new_tokens":1}`, 0, true},
		{"unknown path rejected", "/v1/anything", `{"model":"m/x","max_tokens":1}`, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, got, err := parseRequestLimits(true, tc.path, []byte(tc.body))
			if tc.bad {
				if err == nil {
					t.Fatal("expected rejection")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("maxOut=%d, want %d", got, tc.want)
			}
		})
	}
}

func TestConfidentialSamplerControlsAreBounded(t *testing.T) {
	accept := []string{
		`{"model":"m/x","max_tokens":64,"logprobs":true,"top_logprobs":20,"top_k":1024,"min_tokens":64}`,
		`{"model":"m/x","max_tokens":64,"logprobs":false,"top_logprobs":0,"top_k":-1,"min_tokens":0}`,
	}
	for _, body := range accept {
		if _, _, err := parseRequestLimits(true, "/v1/chat/completions", []byte(body)); err != nil {
			t.Errorf("must accept bounded sampling controls %s: %v", body, err)
		}
	}

	reject := []string{
		// SGLang scheduler crash / response-amplification boundaries.
		`{"model":"m/x","max_tokens":64,"top_logprobs":21}`,
		`{"model":"m/x","max_tokens":64,"top_logprobs":1000000}`,
		`{"model":"m/x","max_tokens":64,"top_logprobs":1.5}`,
		`{"model":"m/x","max_tokens":64,"logprobs":1000000}`,
		`{"model":"m/x","max_tokens":64,"logprobs":null}`,
		`{"model":"m/x","max_tokens":64,"top_logprobs":null}`,
		`{"model":"m/x","max_tokens":64,"top_k":1025}`,
		`{"model":"m/x","max_tokens":64,"top_k":0}`,
		`{"model":"m/x","max_tokens":64,"top_k":-2}`,
		`{"model":"m/x","max_tokens":64,"top_k":1.5}`,
		`{"model":"m/x","max_tokens":64,"min_tokens":65}`,
		// Native compatibility fields that can reach unbounded token-id work.
		`{"model":"m/x","max_tokens":64,"input_ids":[1000000000]}`,
		`{"model":"m/x","max_tokens":64,"stop_token_ids":[1000000000]}`,
		`{"model":"m/x","max_tokens":64,"token_ids_logprob":[1000000000]}`,
		`{"model":"m/x","max_tokens":64,"top_logprobs_num":1000000}`,
		`{"model":"m/x","max_tokens":64,"min_new_tokens":1}`,
		`{"model":"m/x","max_tokens":64,"parallel_sample_num":64}`,
		// Case variants cannot bypass the edge check or create a parser split.
		`{"model":"m/x","max_tokens":64,"Top_Logprobs":1000000}`,
		`{"model":"m/x","max_tokens":64,"top_k":1,"TOP_K":1000000}`,
	}
	for _, body := range reject {
		if _, _, err := parseRequestLimits(true, "/v1/chat/completions", []byte(body)); err == nil {
			t.Errorf("must reject unsafe sampling control: %s", body)
		}
	}
	// Every explicitly disallowed internal/diagnostic control must fail closed
	// even when it is null. This prevents a new SGLang image from treating a
	// previously ignored field as an enabled feature without a proxy review.
	for key := range unsafeConfidentialKeys {
		body := fmt.Sprintf(`{"model":"m/x","max_tokens":64,%q:null}`, key)
		if _, _, err := parseRequestLimits(true, "/v1/chat/completions", []byte(body)); err == nil {
			t.Errorf("must reject unsafe control %q", key)
		}
	}
}

func TestParseRequestLimitsLegacyLenient(t *testing.T) {
	// Legacy mode keeps the old last-wins, case-insensitive behavior.
	model, maxOut, err := parseRequestLimits(false, "/v1/chat/completions", []byte(`{"Model":"m/x","max_tokens":1,"max_tokens":64}`))
	if err != nil {
		t.Fatal(err)
	}
	if model != "m/x" || maxOut != 64 {
		t.Errorf("legacy parse = %q/%d, want m/x/64", model, maxOut)
	}
}

func TestParseRequestLimitsRejectsDeeplyNestedJSON(t *testing.T) {
	body := `{"model":"m/x","max_tokens":8,"messages":` + nestedJSON(maxRequestJSONDepth) + `}`
	if _, _, err := parseRequestLimits(true, "/v1/chat/completions", []byte(body)); err == nil {
		t.Fatal("must reject request JSON at the nesting limit once its wrapper is included")
	}
}

func TestFanoutMultiplicityRejected(t *testing.T) {
	reject := []string{
		`{"model":"m/x","max_tokens":16,"n":64}`,
		`{"model":"m/x","max_tokens":16,"n":2}`,
		`{"model":"m/x","max_tokens":16,"best_of":4}`,
		`{"model":"m/x","max_tokens":16,"n":"64"}`,
	}
	for _, body := range reject {
		if _, _, err := parseRequestLimits(true, "/v1/chat/completions", []byte(body)); err == nil {
			t.Errorf("must reject fan-out: %s", body)
		}
	}
	for _, body := range []string{
		`{"model":"m/x","max_tokens":16,"n":1}`,
		`{"model":"m/x","max_tokens":16,"best_of":1}`,
		`{"model":"m/x","max_tokens":16}`,
	} {
		if _, _, err := parseRequestLimits(true, "/v1/chat/completions", []byte(body)); err != nil {
			t.Errorf("must accept %s: %v", body, err)
		}
	}
}

func TestPayloadBoundsRC26(t *testing.T) {
	reject := []struct{ name, body string }{
		{"ebnf rejected", `{"model":"m/x","max_tokens":8,"ebnf":"root ::= 'a'"}`},
		{"guided_grammar rejected", `{"model":"m/x","max_tokens":8,"guided_grammar":"x"}`},
		{"regex rejected", `{"model":"m/x","max_tokens":8,"regex":".*"}`},
		{"json schema rejected", `{"model":"m/x","max_tokens":8,"response_format":{"type":"json_schema","json_schema":{"name":"x"}}}`},
		{"sampling_params passthrough rejected", `{"model":"m/x","max_tokens":8,"sampling_params":{"top_k":1}}`},
		{"huge logit_bias", `{"model":"m/x","max_tokens":8,"logit_bias":{` + bigBias(150) + `}}`},
		{"logit_bias bad value", `{"model":"m/x","max_tokens":8,"logit_bias":{"12":999}}`},
		{"logit_bias bad token id", `{"model":"m/x","max_tokens":8,"logit_bias":{"notanum":1}}`},
		{"logit_bias trailing text", `{"model":"m/x","max_tokens":8,"logit_bias":{"12junk":1}}`},
		{"stop flood", `{"model":"m/x","max_tokens":8,"stop":["a","b","c","d","e","f","g","h","i"]}`},
		{"tools flood", `{"model":"m/x","max_tokens":8,"tools":` + bigTools(65) + `}`},
		{"tool choice invalid", `{"model":"m/x","max_tokens":8,"tool_choice":"all"}`},
		{"tool choice deep nesting", `{"model":"m/x","max_tokens":8,"tool_choice":` + nestedJSON(22) + `}`},
	}
	for _, tc := range reject {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseRequestLimits(true, "/v1/chat/completions", []byte(tc.body)); err == nil {
				t.Errorf("must reject: %s", tc.body[:min(60, len(tc.body))])
			}
		})
	}
	allow := []struct{ name, body string }{
		{"json_object mode", `{"model":"m/x","max_tokens":8,"response_format":{"type":"json_object"}}`},
		{"small logit_bias", `{"model":"m/x","max_tokens":8,"logit_bias":{"12":-10,"34":5}}`},
		{"few stops", `{"model":"m/x","max_tokens":8,"stop":["END","DONE"]}`},
		{"one tool", `{"model":"m/x","max_tokens":8,"tools":[{"type":"function","function":{"name":"f"}}]}`},
		{"auto tool choice", `{"model":"m/x","max_tokens":8,"tool_choice":"auto"}`},
		{"named function tool choice", `{"model":"m/x","max_tokens":8,"tool_choice":{"type":"function","function":{"name":"f"}}}`},
	}
	for _, tc := range allow {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseRequestLimits(true, "/v1/chat/completions", []byte(tc.body)); err != nil {
				t.Errorf("must accept %s: %v", tc.name, err)
			}
		})
	}
}

func bigBias(n int) string {
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		parts = append(parts, `"`+string(rune('0'+i%10))+`x`+strings.Repeat("1", i/10)+`":1`)
	}
	return strings.Join(parts, ",")
}

func bigTools(n int) string {
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		parts = append(parts, `{"type":"function","function":{"name":"f"}}`)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func nestedJSON(depth int) string {
	return strings.Repeat(`{"x":`, depth) + `0` + strings.Repeat(`}`, depth)
}
