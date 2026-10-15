package gate

import (
	"fmt"
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
