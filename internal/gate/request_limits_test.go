package gate

import "testing"

func TestParseRequestLimitsConfidentialStrict(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
		maxOut  int
	}{
		{"plain max_tokens", `{"model":"m/x","max_tokens":64}`, false, 64},
		{"max_completion_tokens counts", `{"model":"m/x","max_tokens":1,"max_completion_tokens":128}`, false, 128},
		{"max_output_tokens counts", `{"model":"m/x","max_tokens":1,"max_output_tokens":128}`, false, 128},
		{"max of all three", `{"model":"m/x","max_tokens":5,"max_completion_tokens":128,"max_output_tokens":64}`, false, 128},
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
			model, maxOut, err := parseRequestLimits(true, []byte(tc.body))
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

func TestParseRequestLimitsLegacyLenient(t *testing.T) {
	// Legacy mode keeps the old last-wins, case-insensitive behavior.
	model, maxOut, err := parseRequestLimits(false, []byte(`{"Model":"m/x","max_tokens":1,"max_tokens":64}`))
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
		if _, _, err := parseRequestLimits(true, []byte(body)); err == nil {
			t.Errorf("must reject fan-out: %s", body)
		}
	}
	for _, body := range []string{
		`{"model":"m/x","max_tokens":16,"n":1}`,
		`{"model":"m/x","max_tokens":16,"best_of":1}`,
		`{"model":"m/x","max_tokens":16}`,
	} {
		if _, _, err := parseRequestLimits(true, []byte(body)); err != nil {
			t.Errorf("must accept %s: %v", body, err)
		}
	}
}
