package gate

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Harness compatibility suite: the exact payload shapes the supported agentic
// harnesses (kimi-code, claude-code, codex, opencode) send through the
// confidential gate. rc.26 broke these twice (string-only content, a
// 64-message ceiling); this file pins admission for the real shapes and the
// continued rejection of the unsafe ones, so a payload-bound change can never
// silently lock out harness traffic again.

// harnessClaims builds entitlement claims with harness-scale bounds: the gate
// requires clientBodyLen <= max_input_tokens and max_tokens <=
// max_output_tokens, and production entitlements carry up to billing's 6 MiB
// input cap.
func harnessClaims(jti string, now time.Time) map[string]any {
	return map[string]any{
		"iss": "https://billing.adverserial.ai", "aud": "https://api.adverserial.ai",
		"typ": "adverserial-confidential-entitlement/v1", "jti": jti,
		"model": "lordx64/cyberglm", "max_input_tokens": 8 << 20, "max_output_tokens": 1 << 20,
		"max_requests": 1, "cnf": map[string]string{"tls_spki_sha256": startTestSPKI},
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	}
}

// agenticHistory builds an n-message alternating user/assistant history with
// array-shaped text content (the harness default), sprinkling a tool-call
// round trip every fourth pair.
func agenticHistory(n int) string {
	var b strings.Builder
	b.WriteString(`[{"role":"system","content":[{"type":"text","text":"You are an agentic coding assistant."}]}`)
	remaining := n - 1
	toolSeq := 0
	for remaining > 0 {
		if remaining >= 3 && toolSeq%2 == 0 {
			b.WriteString(fmt.Sprintf(`,{"role":"assistant","content":null,"tool_calls":[{"id":"call_%d","type":"function","function":{"name":"Bash","arguments":"{\"command\":\"ls\"}"}}]}`, toolSeq))
			b.WriteString(fmt.Sprintf(`,{"role":"tool","tool_call_id":"call_%d","content":"main.go\nREADME.md"}`, toolSeq))
			remaining -= 2
		} else {
			b.WriteString(fmt.Sprintf(`,{"role":"user","content":[{"type":"text","text":"turn %d: please continue"}]}`, remaining))
			remaining--
		}
		if remaining > 0 {
			b.WriteString(fmt.Sprintf(`,{"role":"assistant","reasoning_content":"thinking about turn %d","content":[{"type":"text","text":"done with turn %d"}]}`, remaining, remaining))
			remaining--
		}
		toolSeq++
	}
	b.WriteString("]")
	return b.String()
}

func TestHarnessCompatAdmission(t *testing.T) {
	stub := &startStub{resp: `{"stored":true,"started":false}`}
	bs := stub.server()
	defer bs.Close()
	g, private, now := newStartGate(t, bs.URL)
	g.UpstreamReady = func() bool { return true }
	up := &countingHandler{t: t}
	h := g.Middleware(up.handler())

	kimiTurn := `{
		"model": "lordx64/cyberglm",
		"max_tokens": 8192,
		"stream": true,
		"stream_options": {"include_usage": true},
		"temperature": 0.6,
		"top_p": 0.95,
		"messages": [
			{"role": "system", "content": [{"type": "text", "text": "You are Kimi Code, a coding assistant."}]},
			{"role": "user", "content": [{"type": "text", "text": "hey there"}]}
		]
	}`

	claudeToolTurn := `{
		"model": "lordx64/cyberglm",
		"max_tokens": 4096,
		"stream": true,
		"stream_options": {"include_usage": true},
		"messages": [
			{"role": "system", "content": [{"type":"text","text":"You are an agentic coding assistant."}]},
			{"role": "user", "content": [{"type": "text", "text": "list the files here"}]},
			{"role": "assistant", "content": null, "tool_calls": [{"id":"call_1","type":"function","function":{"name":"Bash","arguments":"{\"command\":\"ls\"}"}}]},
			{"role": "tool", "tool_call_id": "call_1", "content": "main.go\nREADME.md"},
			{"role": "user", "content": [{"type":"text","text":"thanks"}]}
		],
		"tools": [
			{"type":"function","function":{"name":"Bash","description":"Run a shell command","parameters":{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}}},
			{"type":"function","function":{"name":"Read","description":"Read a file","parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}},
			{"type":"function","function":{"name":"Edit","description":"Edit a file","parameters":{"type":"object","properties":{"path":{"type":"string"},"old_string":{"type":"string"},"new_string":{"type":"string"}},"required":["path","old_string","new_string"]}}}
		],
		"tool_choice": "auto"
	}`

	codexTurn := `{
		"model": "lordx64/cyberglm",
		"max_completion_tokens": 2048,
		"messages": [
			{"role": "developer", "content": [{"type":"text","text":"Follow the repository conventions."}]},
			{"role": "user", "content": [{"type":"text","text":"add a helper"}]}
		]
	}`

	plainStrings := `{
		"model": "lordx64/cyberglm",
		"max_tokens": 1024,
		"messages": [
			{"role": "system", "content": "You are helpful."},
			{"role": "user", "content": "hi"},
			{"role": "assistant", "content": "hello!"},
			{"role": "user", "content": "again"}
		]
	}`

	accepted := []struct {
		name string
		path string
		body string
	}{
		{"kimi-code streaming turn (array content parts)", "/v1/chat/completions", kimiTurn},
		{"claude-code tool-call round trip", "/v1/chat/completions", claudeToolTurn},
		{"codex/opencode developer role + max_completion_tokens", "/v1/chat/completions", codexTurn},
		{"plain string content (legacy clients)", "/v1/chat/completions", plainStrings},
		{"128-message agentic history", "/v1/chat/completions",
			`{"model":"lordx64/cyberglm","max_tokens":8192,"stream":true,"messages":` + agenticHistory(128) + `}`},
		{"512-message boundary history", "/v1/chat/completions",
			`{"model":"lordx64/cyberglm","max_tokens":8192,"messages":` + agenticHistory(512) + `}`},
		{"responses API string input", "/v1/responses",
			`{"model":"lordx64/cyberglm","max_output_tokens":64,"input":"what is 2+2"}`},
		{"responses API items input", "/v1/responses",
			`{"model":"lordx64/cyberglm","max_output_tokens":64,"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]}`},
	}

	for i, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			beforeHits := up.hits.Load()
			beforeStarts := stub.calls.Load()
			token := signedEntitlement(t, private, "billing", harnessClaims(fmt.Sprintf("harness-ok-%d", i), now))
			rec := postPath(t, h, token, tc.path, tc.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("harness payload rejected: status=%d body=%s", rec.Code, rec.Body.String())
			}
			if up.hits.Load() != beforeHits+1 {
				t.Errorf("upstream hits did not increase (%d -> %d)", beforeHits, up.hits.Load())
			}
			if stub.calls.Load() != beforeStarts+1 {
				t.Errorf("start calls did not increase (%d -> %d)", beforeStarts, stub.calls.Load())
			}
		})
	}

	// The kimi-code shape must arrive upstream with include_usage injected even
	// when the client only asked for stream:true (terminal usage chunk drives
	// settlement).
	t.Run("stream without stream_options gets include_usage injected", func(t *testing.T) {
		body := `{"model":"lordx64/cyberglm","max_tokens":64,"stream":true,"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`
		token := signedEntitlement(t, private, "billing", harnessClaims("harness-inject", now))
		rec := postChat(t, h, token, body)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		echo := rec.Body.String()
		if !strings.Contains(echo, `"include_usage":true`) {
			t.Errorf("upstream body lacks injected include_usage: %s", echo)
		}
	})

	// The exact toolset kimi-code 2.x sends on every turn: 26 built-in tools
	// whose schemas serialize to ~77 KB — captured from a live kimi-code
	// request (testdata/kimi_code_tools.json). rc.26's 64 KB tools byte cap
	// rejected every real kimi-code turn; pin the genuine payload so the cap
	// can never silently drop below harness reality again.
	t.Run("kimi-code captured 26-tool payload admitted", func(t *testing.T) {
		tools, err := os.ReadFile("testdata/kimi_code_tools.json")
		if err != nil {
			t.Fatal(err)
		}
		body := `{"model":"lordx64/cyberglm","max_tokens":4096,"stream":true,` +
			`"stream_options":{"include_usage":true},"reasoning_effort":"max","prompt_cache_key":"sess-1",` +
			`"messages":[{"role":"system","content":[{"type":"text","text":"You are Kimi Code."}]},` +
			`{"role":"user","content":[{"type":"text","text":"say ok"}]}],"tools":` + string(tools) + `}`
		token := signedEntitlement(t, private, "billing", harnessClaims("harness-kimi-tools", now))
		rec := postChat(t, h, token, body)
		if rec.Code != http.StatusOK {
			t.Fatalf("captured kimi-code payload rejected: status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
}

// TestHarnessCompatRejects pins the unsafe shapes that must stay rejected
// after the harness-compat fix: media parts, runaway cardinalities, and
// malformed content. None of them may consume an entitlement, register a
// dispatch, or reach the upstream.
func TestHarnessCompatRejects(t *testing.T) {
	stub := &startStub{resp: `{"stored":true,"started":false}`}
	bs := stub.server()
	defer bs.Close()
	g, private, now := newStartGate(t, bs.URL)
	g.UpstreamReady = func() bool { return true }
	up := &countingHandler{t: t}
	h := g.Middleware(up.handler())

	manyParts := `{"role":"user","content":[` + strings.Repeat(`{"type":"text","text":"x"},`, 32) + `{"type":"text","text":"x"}]}`

	rejected := []struct {
		name string
		path string
		body string
	}{
		{"media content part (image_url)", "/v1/chat/completions",
			`{"model":"lordx64/cyberglm","max_tokens":8,"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid/a"}}]}]}`},
		{"media content part (base64 data uri)", "/v1/chat/completions",
			`{"model":"lordx64/cyberglm","max_tokens":8,"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]}]}`},
		{"513 messages", "/v1/chat/completions",
			`{"model":"lordx64/cyberglm","max_tokens":8,"messages":` + agenticHistory(513) + `}`},
		{"empty messages array", "/v1/chat/completions",
			`{"model":"lordx64/cyberglm","max_tokens":8,"messages":[]}`},
		{"33 content parts in one message", "/v1/chat/completions",
			`{"model":"lordx64/cyberglm","max_tokens":8,"messages":[` + manyParts + `]}`},
		{"content part without type", "/v1/chat/completions",
			`{"model":"lordx64/cyberglm","max_tokens":8,"messages":[{"role":"user","content":[{"text":"hi"}]}]}`},
		{"text part without text string", "/v1/chat/completions",
			`{"model":"lordx64/cyberglm","max_tokens":8,"messages":[{"role":"user","content":[{"type":"text"}]}]}`},
		{"non-object content part", "/v1/chat/completions",
			`{"model":"lordx64/cyberglm","max_tokens":8,"messages":[{"role":"user","content":["hi"]}]}`},
		{"numeric content", "/v1/chat/completions",
			`{"model":"lordx64/cyberglm","max_tokens":8,"messages":[{"role":"user","content":42}]}`},
		{"unsupported role", "/v1/chat/completions",
			`{"model":"lordx64/cyberglm","max_tokens":8,"messages":[{"role":"function","content":"hi"}]}`},
		{"responses input over 512 items", "/v1/responses",
			`{"model":"lordx64/cyberglm","max_output_tokens":8,"input":[` + strings.Repeat(`{"type":"message","role":"user","content":"x"},`, 512) + `{"type":"message","role":"user","content":"x"}]}`},
		{"tools over 256KB", "/v1/chat/completions",
			`{"model":"lordx64/cyberglm","max_tokens":8,"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","description":"` + strings.Repeat("y", 257<<10) + `"}}]}`},
		{"responses null input", "/v1/responses",
			`{"model":"lordx64/cyberglm","max_output_tokens":8,"input":null}`},
	}

	for i, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			beforeHits := up.hits.Load()
			beforeStarts := stub.calls.Load()
			token := signedEntitlement(t, private, "billing", harnessClaims(fmt.Sprintf("harness-bad-%d", i), now))
			rec := postPath(t, h, token, tc.path, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d, want 400 (body %s)", rec.Code, rec.Body.String())
			}
			if up.hits.Load() != beforeHits {
				t.Error("rejected payload reached the upstream")
			}
			if stub.calls.Load() != beforeStarts {
				t.Error("rejected payload registered a dispatch start")
			}
			if strings.Contains(rec.Body.String(), "prompt-content-marker") {
				t.Error("rejection reflected prompt content")
			}
		})
	}
}
