package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const testKid = "Ft_xbM9sJd-2OtTxhG1wg7qNk1xiSb_JzhcCsOv2MJY"

func testAugmenter(allowed ...string) *ModelsAugmenter {
	jwk := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x":   "ywO8Ki0SQfE7voSQGI-XmES2HhS0ci-0CMCB2nwk_eQ",
		"y":   "M54SOaRg-3jxlGc1vh1yzvOJKOcncy3IHTMY9a-s4fE",
		"kid": testKid,
	}
	a := &ModelsAugmenter{
		AttestationURL:  "https://cc-api.adverserial.ai/attestation",
		VerificationURL: "https://verify.adverserial.ai",
		ReceiptIssuer:   "https://verify.adverserial.ai",
		ReceiptAudience: "cc-chat.adverserial.ai",
		TrustedKeys:     map[string]any{testKid: jwk},
		Endpoint:        "https://cc-api.adverserial.ai",
		ModelDigest:     "sha256:modeldigest",
		RuntimeDigest:   "sha256:runtimedigest",
	}
	if allowed != nil {
		a.Allowed = map[string]bool{}
		for _, id := range allowed {
			a.Allowed[id] = true
		}
	}
	return a
}

const modelsDoc = `{"object":"list","data":[` +
	`{"id":"lordx64/cyberglm","object":"model","created":1,"owned_by":"adverserial","info":{"meta":{"existing":true}}},` +
	`{"id":"other/model","object":"model","created":2,"owned_by":"vendor"}` +
	`]}`

// startPair boots a fake upstream returning body for GET /v1/models and a
// front proxy with the given augmenter.
func startPair(t *testing.T, aug *ModelsAugmenter, upstreamHandler http.HandlerFunc) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	u, _ := url.Parse(upstream.URL)
	front := httptest.NewServer(Logging(logger, New(u, logger, aug, nil)))
	t.Cleanup(front.Close)
	return front, &logBuf
}

func getModels(t *testing.T, front *httptest.Server) (int, []byte) {
	t.Helper()
	resp, err := http.Get(front.URL + "/v1/models")
	if err != nil {
		t.Fatalf("GET /v1/models: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, body
}

func modelMeta(t *testing.T, body []byte, id string) map[string]any {
	t.Helper()
	var doc struct {
		Data []struct {
			ID   string         `json:"id"`
			Info map[string]any `json:"info"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("models response is not JSON: %v\n%s", err, body)
	}
	for _, m := range doc.Data {
		if m.ID == id {
			if m.Info == nil {
				return nil
			}
			meta, _ := m.Info["meta"].(map[string]any)
			return meta
		}
	}
	t.Fatalf("model %q not in response", id)
	return nil
}

// TestModelsAugmentation: every listed model gains the meta block with the
// URLs and keys from proxy config; pre-existing meta keys survive; no content
// appears in logs.
func TestModelsAugmentation(t *testing.T) {
	const marker = "MARKER-model-body-never-logged"
	front, logBuf := startPair(t, testAugmenter(), func(w http.ResponseWriter, r *http.Request) {
		if ac := r.Header.Get("Accept-Encoding"); ac != "" {
			t.Errorf("Accept-Encoding should be stripped for /v1/models, got %q", ac)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"orig-etag"`)
		// A marker inside the body proves content is not logged.
		_, _ = w.Write([]byte(strings.Replace(modelsDoc, `"created":1`, `"created":1,"note":"`+marker+`"`, 1)))
	})

	status, body := getModels(t, front)
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}

	meta := modelMeta(t, body, "lordx64/cyberglm")
	if meta["existing"] != true {
		t.Errorf("pre-existing meta key lost: %v", meta)
	}
	cv, ok := meta["confidential_verification"].(map[string]any)
	if !ok {
		t.Fatalf("confidential_verification missing: %v", meta)
	}
	if cv["attestation_url"] != "https://cc-api.adverserial.ai/attestation" ||
		cv["verification_url"] != "https://verify.adverserial.ai" ||
		cv["receipt_issuer"] != "https://verify.adverserial.ai" ||
		cv["receipt_audience"] != "cc-chat.adverserial.ai" {
		t.Errorf("cv block = %v", cv)
	}
	keys, ok := cv["trusted_receipt_keys"].(map[string]any)
	if !ok || keys[testKid] == nil {
		t.Errorf("trusted_receipt_keys = %v", cv["trusted_receipt_keys"])
	}
	expected, ok := cv["expected"].(map[string]any)
	if !ok {
		t.Fatal("expected block missing")
	}
	if expected["model_id"] != "lordx64/cyberglm" ||
		expected["endpoint"] != "https://cc-api.adverserial.ai" ||
		expected["model_digest"] != "sha256:modeldigest" ||
		expected["runtime_digest"] != "sha256:runtimedigest" {
		t.Errorf("expected = %v", expected)
	}

	// Unfiltered: the second model is augmented too, with its own id.
	meta2 := modelMeta(t, body, "other/model")
	cv2, ok := meta2["confidential_verification"].(map[string]any)
	if !ok {
		t.Fatalf("second model not augmented: %v", meta2)
	}
	if exp2 := cv2["expected"].(map[string]any); exp2["model_id"] != "other/model" {
		t.Errorf("second model expected.model_id = %v", exp2["model_id"])
	}

	if strings.Contains(logBuf.String(), marker) {
		t.Fatalf("models body leaked into logs:\n%s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "path=/v1/models") {
		t.Errorf("expected metadata log line, got:\n%s", logBuf.String())
	}
}

// TestModelsAugmentationFilter: with ATTESTED_MODELS set, only listed models
// gain the block; others pass through untouched.
func TestModelsAugmentationFilter(t *testing.T) {
	front, _ := startPair(t, testAugmenter("lordx64/cyberglm"), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(modelsDoc))
	})

	_, body := getModels(t, front)
	if meta := modelMeta(t, body, "lordx64/cyberglm"); meta["confidential_verification"] == nil {
		t.Error("listed model not augmented")
	}
	if meta := modelMeta(t, body, "other/model"); meta != nil {
		t.Errorf("non-listed model must be untouched, got meta %v", meta)
	}
}

// TestModelsUpstreamErrorPassthrough: upstream failures pass through
// byte-identical — status, body, and no injection.
func TestModelsUpstreamErrorPassthrough(t *testing.T) {
	const errBody = `{"error":"model backend down"}`
	front, _ := startPair(t, testAugmenter(), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(errBody))
	})

	status, body := getModels(t, front)
	if status != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", status)
	}
	if string(body) != errBody {
		t.Errorf("body = %s, want verbatim %s", body, errBody)
	}
}

// TestModelsNonJSONPassthrough: malformed JSON passes through unchanged.
func TestModelsNonJSONPassthrough(t *testing.T) {
	const garbage = `this is not json`
	front, _ := startPair(t, testAugmenter(), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(garbage))
	})
	status, body := getModels(t, front)
	if status != http.StatusOK || string(body) != garbage {
		t.Errorf("got %d %q", status, body)
	}
}

// TestOtherResponsesUntouched: a JSON body with a "data" array on another
// route must pass through byte-identical, and POST /v1/models is untouched.
func TestOtherResponsesUntouched(t *testing.T) {
	const otherDoc = `{"data":[{"id":"x","info":{}}]}`
	front, _ := startPair(t, testAugmenter(), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(otherDoc))
	})

	for _, target := range []struct{ method, path string }{
		{http.MethodGet, "/v1/chat/completions"},
		{http.MethodGet, "/v1/models/"},
		{http.MethodPost, "/v1/models"},
	} {
		req, _ := http.NewRequest(target.method, front.URL+target.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", target.method, target.path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != otherDoc {
			t.Errorf("%s %s: body modified: %s", target.method, target.path, body)
		}
	}
}

// TestAugmentIdempotentOnEmptyAndMissingData covers Augment edge cases
// directly.
func TestAugmentIdempotentOnEmptyAndMissingData(t *testing.T) {
	aug := testAugmenter()
	for _, in := range []string{
		`{}`,
		`{"object":"list"}`,
		`{"data":[]}`,
		`{"data":[{"object":"model"}]}`, // no id
		`{"data":["just-a-string"]}`,
	} {
		if out := aug.Augment([]byte(in)); string(out) != in {
			t.Errorf("Augment(%s) = %s, want unchanged", in, out)
		}
	}
}
