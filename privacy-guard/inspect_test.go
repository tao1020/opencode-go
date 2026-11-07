package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// scanOnlyGateway builds a gateway with no upstream: /inspect only.
func scanOnlyGateway(t *testing.T) *Gateway {
	t.Helper()
	gateway, err := NewGateway(Config{
		ClientAPIKey:   testClientKey,
		QueueTimeout:   testConfig("").QueueTimeout,
		ScanTimeout:    testConfig("").ScanTimeout,
		RequestTimeout: testConfig("").RequestTimeout,
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	return gateway
}

func postInspect(t *testing.T, handler http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/inspect", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testClientKey)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func decodeInspect(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("inspect response is not JSON: %v (%s)", err, recorder.Body.String())
	}
	return payload
}

func TestInspectCleanPayload(t *testing.T) {
	gateway := scanOnlyGateway(t)
	payload := `{` +
		`"messages":[` +
		`{"type":"text","text":"please read the file"},` +
		`{"type":"reasoning","text":"thinking about the task"},` +
		`{"type":"tool-call","name":"read","arguments":{"path":"notes.md"}}],` +
		`"tools":[{"name":"read","parameters":{"type":"object","properties":{"file":{"type":"string"},"image":{"type":"string"}}}}],` +
		`"toolHistory":[{"tool":"read","result":"done"}],` +
		`"replayState":{"cursor":"abc123","attempt":2}}`

	recorder := postInspect(t, gateway.Routes(), payload)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	response := decodeInspect(t, recorder)
	if response["clean"] != true {
		t.Fatalf("expected clean, got %v", response)
	}
	if response["findings"] != float64(0) {
		t.Fatalf("expected 0 findings, got %v", response["findings"])
	}
	if _, hasReason := response["reason"]; hasReason {
		t.Fatalf("clean response must omit reason: %v", response)
	}
}

func TestInspectContractIsExactAndTextFree(t *testing.T) {
	gateway := scanOnlyGateway(t)
	secret := "SuperSecret123!"
	payload := `{"messages":[{"type":"text","text":"password=` + secret + `"}],` +
		`"replayState":{"password":"` + secret + `"}}`

	recorder := postInspect(t, gateway.Routes(), payload)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	response := decodeInspect(t, recorder)

	allowed := map[string]bool{"version": true, "clean": true, "findings": true, "reason": true}
	for key := range response {
		if !allowed[key] {
			t.Fatalf("unexpected field %q in response: %v", key, response)
		}
	}
	if response["version"] != float64(1) {
		t.Fatalf("version = %v", response["version"])
	}
	if response["clean"] != false || response["reason"] != "secrets" {
		t.Fatalf("expected secrets, got %v", response)
	}
	if findings, ok := response["findings"].(float64); !ok || findings < 1 {
		t.Fatalf("findings must be a positive number, got %v", response["findings"])
	}
	if strings.Contains(recorder.Body.String(), secret) {
		t.Fatalf("response leaked the secret: %s", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "replayState") || strings.Contains(recorder.Body.String(), "password=") {
		t.Fatalf("response leaked payload text: %s", recorder.Body.String())
	}
}

func TestInspectFindsSecretsInReplayStateAndToolArguments(t *testing.T) {
	gateway := scanOnlyGateway(t)
	payload := `{"messages":[{"type":"tool-call","name":"bash","arguments":{"cmd":"export PGPASSWORD=supersecret123"}}],` +
		`"replayState":{"cursor":"ghp_16C7e42F292c6912E7710c838347Ae178B4a"}}`

	recorder := postInspect(t, gateway.Routes(), payload)
	response := decodeInspect(t, recorder)
	if response["clean"] != false || response["reason"] != "secrets" {
		t.Fatalf("expected secrets, got %v", response)
	}
	for _, secret := range []string{"supersecret123", "ghp_16C7e42F292c6912E7710c838347Ae178B4a"} {
		if strings.Contains(recorder.Body.String(), secret) {
			t.Fatalf("response leaked %q", secret)
		}
	}
}

func TestInspectSchemaWithFileAndImagePropertiesIsClean(t *testing.T) {
	gateway := scanOnlyGateway(t)
	payload := `{"tools":[{"name":"read","description":"Read a file from disk",` +
		`"parameters":{"type":"object","properties":{` +
		`"file":{"type":"string","description":"path to read"},` +
		`"image":{"type":"string","description":"image path"},` +
		`"image_url":{"type":"string","description":"a URL, still just text"}},` +
		`"required":["file"]}}]}`

	recorder := postInspect(t, gateway.Routes(), payload)
	response := decodeInspect(t, recorder)
	if response["clean"] != true {
		t.Fatalf("schema must not be treated as media: %v", response)
	}
	if response["findings"] != float64(0) {
		t.Fatalf("expected 0 findings, got %v", response["findings"])
	}
}

func TestInspectRealMediaIsUnsupported(t *testing.T) {
	cases := map[string]string{
		"image block":      `{"messages":[{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}`,
		"image type":       `{"messages":[{"type":"image","data":"AAAA"}]}`,
		"audio type":       `{"messages":[{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}]}`,
		"inline data uri":  `{"messages":[{"type":"text","text":"data:image/png;base64,AAAA"}]}`,
		"video attachment": `{"messages":[{"type":"video_url","video_url":{"url":"https://example.com/v.mp4"}}]}`,
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			recorder := postInspect(t, scanOnlyGateway(t).Routes(), payload)
			response := decodeInspect(t, recorder)
			if response["clean"] != false || response["reason"] != "unsupported" {
				t.Fatalf("expected unsupported, got %v", response)
			}
		})
	}
}

// DSH has no native upload: a file handle is text, not bytes.
func TestInspectFileHandleIsNotUnsupported(t *testing.T) {
	gateway := scanOnlyGateway(t)
	payload := `{"messages":[{"type":"tool-call","name":"read","arguments":{"file":"/tmp/notes.md","path":"notes.md"}}],"file":"/tmp/notes.md"}`
	response := decodeInspect(t, postInspect(t, gateway.Routes(), payload))
	if response["clean"] != true {
		t.Fatalf("file handle must not be unsupported: %v", response)
	}
}

func TestInspectUnknownBlockTypesAreUnsupported(t *testing.T) {
	gateway := scanOnlyGateway(t)

	// A typed block inside a block array that the guard does not understand
	// could carry bytes it cannot inspect, so it is refused.
	for _, payload := range []string{
		`{"messages":[{"type":"mystery","payload":"hello"}]}`,
		`{"messages":[{"type":"tool-output","payload":"hello"}]}`,
		`{"content":[{"type":"blob","data":"AAAA"}]}`,
	} {
		response := decodeInspect(t, postInspect(t, gateway.Routes(), payload))
		if response["clean"] != false || response["reason"] != "unsupported" {
			t.Fatalf("unknown block must be unsupported: %v (%s)", response, payload)
		}
	}

	// An unknown "type" in metadata (not a block array) is still fine.
	clean := decodeInspect(t, postInspect(t, gateway.Routes(), `{"replayState":{"type":"cursor","cursor":"abc"}}`))
	if clean["clean"] != true {
		t.Fatalf("metadata type must not be refused: %v", clean)
	}
}

func TestInspectRejectsBadInputWithoutDetails(t *testing.T) {
	gateway := scanOnlyGateway(t)

	for name, body := range map[string]string{
		"not json":      `{"model":`,
		"array root":    `[1,2,3]`,
		"trailing junk": `{"a":1} {}`,
		"duplicate key": `{"a":1,"a":2}`,
	} {
		t.Run(name, func(t *testing.T) {
			recorder := postInspect(t, gateway.Routes(), body)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", recorder.Code)
			}
			if strings.Contains(recorder.Body.String(), "a\":") {
				t.Fatalf("error body leaked input: %s", recorder.Body.String())
			}
		})
	}
}

func TestInspectRequiresAuthAndSizeLimit(t *testing.T) {
	gateway := scanOnlyGateway(t)
	handler := gateway.Routes()

	unauthenticated := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/inspect", strings.NewReader(`{"messages":[]}`))
	handler.ServeHTTP(unauthenticated, request)
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", unauthenticated.Code)
	}

	huge := `{"messages":[{"type":"text","text":"` + strings.Repeat("a", int(defaultMaxBody)+1024) + `"}]}`
	if recorder := postInspect(t, handler, huge); recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", recorder.Code)
	}
}

func TestInspectScannerFailureReturnsGenericError(t *testing.T) {
	gateway := scanOnlyGateway(t)
	gateway.redactor = failingRedactor{err: errors.New("scanner boom")}

	recorder := postInspect(t, gateway.Routes(), `{"messages":[{"type":"text","text":"hello"}]}`)
	if recorder.Code < 500 {
		t.Fatalf("expected 5xx, got %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "boom") {
		t.Fatalf("scanner detail leaked: %s", recorder.Body.String())
	}
}

func TestScanOnlyModeDisablesChatProxy(t *testing.T) {
	gateway := scanOnlyGateway(t)
	handler := gateway.Routes()

	recorder := postChat(t, handler, `{"model":"m","messages":[]}`, testClientKey)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for chat in scan-only mode, got %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "scan-only") {
		t.Fatalf("unexpected body: %s", recorder.Body.String())
	}

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if !strings.Contains(health.Body.String(), "scan-only") {
		t.Fatalf("healthz should report scan-only mode: %s", health.Body.String())
	}
}

// A schema property named "password" must not turn its own type/description into
// credentials; only default/enum/examples literals are sensitive.
func TestInspectSchemaPasswordPropertyIsNotAFinding(t *testing.T) {
	gateway := scanOnlyGateway(t)
	payload := `{"tools":[{"name":"login","parameters":{"type":"object","properties":{` +
		`"password":{"type":"string","description":"the account password"},` +
		`"user":{"type":"string"}}},"required":["user","password"]}],` +
		`"messages":[{"type":"text","text":"call login with user and password"}]}`

	response := decodeInspect(t, postInspect(t, gateway.Routes(), payload))
	if response["clean"] != true || response["findings"] != float64(0) {
		t.Fatalf("schema password property produced findings: %v", response)
	}
}

func TestInspectCountsShortAndNumericCredentials(t *testing.T) {
	gateway := scanOnlyGateway(t)

	for name, payload := range map[string]string{
		"numeric password": `{"replayState":{"password":123456}}`,
		"short password":   `{"replayState":{"password":"abc"}}`,
		"short api key":    `{"replayState":{"api_key":"xy"}}`,
		"schema default":   `{"tools":[{"name":"t","parameters":{"properties":{"password":{"type":"string","default":"abc"}}}}]}`,
		"schema enum":      `{"tools":[{"name":"t","parameters":{"properties":{"password":{"type":"string","enum":["abcd"]}}}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			response := decodeInspect(t, postInspect(t, gateway.Routes(), payload))
			if response["clean"] != false || response["reason"] != "secrets" {
				t.Fatalf("expected secrets, got %v", response)
			}
		})
	}
}

// /inspect must also flag short contextual quoted passwords (the proxy refuses
// them, so the preflight must predict that).
func TestInspectCountsShortContextualSecrets(t *testing.T) {
	gateway := scanOnlyGateway(t)
	for _, secret := range []string{"abc", "xy", "7", "a"} {
		t.Run(secret, func(t *testing.T) {
			payload := `{"messages":[{"type":"text","text":"database password=\"` + secret + `\""}]}`
			response := decodeInspect(t, postInspect(t, gateway.Routes(), payload))
			if response["clean"] != false || response["reason"] != "secrets" {
				t.Fatalf("short contextual secret not reported: %v", response)
			}
		})
	}
}

func TestInspectAllowsEmptyCredentialValues(t *testing.T) {
	gateway := scanOnlyGateway(t)
	response := decodeInspect(t, postInspect(t, gateway.Routes(), `{"messages":[{"type":"text","text":"password=\"\""}],"replayState":{"password":""}}`))
	if response["clean"] != true || response["findings"] != float64(0) {
		t.Fatalf("empty value must stay clean: %v", response)
	}
}

// DSH block types the plugin may send: tool-set changes and file handles are
// text; only actual inline bytes are unsupported.
func TestInspectAcceptsDSHBlockTypes(t *testing.T) {
	gateway := scanOnlyGateway(t)
	for _, payload := range []string{
		`{"messages":[{"type":"tool-addition","tool":"read"}]}`,
		`{"messages":[{"type":"tool-removal","tool":"read"}]}`,
		`{"messages":[{"type":"file-handle","path":"/tmp/notes.md"}]}`,
		`{"messages":[{"type":"file","path":"/tmp/notes.md"}]}`,
	} {
		response := decodeInspect(t, postInspect(t, gateway.Routes(), payload))
		if response["clean"] != true {
			t.Fatalf("DSH block type must be accepted: %v (%s)", response, payload)
		}
	}

	// A file block with inline bytes is still unsupported.
	response := decodeInspect(t, postInspect(t, gateway.Routes(), `{"messages":[{"type":"file","data":"data:application/pdf;base64,AAAA"}]}`))
	if response["clean"] != false || response["reason"] != "unsupported" {
		t.Fatalf("inline file bytes must be unsupported: %v", response)
	}
}
