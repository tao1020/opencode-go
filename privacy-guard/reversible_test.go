package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const testMaskScope = "0123456789abcdef0123456789abcdef" // 32 chars = 128 bits

func maskGateway(t *testing.T) *Gateway {
	t.Helper()
	gateway, err := NewGateway(Config{
		ClientAPIKey:   testClientKey,
		QueueTimeout:   5 * time.Second,
		ScanTimeout:    5 * time.Second,
		RequestTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	return gateway
}

func maskEnvelope(t *testing.T, scope string, payload any) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"version": 1, "scope": scope, "payload": payload})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func postMask(t *testing.T, handler http.Handler, body, key string) (*httptest.ResponseRecorder, maskResponse) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/mask", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if key != "" {
		request.Header.Set("Authorization", "Bearer "+key)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	var response maskResponse
	if recorder.Code == http.StatusOK {
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("mask response is not JSON: %v", err)
		}
	}
	return recorder, response
}

// restoreTree replaces tokens in every decoded string, which is what the local
// client does with the mappings.
func restoreTree(node any, mappings []maskMapping) any {
	byToken := make(map[string]string, len(mappings))
	for _, mapping := range mappings {
		byToken[mapping.Token] = mapping.Original
	}
	var walk func(any) any
	walk = func(value any) any {
		switch typed := value.(type) {
		case map[string]any:
			out := make(map[string]any, len(typed))
			for k, v := range typed {
				out[k] = walk(v)
			}
			return out
		case []any:
			out := make([]any, len(typed))
			for i, v := range typed {
				out[i] = walk(v)
			}
			return out
		case string:
			out := typed
			for token, original := range byToken {
				out = strings.ReplaceAll(out, token, original)
			}
			return out
		default:
			return value
		}
	}
	return walk(node)
}

// canonical decodes JSON-encoded strings (tool arguments) so two documents can
// be compared structurally rather than byte for byte.
func canonical(node any) any {
	switch typed := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, v := range typed {
			out[k] = canonical(v)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, v := range typed {
			out[i] = canonical(v)
		}
		return out
	case string:
		trimmed := strings.TrimSpace(typed)
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			var decoded any
			decoder := json.NewDecoder(strings.NewReader(trimmed))
			decoder.UseNumber()
			if err := decoder.Decode(&decoded); err == nil {
				return canonical(decoded)
			}
		}
		return typed
	default:
		return node
	}
}

func decodeAny(t *testing.T, raw []byte) any {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, raw)
	}
	return canonical(value)
}

func TestMaskContractAndRoundTrip(t *testing.T) {
	gateway := maskGateway(t)
	payload := map[string]any{
		"model": "gpt-4o-mini",
		"messages": []any{
			map[string]any{"role": "user", "content": "database password=\"SuperSecret123!\""},
			map[string]any{"role": "assistant", "reasoning_content": "checked token ghp_16C7e42F292c6912E7710c838347Ae178B4a", "content": "ok"},
			map[string]any{"role": "assistant", "content": nil, "tool_calls": []any{
				map[string]any{"id": "c1", "type": "function", "function": map[string]any{
					"name":      "bash",
					"arguments": `{"cmd":"export PGPASSWORD=supersecret123","path":"/tmp/x"}`,
				}},
			}},
		},
	}

	recorder, response := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, payload), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}

	// Contract: exactly these fields.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"version": true, "payload": true, "mappings": true, "uninspectedMedia": true}
	for key := range raw {
		if !allowed[key] {
			t.Fatalf("unexpected response field %q", key)
		}
	}
	if response.Version != 1 || response.UninspectedMedia {
		t.Fatalf("unexpected envelope: %+v", response)
	}

	// No secret text remains in the masked payload.
	for _, secret := range []string{"SuperSecret123!", "ghp_16C7e42F292c6912E7710c838347Ae178B4a", "supersecret123"} {
		if strings.Contains(string(response.Payload), secret) {
			t.Errorf("secret %q survived masking: %s", secret, response.Payload)
		}
	}
	// Tool-call structure and argument JSON stay intact.
	if !json.Valid(response.Payload) {
		t.Fatalf("masked payload is not valid JSON: %s", response.Payload)
	}

	restored := restoreTree(decodeAny(t, response.Payload), response.Mappings)
	if !reflect.DeepEqual(restored, decodeAny(t, mustJSON(t, payload))) {
		t.Fatalf("round trip mismatch\nrestored: %#v\nwant: %#v", restored, decodeAny(t, mustJSON(t, payload)))
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestMaskTokensAreScopedAndStable(t *testing.T) {
	gateway := maskGateway(t)
	handler := gateway.Routes()
	payload := map[string]any{"messages": []any{map[string]any{"role": "user", "content": "password=\"SuperSecret123!\""}}}

	_, first := postMask(t, handler, maskEnvelope(t, testMaskScope, payload), testClientKey)
	_, second := postMask(t, handler, maskEnvelope(t, testMaskScope, payload), testClientKey)
	otherScope := "fedcba9876543210fedcba9876543210"
	_, third := postMask(t, handler, maskEnvelope(t, otherScope, payload), testClientKey)

	if len(first.Mappings) != 1 || len(second.Mappings) != 1 || len(third.Mappings) != 1 {
		t.Fatalf("unexpected mapping counts: %d %d %d", len(first.Mappings), len(second.Mappings), len(third.Mappings))
	}
	if first.Mappings[0].Token != second.Mappings[0].Token {
		t.Fatalf("same scope must keep the token stable: %q vs %q", first.Mappings[0].Token, second.Mappings[0].Token)
	}
	if first.Mappings[0].Token == third.Mappings[0].Token {
		t.Fatalf("different scopes must not share a token: %q", first.Mappings[0].Token)
	}
	if !strings.HasPrefix(first.Mappings[0].Token, maskTokenPrefix) || len(first.Mappings[0].Token) != len(maskTokenPrefix)+32+2 {
		t.Fatalf("unexpected token shape: %q", first.Mappings[0].Token)
	}
	if first.Mappings[0].Original != "SuperSecret123!" {
		t.Fatalf("mapping original = %q", first.Mappings[0].Original)
	}
}

func TestMaskConcurrentRequestsShareStableTokens(t *testing.T) {
	gateway := maskGateway(t)
	handler := gateway.Routes()
	payload := map[string]any{"messages": []any{map[string]any{"role": "user", "content": "password=\"SuperSecret123!\""}}}
	body := maskEnvelope(t, testMaskScope, payload)

	const workers = 8
	tokens := make([]string, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			recorder, response := postMask(t, handler, body, testClientKey)
			if recorder.Code != http.StatusOK || len(response.Mappings) != 1 {
				t.Errorf("worker %d: code=%d mappings=%d", index, recorder.Code, len(response.Mappings))
				return
			}
			tokens[index] = response.Mappings[0].Token
		}(i)
	}
	wg.Wait()
	for i := 1; i < workers; i++ {
		if tokens[i] != tokens[0] {
			t.Fatalf("token changed under concurrency: %q vs %q", tokens[i], tokens[0])
		}
	}
}

func TestMaskQuotedNewlineUnicode(t *testing.T) {
	gateway := maskGateway(t)
	// Escaped quote/backslash/newline text, real Unicode, and an embedded single
	// quote. These are the forms that appear inside a JSON string in practice.
	literals := []string{
		`pa\"ss\\word\nend`,
		`密码值-秘密`,
		`quote'and\"mix`,
	}
	var contents []any
	for _, secret := range literals {
		contents = append(contents, map[string]any{"role": "user", "content": `password="` + secret + `"`})
	}
	secrets := literals
	payload := map[string]any{"messages": contents}

	recorder, response := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, payload), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	for _, secret := range secrets {
		if strings.Contains(string(response.Payload), secret) {
			t.Errorf("secret %q survived: %s", secret, response.Payload)
		}
	}
	restored := restoreTree(decodeAny(t, response.Payload), response.Mappings)
	if !reflect.DeepEqual(restored, decodeAny(t, mustJSON(t, payload))) {
		t.Fatalf("round trip mismatch for quoted/unicode values: %#v", restored)
	}
}

// A one-character password is masked at its assignment span only; the letter
// must not be replaced everywhere else in the text.
func TestMaskOneCharacterQuotedSecret(t *testing.T) {
	gateway := maskGateway(t)
	content := `database password="a" and the letter a stays`
	payload := map[string]any{"messages": []any{map[string]any{"role": "user", "content": content}}}

	recorder, response := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, payload), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var decoded struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(response.Payload, &decoded); err != nil {
		t.Fatal(err)
	}
	masked := decoded.Messages[0].Content
	if strings.Contains(masked, `password="a"`) {
		t.Fatalf("short password not masked: %s", masked)
	}
	if !strings.Contains(masked, "the letter a stays") {
		t.Fatalf("unrelated letter was masked: %s", masked)
	}
	if len(response.Mappings) != 1 || response.Mappings[0].Original != "a" {
		t.Fatalf("unexpected mappings: %+v", response.Mappings)
	}
}

func TestMaskToolArgumentsOldNewAndValidity(t *testing.T) {
	gateway := maskGateway(t)
	// The edit tool receives values copied from the conversation; the second one
	// carries its own credential context.
	arguments := `{"old":"SuperSecret123!","new":"password=AnotherSecret456!"}`
	content := `password="SuperSecret123!"`
	payload := map[string]any{
		"messages": []any{
			map[string]any{"role": "user", "content": content},
			map[string]any{"role": "assistant", "content": nil, "tool_calls": []any{
				map[string]any{"id": "c1", "type": "function", "function": map[string]any{"name": "edit", "arguments": arguments}},
			}},
		},
	}

	recorder, response := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, payload), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var decoded struct {
		Messages []struct {
			ToolCalls []struct {
				Function struct {
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(response.Payload, &decoded); err != nil {
		t.Fatalf("tool arguments broke JSON: %v", err)
	}
	var maskedArgs string
	for _, message := range decoded.Messages {
		if len(message.ToolCalls) > 0 {
			maskedArgs = message.ToolCalls[0].Function.Arguments
		}
	}
	if maskedArgs == "" {
		t.Fatal("tool call missing from masked payload")
	}
	if !json.Valid([]byte(maskedArgs)) {
		t.Fatalf("inner arguments are not valid JSON: %s", maskedArgs)
	}
	for _, secret := range []string{"SuperSecret123!", "AnotherSecret456!"} {
		if strings.Contains(maskedArgs, secret) {
			t.Errorf("secret %q survived in arguments: %s", secret, maskedArgs)
		}
	}

	restored := restoreTree(decodeAny(t, response.Payload), response.Mappings)
	if !reflect.DeepEqual(restored, decodeAny(t, mustJSON(t, payload))) {
		t.Fatalf("tool argument round trip mismatch: %#v", restored)
	}
}

func TestMaskMalformedToolArguments(t *testing.T) {
	gateway := maskGateway(t)
	handler := gateway.Routes()

	broken := map[string]any{"messages": []any{map[string]any{"role": "assistant", "content": nil, "tool_calls": []any{
		map[string]any{"id": "c1", "type": "function", "function": map[string]any{"name": "bash", "arguments": `{"cmd":`}},
	}}}}
	recorder, _ := postMask(t, handler, maskEnvelope(t, testMaskScope, broken), testClientKey)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed arguments, got %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "malformed tool arguments") {
		t.Fatalf("unexpected body: %s", recorder.Body.String())
	}

	plain := map[string]any{"messages": []any{map[string]any{"role": "assistant", "content": nil, "tool_calls": []any{
		map[string]any{"id": "c1", "type": "function", "function": map[string]any{"name": "bash", "arguments": "echo hello"}},
	}}}}
	if recorder, _ := postMask(t, handler, maskEnvelope(t, testMaskScope, plain), testClientKey); recorder.Code != http.StatusOK {
		t.Fatalf("plain text arguments must be accepted, got %d", recorder.Code)
	}
}

func TestMaskSchemaStructurePreserved(t *testing.T) {
	gateway := maskGateway(t)
	payload := map[string]any{
		"tools": []any{map[string]any{"type": "function", "function": map[string]any{
			"name": "login",
			"parameters": map[string]any{"type": "object", "properties": map[string]any{
				"password": map[string]any{"type": "string", "description": "the account password", "default": "hunter2"},
				"user":     map[string]any{"type": "string"},
			}},
		}}},
	}

	recorder, response := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, payload), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	restored := restoreTree(decodeAny(t, response.Payload), response.Mappings)
	want := decodeAny(t, mustJSON(t, payload))
	if !reflect.DeepEqual(restored, want) {
		t.Fatalf("schema round trip mismatch: %#v", restored)
	}
	if len(response.Mappings) != 1 || response.Mappings[0].Original != "hunter2" {
		t.Fatalf("default must be masked, got %+v", response.Mappings)
	}
	if strings.Contains(string(response.Payload), "hunter2") {
		t.Fatalf("schema default survived: %s", response.Payload)
	}
}

func TestMaskMediaIsPreservedAndFlagged(t *testing.T) {
	gateway := maskGateway(t)
	payload := map[string]any{
		"messages": []any{map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "image_url", "image_url": map[string]any{"url": "https://example.com/a.png"}},
		}}},
		"note": "password=\"SuperSecret123!\"",
	}

	recorder, response := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, payload), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !response.UninspectedMedia {
		t.Fatal("media must set uninspectedMedia")
	}
	if !strings.Contains(string(response.Payload), "https://example.com/a.png") {
		t.Fatalf("media value was altered: %s", response.Payload)
	}
	if strings.Contains(string(response.Payload), "SuperSecret123!") {
		t.Fatalf("text secret must still be masked alongside media: %s", response.Payload)
	}
}

func TestMaskStructuralAndScopeValidation(t *testing.T) {
	gateway := maskGateway(t)
	handler := gateway.Routes()

	structural := map[string]any{"model": "ghp_16C7e42F292c6912E7710c838347Ae178B4a", "messages": []any{}}
	if recorder, _ := postMask(t, handler, maskEnvelope(t, testMaskScope, structural), testClientKey); recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for secret in model, got %d", recorder.Code)
	}

	for _, scope := range []string{"short", "", "has space in it 0123456789012345"} {
		body := maskEnvelope(t, scope, map[string]any{"messages": []any{}})
		if recorder, _ := postMask(t, handler, body, testClientKey); recorder.Code != http.StatusBadRequest {
			t.Fatalf("scope %q should be rejected, got %d", scope, recorder.Code)
		}
	}

	if recorder, _ := postMask(t, handler, `{"version":2,"scope":"0123456789abcdef0123456789abcdef","payload":{}}`, testClientKey); recorder.Code != http.StatusBadRequest {
		t.Fatalf("wrong version should be rejected, got %d", recorder.Code)
	}
	if recorder, _ := postMask(t, handler, maskEnvelope(t, testMaskScope, map[string]any{}), ""); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without a key, got %d", recorder.Code)
	}
}

func TestMaskCapacityFailsClosed(t *testing.T) {
	t.Run("scope cap", func(t *testing.T) {
		gateway := maskGateway(t)
		gateway.maskStore = newMaskStore(1, 10, time.Hour)
		handler := gateway.Routes()
		payload := map[string]any{"messages": []any{}}

		if recorder, _ := postMask(t, handler, maskEnvelope(t, testMaskScope, payload), testClientKey); recorder.Code != http.StatusOK {
			t.Fatalf("first scope should succeed, got %d", recorder.Code)
		}
		other := "aaaa456789abcdef0123456789abcdef"
		recorder, _ := postMask(t, handler, maskEnvelope(t, other, payload), testClientKey)
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("second scope should be refused, got %d", recorder.Code)
		}
	})

	t.Run("mapping cap", func(t *testing.T) {
		gateway := maskGateway(t)
		gateway.maskStore = newMaskStore(4, 1, time.Hour)
		payload := map[string]any{"messages": []any{
			map[string]any{"role": "user", "content": "password=\"SuperSecret123!\""},
			map[string]any{"role": "user", "content": "password=\"AnotherSecret456!\""},
		}}
		recorder, _ := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, payload), testClientKey)
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 when mappings exceed the cap, got %d", recorder.Code)
		}
	})
}

func TestMaskRejectsOversizedBody(t *testing.T) {
	gateway := maskGateway(t)
	huge := `{"version":1,"scope":"` + testMaskScope + `","payload":{"a":"` + strings.Repeat("x", int(defaultMaxBody)+1024) + `"}}`
	recorder, _ := postMask(t, gateway.Routes(), huge, testClientKey)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", recorder.Code)
	}
}

// OpenCode Go sends DeepSeek reasoning_content in the history; it must be masked
// and restored like any other text.
func TestMaskReasoningContent(t *testing.T) {
	gateway := maskGateway(t)
	payload := map[string]any{"messages": []any{
		map[string]any{"role": "assistant", "reasoning_content": "the key is ghp_16C7e42F292c6912E7710c838347Ae178B4a", "content": "done"},
	}}

	recorder, response := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, payload), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	if strings.Contains(string(response.Payload), "ghp_16C7e42F292c6912E7710c838347Ae178B4a") {
		t.Fatalf("reasoning_content leaked: %s", response.Payload)
	}
	restored := restoreTree(decodeAny(t, response.Payload), response.Mappings)
	if !reflect.DeepEqual(restored, decodeAny(t, mustJSON(t, payload))) {
		t.Fatalf("reasoning round trip mismatch: %#v", restored)
	}
}

var _ = fmt.Sprintf

// decodeNumbered keeps JSON numbers as json.Number so a restored number can be
// compared without float coercion.
func decodeNumbered(t *testing.T, raw []byte) any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	return canonical(value)
}

// restoreTyped is the client model: a token that is an exact JSON value is
// restored with its declared type; text tokens are restored as text.
func restoreTyped(node any, mappings []maskMapping) any {
	byToken := make(map[string]maskMapping, len(mappings))
	for _, mapping := range mappings {
		byToken[mapping.Token] = mapping
	}
	var walk func(any) any
	walk = func(value any) any {
		switch typed := value.(type) {
		case map[string]any:
			out := make(map[string]any, len(typed))
			for k, v := range typed {
				out[k] = walk(v)
			}
			return out
		case []any:
			out := make([]any, len(typed))
			for i, v := range typed {
				out[i] = walk(v)
			}
			return out
		case string:
			if mapping, ok := byToken[typed]; ok {
				if mapping.OriginalType == "number" {
					return json.Number(mapping.Original)
				}
				return mapping.Original
			}
			// Tool arguments are JSON text; restore inside the parsed document.
			if trimmed := strings.TrimSpace(typed); strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
				var parsed any
				if err := json.Unmarshal([]byte(trimmed), &parsed); err == nil {
					return walk(parsed)
				}
			}
			out := typed
			for token, mapping := range byToken {
				if mapping.OriginalType == "" {
					out = strings.ReplaceAll(out, token, mapping.Original)
				}
			}
			return out
		default:
			return value
		}
	}
	return walk(node)
}

func TestMaskNumericOriginalType(t *testing.T) {
	gateway := maskGateway(t)
	payload := map[string]any{
		"metadata": map[string]any{"password": 123456},
		"messages": []any{map[string]any{"role": "assistant", "content": nil, "tool_calls": []any{
			map[string]any{"id": "c1", "type": "function", "function": map[string]any{
				"name": "write", "arguments": `{"password":123456,"port":8080}`,
			}},
		}}},
	}

	recorder, response := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, payload), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}

	numbers := 0
	for _, mapping := range response.Mappings {
		if mapping.OriginalType == "number" {
			numbers++
			if mapping.Original != "123456" {
				t.Fatalf("numeric original = %q", mapping.Original)
			}
		}
	}
	if numbers != 1 {
		t.Fatalf("expected one numeric mapping, got %d: %+v", numbers, response.Mappings)
	}

	restored := restoreTyped(decodeNumbered(t, response.Payload), response.Mappings)
	if !reflect.DeepEqual(restored, decodeNumbered(t, mustJSON(t, payload))) {
		t.Fatalf("typed round trip mismatch\nrestored: %#v\nwant: %#v", restored, decodeNumbered(t, mustJSON(t, payload)))
	}

	// The tool argument document must still parse and contain a number again.
	var decoded struct {
		Messages []struct {
			ToolCalls []struct {
				Function struct {
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(response.Payload, &decoded); err != nil {
		t.Fatal(err)
	}
	args := decoded.Messages[0].ToolCalls[0].Function.Arguments
	var parsedArgs map[string]any
	if err := json.Unmarshal([]byte(args), &parsedArgs); err != nil {
		t.Fatalf("masked arguments invalid: %v", err)
	}
	if _, isString := parsedArgs["password"].(string); !isString {
		t.Fatalf("masked numeric value should be a token string until restored: %#v", parsedArgs)
	}
}

// 123 as a number and "123" as a string must never share a token.
func TestMaskNumberAndStringTokensDiffer(t *testing.T) {
	gateway := maskGateway(t)
	payload := map[string]any{
		"metadata": map[string]any{"password": 123456},
		"note":     `password="123456"`,
	}

	recorder, response := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, payload), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	if len(response.Mappings) != 2 {
		t.Fatalf("expected two mappings, got %+v", response.Mappings)
	}
	var numeric, textual *maskMapping
	for i := range response.Mappings {
		mapping := &response.Mappings[i]
		if mapping.OriginalType == "number" {
			numeric = mapping
		} else {
			textual = mapping
		}
	}
	if numeric == nil || textual == nil {
		t.Fatalf("expected one numeric and one string mapping: %+v", response.Mappings)
	}
	if numeric.Original != "123456" || textual.Original != "123456" {
		t.Fatalf("unexpected originals: %+v", response.Mappings)
	}
	if numeric.Token == textual.Token {
		t.Fatalf("number and string share a token: %q", numeric.Token)
	}
}

func TestMaskByteBudgetPerScope(t *testing.T) {
	gateway := maskGateway(t)
	gateway.maskStore = newMaskStore(10, 100, time.Hour)
	gateway.maskStore.perScopeBudget = 16

	big := strings.Repeat("x", 40)
	body := maskEnvelope(t, testMaskScope, map[string]any{"note": `password="` + big + `"`})
	recorder, _ := postMask(t, gateway.Routes(), body, testClientKey)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on per-scope byte budget, got %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "mask capacity exceeded") {
		t.Fatalf("unexpected body: %s", recorder.Body.String())
	}

	// A refused request must leave no residue: a smaller secret still fits.
	small := maskEnvelope(t, testMaskScope, map[string]any{"note": `password="abc"`})
	recorder, response := postMask(t, gateway.Routes(), small, testClientKey)
	if recorder.Code != http.StatusOK || len(response.Mappings) != 1 {
		t.Fatalf("budget leaked after refusal: %d %+v", recorder.Code, response.Mappings)
	}
}

func TestMaskGlobalByteBudget(t *testing.T) {
	gateway := maskGateway(t)
	gateway.maskStore = newMaskStore(10, 100, time.Hour)
	gateway.maskStore.globalBudget = 64
	gateway.maskStore.perScopeBudget = 1024

	big := strings.Repeat("y", 40)
	first := maskEnvelope(t, testMaskScope, map[string]any{"note": `password="` + big + `"`})
	if recorder, _ := postMask(t, gateway.Routes(), first, testClientKey); recorder.Code != http.StatusOK {
		t.Fatalf("first scope should fit, got %d", recorder.Code)
	}
	second := maskEnvelope(t, "aaaa456789abcdef0123456789abcdef", map[string]any{"note": `password="` + big + `"`})
	if recorder, _ := postMask(t, gateway.Routes(), second, testClientKey); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on global byte budget, got %d", recorder.Code)
	}
}

func TestMaskBudgetReclaimedAfterTTL(t *testing.T) {
	gateway := maskGateway(t)
	store := newMaskStore(10, 100, time.Hour)
	clock := time.Unix(1000, 0)
	store.now = func() time.Time { return clock }
	store.globalBudget = 48
	store.perScopeBudget = 1024
	gateway.maskStore = store

	big := strings.Repeat("z", 40)
	first := maskEnvelope(t, testMaskScope, map[string]any{"note": `password="` + big + `"`})
	if recorder, _ := postMask(t, gateway.Routes(), first, testClientKey); recorder.Code != http.StatusOK {
		t.Fatalf("first scope should fit, got %d", recorder.Code)
	}

	// Still inside the TTL: the global budget is full.
	other := maskEnvelope(t, "bbbb456789abcdef0123456789abcdef", map[string]any{"note": `password="` + big + `"`})
	if recorder, _ := postMask(t, gateway.Routes(), other, testClientKey); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 before TTL, got %d", recorder.Code)
	}

	// After the TTL the idle scope releases its bytes.
	clock = clock.Add(2 * time.Hour)
	if recorder, _ := postMask(t, gateway.Routes(), other, testClientKey); recorder.Code != http.StatusOK {
		t.Fatalf("expected the budget to be reclaimed, got %d", recorder.Code)
	}
}

func TestMaskResponseSizeIsBounded(t *testing.T) {
	gateway := maskGateway(t)
	gateway.maskStore = newMaskStore(10, 1000, time.Hour)

	payload := map[string]any{"note": "password=\"SuperSecret123!\" password=\"AnotherSecret456!\""}
	body := maskEnvelope(t, testMaskScope, payload)
	recorder, _ := postMask(t, gateway.Routes(), body, testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("baseline request failed: %d", recorder.Code)
	}

	// Set the cap one byte below the response we just measured.
	gateway.maskStore.maxResponse = int64(recorder.Body.Len() - 1)
	recorder, _ = postMask(t, gateway.Routes(), body, testClientKey)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when the response exceeds the bound, got %d", recorder.Code)
	}
	// Nothing partial: the body is the fixed error document.
	if strings.Contains(recorder.Body.String(), "__PG_") || strings.Contains(recorder.Body.String(), "payload") {
		t.Fatalf("partial response was written: %s", recorder.Body.String())
	}
}

// A later turn may echo a token this scope produced (replayState / historical
// masked prefix). The token must stay, must not be treated as a new secret, and
// its mapping must be re-reported so the client can still restore it.
func TestMaskEchoesOwnTokenWithMapping(t *testing.T) {
	gateway := maskGateway(t)
	handler := gateway.Routes()

	_, first := postMask(t, handler, maskEnvelope(t, testMaskScope, map[string]any{
		"note": `password="SuperSecret123!"`,
	}), testClientKey)
	if len(first.Mappings) != 1 {
		t.Fatalf("first call mappings = %d", len(first.Mappings))
	}
	token := first.Mappings[0].Token

	recorder, second := postMask(t, handler, maskEnvelope(t, testMaskScope, map[string]any{
		"replayState": "prior " + token,
		"messages":    []any{map[string]any{"role": "user", "content": "remember " + token}},
	}), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if len(second.Mappings) != 1 {
		t.Fatalf("expected exactly one echoed mapping, got %+v", second.Mappings)
	}
	if second.Mappings[0].Token != token || second.Mappings[0].Original != "SuperSecret123!" {
		t.Fatalf("unexpected echoed mapping: %+v", second.Mappings[0])
	}
	if strings.Count(string(second.Payload), token) != 2 {
		t.Fatalf("token should be preserved in both places: %s", second.Payload)
	}
	// No nesting: no mapping whose original is itself a token.
	for _, mapping := range second.Mappings {
		if isMaskToken(mapping.Original) {
			t.Fatalf("nested mapping created: %+v", mapping)
		}
	}
}

// A token from another scope is never resolved to that scope's secret, but it
// is re-masked as an opaque literal. Otherwise the model sees a token it cannot
// restore and can echo it into a tool call, which the client refuses.
func TestMaskReMasksCrossScopeTokenAsOpaqueLiteral(t *testing.T) {
	gateway := maskGateway(t)
	handler := gateway.Routes()
	otherScope := "fedcba9876543210fedcba9876543210"

	_, first := postMask(t, handler, maskEnvelope(t, otherScope, map[string]any{
		"note": `password="SuperSecret123!"`,
	}), testClientKey)
	foreign := first.Mappings[0].Token

	recorder, second := postMask(t, handler, maskEnvelope(t, testMaskScope, map[string]any{
		"replayState": "foreign " + foreign,
	}), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	if len(second.Mappings) != 1 {
		t.Fatalf("expected one opaque mapping, got %+v", second.Mappings)
	}
	mapping := second.Mappings[0]
	if mapping.Original != foreign {
		t.Fatalf("original = %q, want the foreign token literal", mapping.Original)
	}
	if mapping.Token == foreign {
		t.Fatal("foreign token was left visible")
	}
	if strings.Contains(string(second.Payload), foreign) {
		t.Fatalf("foreign token should not reach the model: %s", second.Payload)
	}
	if strings.Contains(string(second.Payload), "SuperSecret123!") {
		t.Fatalf("cross-scope secret leaked: %s", second.Payload)
	}
	restored := restoreTree(map[string]any{"replayState": "foreign " + mapping.Token}, second.Mappings)
	if got := restored.(map[string]any)["replayState"]; got != "foreign "+foreign {
		t.Fatalf("restored = %q", got)
	}
}

// A token minted by an earlier plugin process survives in session history after
// a restart. The new scope cannot resolve it, so it must be re-masked instead
// of reaching the model as an unrestorable token.
func TestMaskReMasksTokenFromPreviousProcess(t *testing.T) {
	gateway := maskGateway(t)
	handler := gateway.Routes()
	stale := "__PG_1c0a1bf3a897ec549ff3624b0b454265__"

	recorder, response := postMask(t, handler, maskEnvelope(t, testMaskScope, map[string]any{
		"messages": []any{
			map[string]any{"role": "assistant", "content": "check prefix " + stale},
			map[string]any{"role": "tool", "content": "output " + stale},
		},
	}), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if len(response.Mappings) != 1 {
		t.Fatalf("expected one mapping, got %+v", response.Mappings)
	}
	if response.Mappings[0].Original != stale || response.Mappings[0].Token == stale {
		t.Fatalf("unexpected mapping: %+v", response.Mappings[0])
	}
	if strings.Contains(string(response.Payload), stale) {
		t.Fatalf("stale token should not reach the model: %s", response.Payload)
	}
	if strings.Count(string(response.Payload), response.Mappings[0].Token) != 2 {
		t.Fatalf("fresh token should appear twice: %s", response.Payload)
	}

	// The fresh token belongs to this scope and is re-reported when echoed.
	_, echo := postMask(t, handler, maskEnvelope(t, testMaskScope, map[string]any{
		"replayState": "echo " + response.Mappings[0].Token,
	}), testClientKey)
	if len(echo.Mappings) != 1 || echo.Mappings[0].Token != response.Mappings[0].Token || echo.Mappings[0].Original != stale {
		t.Fatalf("fresh token was not re-reported: %+v", echo.Mappings)
	}
}

// A secret that embeds a token literal is masked once as a whole value. Splitting
// it would leave a nested mapping that a single restore pass cannot resolve.
func TestMaskSecretEmbeddingForeignTokenIsOneMapping(t *testing.T) {
	gateway := maskGateway(t)
	handler := gateway.Routes()
	literal := "__PG_0123456789abcdef0123456789abcdef__"
	secret := "prefix " + literal + " suffix"

	recorder, response := postMask(t, handler, maskEnvelope(t, testMaskScope, map[string]any{
		"note": `password="` + secret + `"`,
	}), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if len(response.Mappings) != 1 {
		t.Fatalf("expected one mapping, got %+v", response.Mappings)
	}
	if response.Mappings[0].Original != secret {
		t.Fatalf("original = %q, want the whole secret", response.Mappings[0].Original)
	}
	if strings.Contains(string(response.Payload), literal) {
		t.Fatalf("embedded token leaked: %s", response.Payload)
	}
}

// A secret can itself look like a token. It is a real value: mask it once, and a
// single restore pass must yield exactly that literal, never substitute again.
func TestMaskTokenShapedSecretIsSinglePass(t *testing.T) {
	gateway := maskGateway(t)
	handler := gateway.Routes()
	literal := "__PG_0123456789abcdef0123456789abcdef__"

	recorder, response := postMask(t, handler, maskEnvelope(t, testMaskScope, map[string]any{
		"note": `password="` + literal + `"`,
	}), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if len(response.Mappings) != 1 {
		t.Fatalf("expected one mapping, got %+v", response.Mappings)
	}
	mapping := response.Mappings[0]
	if mapping.Original != literal {
		t.Fatalf("original = %q, want the literal", mapping.Original)
	}
	if mapping.Token == literal {
		t.Fatal("literal was mistaken for an existing token")
	}
	if strings.Contains(string(response.Payload), literal) {
		t.Fatalf("token-shaped secret was not masked: %s", response.Payload)
	}

	// Single pass: apply each mapping once, never re-scan the result.
	single := string(response.Payload)
	for _, m := range response.Mappings {
		single = strings.ReplaceAll(single, m.Token, m.Original)
	}
	if !strings.Contains(single, literal) {
		t.Fatalf("single-pass restore did not yield the literal: %s", single)
	}
	if strings.Count(single, literal) != 1 {
		t.Fatalf("literal was substituted recursively: %s", single)
	}
}

func maskContent(t *testing.T, gateway *Gateway, content string) (string, []maskMapping) {
	t.Helper()
	recorder, response := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, map[string]any{
		"messages": []any{map[string]any{"role": "user", "content": content}},
	}), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var decoded struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(response.Payload, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded.Messages[0].Content, response.Mappings
}

// A pure environment reference carries no value: it must pass through unchanged
// and produce no mapping at all.
func TestMaskEnvironmentReferenceProducesNoMapping(t *testing.T) {
	gateway := maskGateway(t)
	for _, code := range []string{
		`password = os.environ["DB_PASSWORD"]`,
		`password = os.getenv("DB_PASSWORD")`,
		`password := os.Getenv("DB_PASSWORD")`,
		`const password = process.env.DB_PASSWORD;`,
		`const config = {password: process.env.DB_PASSWORD};`,
		`password="${DB_PASSWORD}"`,
	} {
		content, mappings := maskContent(t, gateway, code)
		if content != code {
			t.Fatalf("reference rewritten:\n want %q\n got  %q", code, content)
		}
		if len(mappings) != 0 {
			t.Fatalf("reference produced mappings: %+v", mappings)
		}
	}
}

// The fallback literal inside a two-argument lookup is still a value.
func TestMaskGetenvHardcodedDefaultStillMasked(t *testing.T) {
	gateway := maskGateway(t)
	code := `password = os.getenv("DB_PASSWORD", "hardcoded-secret")`
	content, mappings := maskContent(t, gateway, code)

	if strings.Contains(content, "hardcoded-secret") {
		t.Fatalf("default value survived: %s", content)
	}
	if !strings.Contains(content, `os.getenv("DB_PASSWORD"`) {
		t.Fatalf("reference was broken: %s", content)
	}
	if len(mappings) != 1 || mappings[0].Original != "hardcoded-secret" {
		t.Fatalf("unexpected mappings: %+v", mappings)
	}
}

// A real literal next to a reference is still a secret.
func TestMaskLiteralNextToReferenceStillMasked(t *testing.T) {
	gateway := maskGateway(t)
	code := "password=\"SuperSecret123!\"\napi = os.environ[\"API_KEY\"]"
	content, mappings := maskContent(t, gateway, code)

	if strings.Contains(content, "SuperSecret123!") {
		t.Fatalf("literal secret survived: %s", content)
	}
	if !strings.Contains(content, `os.environ["API_KEY"]`) {
		t.Fatalf("reference was broken: %s", content)
	}
	if len(mappings) != 1 || mappings[0].Original != "SuperSecret123!" {
		t.Fatalf("unexpected mappings: %+v", mappings)
	}
}

// A hardcoded single-character literal is still a value, not a reference.
func TestMaskShortLiteralStillMasked(t *testing.T) {
	gateway := maskGateway(t)
	content, mappings := maskContent(t, gateway, `password="a"`)
	if strings.Contains(content, `password="a"`) {
		t.Fatalf("short literal was skipped: %s", content)
	}
	if len(mappings) != 1 || mappings[0].Original != "a" {
		t.Fatalf("unexpected mappings: %+v", mappings)
	}
}

// Only well-formed references are exempt. An unknown expression must not be
// silently ignored.
func TestMaskUnknownExpressionIsNotIgnored(t *testing.T) {
	gateway := maskGateway(t)
	content, _ := maskContent(t, gateway, `password=lookupSecret("hunter2")`)
	if content == `password=lookupSecret("hunter2")` {
		t.Fatalf("unknown expression was silently ignored: %s", content)
	}
	if !strings.Contains(content, maskTokenPrefix) {
		t.Fatalf("unknown expression produced no masking: %s", content)
	}
}

// Review c28-1: camelCase and separator variants of credential names must be
// recognised, in text assignments and in JSON field names.
func TestMaskCredentialNameVariants(t *testing.T) {
	gateway := maskGateway(t)
	names := []string{"secretKey", "secretkey", "signing_key", "signingKey", "encryption_key", "encryptionKey", "authorization", "bearer"}
	for _, name := range names {
		t.Run("text "+name, func(t *testing.T) {
			content, mappings := maskContent(t, gateway, name+`="SuperSecret123!"`)
			if strings.Contains(content, "SuperSecret123!") {
				t.Fatalf("%s assignment was not masked: %s", name, content)
			}
			if len(mappings) != 1 || mappings[0].Original != "SuperSecret123!" {
				t.Fatalf("%s mappings: %+v", name, mappings)
			}
		})
		t.Run("json "+name, func(t *testing.T) {
			recorder, response := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, map[string]any{
				"metadata": map[string]any{name: "SuperSecret123!"},
			}), testClientKey)
			if recorder.Code != http.StatusOK {
				t.Fatalf("%s: status %d (%s)", name, recorder.Code, recorder.Body.String())
			}
			if strings.Contains(string(response.Payload), "SuperSecret123!") {
				t.Fatalf("%s field was not masked: %s", name, response.Payload)
			}
			if len(response.Mappings) != 1 {
				t.Fatalf("%s mappings: %+v", name, response.Mappings)
			}
		})
	}
}

// Review c28-2: a short secret propagates when a whole string equals it, but a
// substring of a longer string is not rewritten.
func TestMaskShortSecretPropagatesToWholeString(t *testing.T) {
	gateway := maskGateway(t)
	recorder, response := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, map[string]any{
		"content":  "abc",
		"password": "abc",
	}), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d", recorder.Code)
	}
	if strings.Contains(string(response.Payload), `"abc"`) && !strings.Contains(string(response.Payload), `"__PG_`) {
		t.Fatalf("short secret was not masked: %s", response.Payload)
	}
	if len(response.Mappings) != 1 || response.Mappings[0].Original != "abc" {
		t.Fatalf("mappings: %+v", response.Mappings)
	}

	// Declared limitation: a short value embedded in a longer string is not
	// replaced, because that would corrupt ordinary words.
	content, mappings := maskContent(t, gateway, "abcdef is a word")
	if content != "abcdef is a word" || len(mappings) != 0 {
		t.Fatalf("substring limitation broken: %q %+v", content, mappings)
	}
}

// Review c28-3: a key carrying a real detected secret rejects the request, while
// an ordinary schema property name is not a secret.
func TestMaskKeyWithDetectedSecretIsRejected(t *testing.T) {
	gateway := maskGateway(t)
	recorder, _ := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, map[string]any{
		"ghp_16C7e42F292c6912E7710c838347Ae178B4a": "value",
	}), testClientKey)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "secret in structural field") {
		t.Fatalf("unexpected body: %s", recorder.Body.String())
	}

	// A schema property called "password" is a name, not a secret.
	payload := map[string]any{"tools": []any{map[string]any{"name": "login", "parameters": map[string]any{
		"properties": map[string]any{"password": map[string]any{"type": "string"}},
	}}}}
	recorder, response := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, payload), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("schema property rejected: %d %s", recorder.Code, recorder.Body.String())
	}
	if len(response.Mappings) != 0 {
		t.Fatalf("schema property produced mappings: %+v", response.Mappings)
	}
}

// Review c28-4: punctuation after a verbal prefix is not the value.
func TestMaskProsePunctuationIsNotTheValue(t *testing.T) {
	gateway := maskGateway(t)
	for _, code := range []string{
		`password is: hunter2secret`,
		`password is : hunter2secret`,
		`密码是： hunter2secret`,
		`密码是 hunter2secret`,
	} {
		content, mappings := maskContent(t, gateway, code)
		if strings.Contains(content, "hunter2secret") {
			t.Fatalf("%q: secret not masked: %s", code, content)
		}
		if strings.Contains(content, "__PG_") && strings.Contains(content, ": __PG_") == false && strings.Contains(content, "： __PG_") == false {
			// the token must replace the value, never the punctuation
			t.Logf("%q -> %s", code, content)
		}
		if len(mappings) != 1 || mappings[0].Original != "hunter2secret" {
			t.Fatalf("%q mappings: %+v", code, mappings)
		}
	}

	// A bare "password is:" with no value must not invent one.
	content, mappings := maskContent(t, gateway, "password is:")
	if len(mappings) != 0 {
		t.Fatalf("punctuation captured as a value: %q %+v", content, mappings)
	}
}

// Review c28-8: media keys only bypass scanning inside a real content part.
func TestMaskMediaSkipIsPathSensitive(t *testing.T) {
	gateway := maskGateway(t)
	detectable := "token ghp_16C7e42F292c6912E7710c838347Ae178B4a"

	for _, key := range []string{"b64_json", "input_image", "input_audio", "image_url"} {
		recorder, response := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, map[string]any{
			"metadata": map[string]any{key: detectable},
		}), testClientKey)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s: status %d", key, recorder.Code)
		}
		if strings.Contains(string(response.Payload), "ghp_16C7e42F292c6912E7710c838347Ae178B4a") {
			t.Fatalf("%s metadata secret bypassed scanning: %s", key, response.Payload)
		}
	}

	// A real content part is preserved and flagged.
	payload := map[string]any{"messages": []any{map[string]any{"role": "user", "content": []any{
		map[string]any{"type": "image_url", "image_url": map[string]any{"url": "https://example.com/a.png"}},
	}}}}
	recorder, response := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, payload), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d", recorder.Code)
	}
	if !response.UninspectedMedia {
		t.Fatal("content-part media must be flagged")
	}
	if !strings.Contains(string(response.Payload), "https://example.com/a.png") {
		t.Fatalf("media bytes changed: %s", response.Payload)
	}
}

// Shell references are exempt only in the conventional uppercase form.
func TestMaskShellReferenceCaseSensitivity(t *testing.T) {
	gateway := maskGateway(t)
	for _, code := range []string{`password="$DB_PASSWORD"`, `password="${DB_PASSWORD}"`} {
		content, mappings := maskContent(t, gateway, code)
		if content != code || len(mappings) != 0 {
			t.Fatalf("%q should be preserved, got %q %+v", code, content, mappings)
		}
	}
	for _, code := range []string{`password="$uperSecret123"`, `password="${dbPassword}"`} {
		content, _ := maskContent(t, gateway, code)
		if content == code {
			t.Fatalf("%q should be masked, got %q", code, content)
		}
	}
}

// restoreOnce applies every mapping exactly once, without rescanning, which is
// the contract the engine promises to clients.
func restoreOnce(masked string, mappings []maskMapping) string {
	byToken := make(map[string]string, len(mappings))
	for _, mapping := range mappings {
		byToken[mapping.Token] = mapping.Original
	}
	return maskTokenRE.ReplaceAllStringFunc(masked, func(token string) string {
		if original, ok := byToken[token]; ok {
			return original
		}
		return token
	})
}

// Review c28-A: an authentication header keeps its scheme and loses only the
// credential, including short credentials and shell-quoted curl arguments.
func TestMaskAuthorizationHeaderPreservesScheme(t *testing.T) {
	gateway := maskGateway(t)
	cases := []struct {
		code       string
		credential string
	}{
		{`Authorization: Bearer abc123`, "abc123"},
		{`Authorization: Basic dXNlcjpwYXNz`, "dXNlcjpwYXNz"},
		{`Authorization:Bearer abc`, "abc"},
		{`curl -H 'Authorization: Bearer abc123' https://example.com`, "abc123"},
		{`curl -H "Authorization: Basic dXNlcjpwYXNz" https://example.com`, "dXNlcjpwYXNz"},
	}
	for _, test := range cases {
		t.Run(test.code, func(t *testing.T) {
			content, mappings := maskContent(t, gateway, test.code)
			if strings.Contains(content, test.credential) {
				t.Fatalf("credential survived: %s", content)
			}
			scheme := "Bearer"
			if strings.Contains(test.code, "Basic") {
				scheme = "Basic"
			}
			if !strings.Contains(content, scheme) {
				t.Fatalf("scheme was masked: %s", content)
			}
			if len(mappings) != 1 || mappings[0].Original != test.credential {
				t.Fatalf("mappings: %+v", mappings)
			}
			if restored := restoreOnce(content, mappings); restored != test.code {
				t.Fatalf("restore mismatch\n want %q\n got  %q", test.code, restored)
			}
		})
	}

	// A JSON Authorization value is fine to mask whole.
	recorder, response := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, map[string]any{
		"Authorization": "Bearer abc123",
	}), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d", recorder.Code)
	}
	if strings.Contains(string(response.Payload), "abc123") {
		t.Fatalf("JSON Authorization leaked: %s", response.Payload)
	}
	if len(response.Mappings) != 1 || response.Mappings[0].Original != "Bearer abc123" {
		t.Fatalf("JSON mappings: %+v", response.Mappings)
	}
}

// Review c28-B and the single-pass invariant: masking then restoring once must
// return the original text for every form, with no nested token.
func TestMaskSinglePassRestorationInvariant(t *testing.T) {
	gateway := maskGateway(t)
	cases := []string{
		`password=${dbPassword}`,
		`password={abc}`,
		`password=[abc]`,
		`password=${dbPassword} and text`,
		`Authorization: Bearer abc123`,
		`Authorization: Basic dXNlcjpwYXNz`,
		`curl -H 'Authorization: Bearer abc123' https://example.com`,
		`password="pa\"ss\\word\nend"`,
		`password='single quoted secret'`,
		`the password is: hunter2secret`,
		`密码是： hunter2secret`,
		`secretKey="SuperSecret123!"`,
		`password="$uperSecret123"`,
		`password=abc123`,
	}
	for _, code := range cases {
		t.Run(code, func(t *testing.T) {
			content, mappings := maskContent(t, gateway, code)
			if len(mappings) == 0 {
				t.Fatalf("expected at least one mapping for %q", code)
			}
			if restored := restoreOnce(content, mappings); restored != code {
				t.Fatalf("single-pass restore mismatch\n want %q\n got  %q\n masked %q\n mappings %+v", code, restored, content, mappings)
			}
			// No nested token: every token in output belongs to this response.
			for _, token := range maskTokenRE.FindAllString(content, -1) {
				if !strings.Contains(strings.Join(tokensOf(mappings), " "), token) {
					t.Fatalf("unknown token in output: %s", token)
				}
			}
		})
	}
}

func tokensOf(mappings []maskMapping) []string {
	out := make([]string, 0, len(mappings))
	for _, mapping := range mappings {
		out = append(out, mapping.Token)
	}
	return out
}

// Scheme words are only exempt inside a real Authorization header. The same
// words used as a credential must still be masked.
func TestMaskSchemeWordsAsCredentials(t *testing.T) {
	gateway := maskGateway(t)
	cases := []struct {
		code   string
		secret string
	}{
		{`password="Bot"`, "Bot"},
		{`password=Bearer`, "Bearer"},
		{`secretKey="Basic"`, "Basic"},
	}
	for _, test := range cases {
		t.Run(test.code, func(t *testing.T) {
			content, mappings := maskContent(t, gateway, test.code)
			if strings.Contains(content, `"`+test.secret+`"`) || strings.HasSuffix(content, "="+test.secret) {
				t.Fatalf("scheme word treated as exempt: %s", content)
			}
			if len(mappings) != 1 || mappings[0].Original != test.secret {
				t.Fatalf("mappings: %+v", mappings)
			}
			if restored := restoreOnce(content, mappings); restored != test.code {
				t.Fatalf("round trip failed\n want %q\n got  %q", test.code, restored)
			}
		})
	}

	// The header exemption still works in the same payload shape.
	content, mappings := maskContent(t, gateway, `Authorization: Bearer abc123`)
	if !strings.Contains(content, "Bearer") || strings.Contains(content, "abc123") {
		t.Fatalf("header scheme lost or credential kept: %s", content)
	}
	if restored := restoreOnce(content, mappings); restored != `Authorization: Bearer abc123` {
		t.Fatalf("header round trip failed: %q", restored)
	}
}

func TestMaskKnownTokenInSensitiveFieldDoesNotNest(t *testing.T) {
	gateway := maskGateway(t)
	handler := gateway.Routes()
	_, first := postMask(t, handler, maskEnvelope(t, testMaskScope, map[string]any{"password": "SyntheticReview123!"}), testClientKey)
	token := first.Mappings[0].Token
	recorder, second := postMask(t, handler, maskEnvelope(t, testMaskScope, map[string]any{"password": token}), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d", recorder.Code)
	}
	if len(second.Mappings) != 1 || second.Mappings[0].Original != "SyntheticReview123!" {
		t.Fatalf("known credential token was nested: %+v", second.Mappings)
	}
}

func TestMaskPassiveStatusProsePreservesOrdinaryWords(t *testing.T) {
	for _, text := range []string{
		"a token is left untouched; left right",
		"the password was left unchanged; left right",
	} {
		t.Run(text, func(t *testing.T) {
			gateway := maskGateway(t)
			_, response := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, map[string]any{"content": text}), testClientKey)
			if len(response.Mappings) != 0 {
				t.Fatalf("status prose became a credential: %+v", response.Mappings)
			}
		})
	}
	for _, text := range []string{`password="left"`, "token is left", `token is "left untouched"`} {
		t.Run(text, func(t *testing.T) {
			gateway := maskGateway(t)
			_, response := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, map[string]any{"content": text}), testClientKey)
			if len(response.Mappings) == 0 {
				t.Fatal("credential was not masked")
			}
		})
	}
}
