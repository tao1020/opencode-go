package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	testSessionA = "opencode-session-A"
	testSessionB = "opencode-session-B"
)

func reversibleGateway(t *testing.T, upstreamURL string) *Gateway {
	t.Helper()
	cfg := testConfig(upstreamURL)
	cfg.Reversible = true
	gateway, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	return gateway
}

// maskedRequest mirrors the OpenCode Go request shape: DeepSeek model, reasoning
// effort, a text secret, and an edit tool carrying both a number and a string.
func maskedRequest() string {
	return `{"model":"deepseek-v4.1-flash","reasoning_effort":"high","stream":false,"messages":[` +
		`{"role":"user","content":"database password=\"SuperSecret123!\""},` +
		`{"role":"assistant","content":null,"tool_calls":[{"id":"c0","type":"function",` +
		`"function":{"name":"edit","arguments":"{\"password\":123456,\"old\":\"SuperSecret123!\"}"}}]}]}`
}

type maskedTokens struct {
	content string
	number  string
}

// tokensFromMaskedBody pulls the tokens the proxy minted, the way a model would
// echo them back.
func tokensFromMaskedBody(t *testing.T, body []byte) maskedTokens {
	t.Helper()
	var request struct {
		Messages []struct {
			Content   string `json:"content"`
			ToolCalls []struct {
				Function struct {
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatalf("masked request is not JSON: %v", err)
	}
	var tokens maskedTokens
	for _, message := range request.Messages {
		if token := maskTokenRE.FindString(message.Content); token != "" {
			tokens.content = token
		}
		for _, call := range message.ToolCalls {
			var arguments map[string]any
			if err := json.Unmarshal([]byte(call.Function.Arguments), &arguments); err != nil {
				continue
			}
			if value, ok := arguments["password"].(string); ok && maskTokenRE.MatchString(value) {
				tokens.number = value
			}
		}
	}
	if tokens.content == "" || tokens.number == "" {
		t.Fatalf("expected masked tokens in the forwarded request: %s", body)
	}
	return tokens
}

func reversiblePost(t *testing.T, handler http.Handler, body string, session string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testClientKey)
	if session != "" {
		request.Header.Set("X-Opencode-Session", session)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// The upstream echoes the tokens it was given; the client must see the real
// values again, with the numeric tool argument restored as a JSON number.
func TestReversibleProxyRestoresJSONResponse(t *testing.T) {
	capture := &upstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := capture.record(r)
		tokens := tokensFromMaskedBody(t, body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"x","choices":[{"message":{"role":"assistant","content":"copy %s",`+
			`"tool_calls":[{"id":"c1","type":"function","function":{"name":"edit",`+
			`"arguments":"{\"password\":\"%s\",\"old\":\"%s\"}"}}]}}]}`,
			tokens.content, tokens.number, tokens.content)
	}))
	defer upstream.Close()

	gateway := reversibleGateway(t, upstream.URL)
	recorder := reversiblePost(t, gateway.Routes(), maskedRequest(), testSessionA)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), maskTokenPrefix) {
		t.Fatalf("token leaked to the client: %s", recorder.Body.String())
	}

	var response struct {
		Choices []struct {
			Message struct {
				Content   string `json:"content"`
				ToolCalls []struct {
					Function struct {
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("restored response is not JSON: %v", err)
	}
	message := response.Choices[0].Message
	if message.Content != "copy SuperSecret123!" {
		t.Fatalf("content = %q", message.Content)
	}
	var arguments struct {
		Password json.Number `json:"password"`
		Old      string      `json:"old"`
	}
	if err := json.Unmarshal([]byte(message.ToolCalls[0].Function.Arguments), &arguments); err != nil {
		t.Fatalf("restored arguments are not JSON: %v (%s)", err, message.ToolCalls[0].Function.Arguments)
	}
	if arguments.Password.String() != "123456" {
		t.Fatalf("numeric argument restored as %q", arguments.Password)
	}
	if arguments.Old != "SuperSecret123!" {
		t.Fatalf("string argument restored as %q", arguments.Old)
	}
}

// Provider-facing policy: fixed UA, pseudonymous session header, no client
// metadata, upstream credential injected, and the request semantics preserved.
func TestReversibleProxyProviderHeadersAndFields(t *testing.T) {
	capture := &upstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := capture.record(r)
		tokens := tokensFromMaskedBody(t, body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"choices":[{"message":{"role":"assistant","content":"%s"}}]}`, tokens.content)
	}))
	defer upstream.Close()

	gateway := reversibleGateway(t, upstream.URL)
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(maskedRequest()))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testClientKey)
	request.Header.Set("X-Opencode-Session", testSessionA)
	request.Header.Set("X-Metadata", "must-not-be-forwarded")
	request.Header.Set("User-Agent", "some-client/9.9")
	recorder := httptest.NewRecorder()
	gateway.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	forwarded, _, auth, headers := capture.snapshot()
	if got := headers.Get("User-Agent"); got != reversibleUserAgent {
		t.Fatalf("User-Agent = %q, want %q", got, reversibleUserAgent)
	}
	session := headers.Get("X-Opencode-Session")
	if len(session) != 32 || !maskScopePattern.MatchString(session) {
		t.Fatalf("session header is not an opaque 32-char scope: %q", session)
	}
	if session == testSessionA {
		t.Fatal("raw client session was forwarded")
	}
	if headers.Get("X-Metadata") != "" {
		t.Fatal("client metadata header was forwarded")
	}
	if auth != "Bearer "+testUpstreamKey {
		t.Fatalf("upstream Authorization = %q", auth)
	}

	var parsed map[string]any
	if err := json.Unmarshal(forwarded, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["model"] != "deepseek-v4.1-flash" || parsed["reasoning_effort"] != "high" {
		t.Fatalf("request semantics changed: %v %v", parsed["model"], parsed["reasoning_effort"])
	}
}

// The same OpenCode session keeps its tokens; another session and a request with
// no session header must not share them.
func TestReversibleProxySessionIsolation(t *testing.T) {
	capture := &upstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := capture.record(r)
		tokens := tokensFromMaskedBody(t, body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"choices":[{"message":{"role":"assistant","content":"ok %s"}}]}`, tokens.content)
	}))
	defer upstream.Close()

	gateway := reversibleGateway(t, upstream.URL)
	handler := gateway.Routes()

	first := tokensFromMaskedBody(t, captureAfter(t, handler, testSessionA, capture))
	second := tokensFromMaskedBody(t, captureAfter(t, handler, testSessionA, capture))
	if first.content != second.content {
		t.Fatalf("same session changed token: %q vs %q", first.content, second.content)
	}

	other := tokensFromMaskedBody(t, captureAfter(t, handler, testSessionB, capture))
	if other.content == first.content {
		t.Fatalf("different sessions shared a token: %q", other.content)
	}

	anonymous1 := tokensFromMaskedBody(t, captureAfter(t, handler, "", capture))
	anonymous2 := tokensFromMaskedBody(t, captureAfter(t, handler, "", capture))
	if anonymous1.content == anonymous2.content {
		t.Fatal("requests without a session must not share a scope")
	}
}

// captureAfter returns the masked body the proxy forwarded for this request.
// The handler runs synchronously, so the capture already holds it.
func captureAfter(t *testing.T, handler http.Handler, session string, capture *upstreamCapture) []byte {
	t.Helper()
	recorder := reversiblePost(t, handler, maskedRequest(), session)
	if recorder.Code != http.StatusOK {
		t.Fatalf("request failed: %d %s", recorder.Code, recorder.Body.String())
	}
	body, _, _, _ := capture.snapshot()
	if len(body) == 0 {
		t.Fatal("upstream captured no body")
	}
	return body
}

// A mask failure must refuse the request; it must never forward unmasked.
func TestReversibleProxyNoFallbackWhenMaskingFails(t *testing.T) {
	capture := &upstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer upstream.Close()

	gateway := reversibleGateway(t, upstream.URL)
	gateway.maskStore = newMaskStore(10, 100, time.Hour)
	gateway.maskStore.perScopeBudget = 1 // smaller than any secret

	recorder := reversiblePost(t, gateway.Routes(), maskedRequest(), testSessionA)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if _, hits, _, _ := capture.snapshot(); hits != 0 {
		t.Fatalf("unmasked request was forwarded (%d hits)", hits)
	}
}

// The reversible route is scoped to one model. Any other model is refused
// before masking and never reaches the provider.
func TestReversibleProxyRejectsUnsupportedModel(t *testing.T) {
	capture := &upstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer upstream.Close()

	gateway := reversibleGateway(t, upstream.URL)
	body := strings.Replace(maskedRequest(), `"model":"deepseek-v4.1-flash"`, `"model":"gpt-4o-mini"`, 1)
	recorder := reversiblePost(t, gateway.Routes(), body, testSessionA)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if _, hits, _, _ := capture.snapshot(); hits != 0 {
		t.Fatalf("unsupported model reached the upstream (%d hits)", hits)
	}
	if !strings.Contains(recorder.Body.String(), reversibleModel) {
		t.Fatalf("error should name the supported model: %s", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "gpt-4o-mini") {
		t.Fatalf("error echoed the rejected model: %s", recorder.Body.String())
	}
}

// Auxiliary title/compaction calls use the same model with a lower reasoning
// effort. The model gate must not require high reasoning.
func TestReversibleProxyPreservesAuxiliaryLowReasoning(t *testing.T) {
	capture := &upstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer upstream.Close()

	gateway := reversibleGateway(t, upstream.URL)
	body := strings.Replace(maskedRequest(), `"reasoning_effort":"high"`, `"reasoning_effort":"low"`, 1)
	recorder := reversiblePost(t, gateway.Routes(), body, testSessionA)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	forwarded, _, _, _ := capture.snapshot()
	var parsed struct {
		Model     string `json:"model"`
		Reasoning string `json:"reasoning_effort"`
	}
	if err := json.Unmarshal(forwarded, &parsed); err != nil {
		t.Fatalf("forwarded body is not JSON: %v", err)
	}
	if parsed.Model != reversibleModel || parsed.Reasoning != "low" {
		t.Fatalf("forwarded model/reasoning = %q/%q", parsed.Model, parsed.Reasoning)
	}
}

// Tokens are longer than the values they replace, so a request that fits the
// inbound cap can exceed the outbound cap after masking. It must be refused
// before any provider I/O.
func TestReversibleProxyRejectsMaskedPayloadOverLimit(t *testing.T) {
	capture := &upstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer upstream.Close()

	gateway := reversibleGateway(t, upstream.URL)
	body := maskedRequest()
	gateway.maxBody = int64(len(body))
	recorder := reversiblePost(t, gateway.Routes(), body, testSessionA)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if _, hits, _, _ := capture.snapshot(); hits != 0 {
		t.Fatalf("masked oversized request reached the upstream (%d hits)", hits)
	}
}

// SSE is restored incrementally and flushed to the client.
func TestReversibleProxyRestoresSSE(t *testing.T) {
	capture := &upstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := capture.record(r)
		tokens := tokensFromMaskedBody(t, body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		half := len(tokens.content) / 2
		fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":\"copy %s\"}}]}\n\n", tokens.content[:half])
		if flusher != nil {
			flusher.Flush()
		}
		fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":\"%s done\"}}]}\n\n", tokens.content[half:])
		if flusher != nil {
			flusher.Flush()
		}
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer upstream.Close()

	gateway := reversibleGateway(t, upstream.URL)
	guard := httptest.NewServer(gateway.Routes())
	defer guard.Close()

	request, err := http.NewRequest(http.MethodPost, guard.URL+"/v1/chat/completions", strings.NewReader(maskedRequest()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testClientKey)
	request.Header.Set("X-Opencode-Session", testSessionA)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("stream read failed: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, "SuperSecret123!") {
		t.Fatalf("SSE token was not restored: %s", text)
	}
	if strings.Contains(text, maskTokenPrefix) {
		t.Fatalf("token leaked in SSE: %s", text)
	}
	if !strings.Contains(text, "[DONE]") {
		t.Fatalf("stream did not complete: %s", text)
	}
}

// A restorer failure mid-stream must abort the connection, not finish normally.
func TestReversibleProxyAbortsOnInvalidSSE(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture := &upstreamCapture{}
		body := capture.record(r)
		tokens := tokensFromMaskedBody(t, body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":\"%s\"}}]}\n\n", tokens.content)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		_, _ = w.Write([]byte("data: {not-json\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer upstream.Close()

	gateway := reversibleGateway(t, upstream.URL)
	guard := httptest.NewServer(gateway.Routes())
	defer guard.Close()

	request, _ := http.NewRequest(http.MethodPost, guard.URL+"/v1/chat/completions", strings.NewReader(maskedRequest()))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testClientKey)
	request.Header.Set("X-Opencode-Session", testSessionA)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return // aborted before headers is also acceptable
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(response.Body)
	if readErr == nil && strings.Contains(string(body), "[DONE]") {
		t.Fatalf("invalid stream completed normally: %s", body)
	}
}

// JSON restore failures are still an ordinary 502 because nothing was written yet.
func TestReversibleProxyRestoreFailureIs502(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture := &upstreamCapture{}
		capture.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[`))
	}))
	defer upstream.Close()

	gateway := reversibleGateway(t, upstream.URL)
	recorder := reversiblePost(t, gateway.Routes(), maskedRequest(), testSessionA)
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "choices") {
		t.Fatalf("upstream bytes leaked: %s", recorder.Body.String())
	}
}

// With the flag off, behaviour and header policy are exactly as before.
func TestReversibleProxyDisabledByDefault(t *testing.T) {
	capture := &upstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"echo [REDACTED_SECRET]"}}]}`))
	}))
	defer upstream.Close()

	gateway := newTestGateway(t, upstream.URL) // Reversible stays false
	recorder := reversiblePost(t, gateway.Routes(), maskedRequest(), testSessionA)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	forwarded, _, _, headers := capture.snapshot()
	if strings.Contains(string(forwarded), "SuperSecret123!") || strings.Contains(string(forwarded), maskTokenPrefix) {
		t.Fatalf("irreversible path body changed: %s", forwarded)
	}
	if headers.Get("X-Opencode-Session") != "" {
		t.Fatal("session header must not be added in irreversible mode")
	}
	if headers.Get("User-Agent") != "" {
		t.Fatalf("User-Agent should stay suppressed, got %q", headers.Get("User-Agent"))
	}
	if !strings.Contains(recorder.Body.String(), "[REDACTED_SECRET]") {
		t.Fatalf("response should pass through unchanged: %s", recorder.Body.String())
	}
}

func TestResolveUpstreamKeySources(t *testing.T) {
	t.Run("from environment", func(t *testing.T) {
		t.Setenv("UPSTREAM_API_KEY", "env-upstream-key")
		t.Setenv("UPSTREAM_API_KEY_FILE", "")
		key, err := resolveUpstreamKey(true)
		if err != nil || key != "env-upstream-key" {
			t.Fatalf("key=%q err=%v", key, err)
		}
	})
	t.Run("from file", func(t *testing.T) {
		path := writeKeyFile(t, 0o600, "file-upstream-key\n")
		t.Setenv("UPSTREAM_API_KEY", "")
		t.Setenv("UPSTREAM_API_KEY_FILE", path)
		key, err := resolveUpstreamKey(true)
		if err != nil || key != "file-upstream-key" {
			t.Fatalf("key=%q err=%v", key, err)
		}
	})
	t.Run("both rejected", func(t *testing.T) {
		path := writeKeyFile(t, 0o600, "file-upstream-key")
		t.Setenv("UPSTREAM_API_KEY", "env-upstream-key")
		t.Setenv("UPSTREAM_API_KEY_FILE", path)
		if _, err := resolveUpstreamKey(true); err == nil {
			t.Fatal("expected rejection when both sources are set")
		}
	})
	t.Run("missing when upstream configured", func(t *testing.T) {
		t.Setenv("UPSTREAM_API_KEY", "")
		t.Setenv("UPSTREAM_API_KEY_FILE", "")
		if _, err := resolveUpstreamKey(true); err == nil {
			t.Fatal("expected rejection when no source is set")
		}
		if key, err := resolveUpstreamKey(false); err != nil || key != "" {
			t.Fatalf("scan-only should not need upstream key: %q %v", key, err)
		}
	})
}
