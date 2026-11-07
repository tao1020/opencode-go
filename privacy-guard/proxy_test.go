package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testClientKey   = "test-client-key-0000000000"
	testUpstreamKey = "upstream-secret-key"
)

// failingRedactor simulates a detector that could not complete.
type failingRedactor struct{ err error }

func (f failingRedactor) Secrets(context.Context, string) ([]string, error) {
	return nil, f.err
}

// upstreamCapture records what actually left the guard.
type upstreamCapture struct {
	mu      sync.Mutex
	body    []byte
	hits    int
	auth    string
	headers http.Header
}

func (c *upstreamCapture) record(r *http.Request) []byte {
	body, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.body = body
	c.hits++
	c.auth = r.Header.Get("Authorization")
	c.headers = r.Header.Clone()
	return body
}

func (c *upstreamCapture) snapshot() (body []byte, hits int, auth string, headers http.Header) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.body, c.hits, c.auth, c.headers
}

func testConfig(upstreamURL string) Config {
	return Config{
		UpstreamURL:         upstreamURL,
		ClientAPIKey:        testClientKey,
		UpstreamAPIKey:      testUpstreamKey,
		QueueTimeout:        5 * time.Second,
		ScanTimeout:         5 * time.Second,
		RequestTimeout:      30 * time.Second,
		ResponseIdleTimeout: 5 * time.Second,
	}
}

func newTestGateway(t *testing.T, upstreamURL string) *Gateway {
	t.Helper()
	gateway, err := NewGateway(testConfig(upstreamURL))
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	return gateway
}

func postChat(t *testing.T, handler http.Handler, body, key string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if key != "" {
		request.Header.Set("Authorization", "Bearer "+key)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestProxyRedactsSecretsInContentToolArgumentsAndToolResults(t *testing.T) {
	capture := &upstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer upstream.Close()

	gateway := newTestGateway(t, upstream.URL)

	body := `{"model":"gpt-4o-mini","messages":[` +
		`{"role":"user","content":"my password is hunter2"},` +
		`{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"bash","arguments":"{\"cmd\":\"curl -H 'Authorization: Bearer ghp_16C7e42F292c6912E7710c838347Ae178B4a' https://example.com\"}"}}]},` +
		`{"role":"tool","tool_call_id":"call_1","content":"export PGPASSWORD=supersecret123"},` +
		`{"role":"user","content":"密码是 SuperSecret123!"}` +
		`],"metadata":{"api_key":"lowentropyvalue"}}`

	recorder := postChat(t, gateway.Routes(), body, testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}

	forwarded, hits, auth, headers := capture.snapshot()
	if hits != 1 {
		t.Fatalf("expected exactly one upstream request, got %d", hits)
	}
	for _, secret := range []string{"hunter2", "ghp_16C7e42F292c6912E7710c838347Ae178B4a", "supersecret123", "SuperSecret123", "lowentropyvalue"} {
		if strings.Contains(string(forwarded), secret) {
			t.Errorf("secret %q reached the upstream: %s", secret, forwarded)
		}
	}
	if !strings.Contains(string(forwarded), RedactedSecret) {
		t.Errorf("no redaction marker in forwarded body: %s", forwarded)
	}
	if !json.Valid(forwarded) {
		t.Errorf("forwarded body is not valid JSON: %s", forwarded)
	}
	if !strings.Contains(string(forwarded), `"tool_calls"`) || !strings.Contains(string(forwarded), `"bash"`) {
		t.Errorf("tool call structure was lost: %s", forwarded)
	}
	if auth != "Bearer "+testUpstreamKey {
		t.Errorf("unexpected upstream Authorization header: %q", auth)
	}
	if strings.Contains(auth, testClientKey) {
		t.Errorf("client virtual key was forwarded upstream")
	}
	for name := range headers {
		switch strings.ToLower(name) {
		case "content-type", "authorization", "content-length", "host":
		default:
			t.Errorf("unexpected header forwarded upstream: %q", name)
		}
	}
}

func TestProxyRejectsOversizedBodyWithoutForwarding(t *testing.T) {
	capture := &upstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	gateway := newTestGateway(t, upstream.URL)
	huge := `{"model":"m","messages":[{"role":"user","content":"` + strings.Repeat("a", int(defaultMaxBody)+1024) + `"}]}`

	recorder := postChat(t, gateway.Routes(), huge, testClientKey)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", recorder.Code)
	}
	if _, hits, _, _ := capture.snapshot(); hits != 0 {
		t.Fatalf("oversized body reached the upstream (%d hits)", hits)
	}
}

func TestProxyRejectsMalformedJSONWithoutForwarding(t *testing.T) {
	cases := map[string]string{
		"duplicate nested key": `{"model":"m","a":{"b":1,"b":2}}`,
		"trailing data":        `{"model":"m"} {}`,
		"truncated":            `{"model":"m"`,
		"not an object":        `[1,2,3]`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			capture := &upstreamCapture{}
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capture.record(r)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			}))
			defer upstream.Close()

			gateway := newTestGateway(t, upstream.URL)
			recorder := postChat(t, gateway.Routes(), body, testClientKey)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", recorder.Code)
			}
			if _, hits, _, _ := capture.snapshot(); hits != 0 {
				t.Fatalf("malformed body reached the upstream (%d hits)", hits)
			}
		})
	}
}

// P0: client-visible errors are fixed strings; they never echo a key or value.
func TestProxyErrorsAreConstantAndContentFree(t *testing.T) {
	capture := &upstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()
	gateway := newTestGateway(t, upstream.URL)

	t.Run("duplicate sensitive key", func(t *testing.T) {
		secret := "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
		body := `{"model":"m","` + secret + `":1,"` + secret + `":2}`
		recorder := postChat(t, gateway.Routes(), body, testClientKey)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", recorder.Code)
		}
		if strings.Contains(recorder.Body.String(), "ghp_") || strings.Contains(recorder.Body.String(), secret) {
			t.Fatalf("error body leaked the key: %s", recorder.Body.String())
		}
		if !strings.Contains(recorder.Body.String(), "duplicate object key") {
			t.Fatalf("unexpected error body: %s", recorder.Body.String())
		}
	})

	t.Run("media value", func(t *testing.T) {
		body := `{"model":"m","messages":[{"role":"user","content":"data:super-secret-payload"}]}`
		recorder := postChat(t, gateway.Routes(), body, testClientKey)
		if recorder.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("expected 415, got %d", recorder.Code)
		}
		if strings.Contains(recorder.Body.String(), "super-secret-payload") {
			t.Fatalf("error body leaked the value: %s", recorder.Body.String())
		}
	})

	if _, hits, _, _ := capture.snapshot(); hits != 0 {
		t.Fatalf("rejected requests reached the upstream (%d hits)", hits)
	}
}

func TestProxySSEPassthroughIsByteExact(t *testing.T) {
	stream := "" +
		"data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"bash\",\"arguments\":\"{\\\"cmd\\\":\\\"ls\\\"}\"}}]}}]}\n\n" +
		"data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n" +
		"data: [DONE]\n\n"

	capture := &upstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.record(r)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(stream))
	}))
	defer upstream.Close()

	gateway := newTestGateway(t, upstream.URL)
	recorder := postChat(t, gateway.Routes(), `{"model":"m","stream":true,"messages":[{"role":"user","content":"ls"}]}`, testClientKey)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("content type = %q", got)
	}
	if recorder.Body.String() != stream {
		t.Fatalf("SSE body changed.\nwant: %q\ngot:  %q", stream, recorder.Body.String())
	}
}

func TestProxyScannerFailureDoesNotForward(t *testing.T) {
	capture := &upstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	gateway := newTestGateway(t, upstream.URL)
	gateway.redactor = failingRedactor{err: errors.New("detector exploded")}

	recorder := postChat(t, gateway.Routes(), `{"model":"m","messages":[{"role":"user","content":"hello"}]}`, testClientKey)
	if recorder.Code < 500 {
		t.Fatalf("expected a 5xx on scanner failure, got %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "exploded") {
		t.Fatalf("internal scanner error leaked: %s", recorder.Body.String())
	}
	if _, hits, _, _ := capture.snapshot(); hits != 0 {
		t.Fatalf("scanner failure still forwarded (%d hits)", hits)
	}
}

func TestProxyScannerTimeoutDoesNotForward(t *testing.T) {
	capture := &upstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	gateway := newTestGateway(t, upstream.URL)
	gateway.redactor = failingRedactor{err: context.DeadlineExceeded}

	recorder := postChat(t, gateway.Routes(), `{"model":"m","messages":[{"role":"user","content":"hello"}]}`, testClientKey)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", recorder.Code)
	}
	if _, hits, _, _ := capture.snapshot(); hits != 0 {
		t.Fatalf("scan timeout still forwarded (%d hits)", hits)
	}
}

func TestProxyClientAuthentication(t *testing.T) {
	capture := &upstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	gateway := newTestGateway(t, upstream.URL)
	body := `{"model":"m","messages":[]}`

	for name, key := range map[string]string{"missing": "", "wrong": "not-the-key-000000000"} {
		t.Run(name, func(t *testing.T) {
			recorder := postChat(t, gateway.Routes(), body, key)
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d", recorder.Code)
			}
		})
	}
	if _, hits, _, _ := capture.snapshot(); hits != 0 {
		t.Fatalf("unauthenticated request reached upstream (%d hits)", hits)
	}

	if recorder := postChat(t, gateway.Routes(), body, testClientKey); recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 with the right key, got %d", recorder.Code)
	}
}

func TestProxyDoesNotFollowRedirects(t *testing.T) {
	var redirected int32
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&redirected, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer redirectTarget.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusTemporaryRedirect)
	}))
	defer upstream.Close()

	gateway := newTestGateway(t, upstream.URL)
	recorder := postChat(t, gateway.Routes(), `{"model":"m","messages":[]}`, testClientKey)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for a redirect response, got %d", recorder.Code)
	}
	if atomic.LoadInt32(&redirected) != 0 {
		t.Fatalf("guard followed a redirect")
	}
}

func TestProxyUpstreamErrorIsNotEchoed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"SECRET-UPSTREAM-INCIDENT-DETAILS"}`))
	}))
	defer upstream.Close()

	gateway := newTestGateway(t, upstream.URL)
	recorder := postChat(t, gateway.Routes(), `{"model":"m","messages":[]}`, testClientKey)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "SECRET-UPSTREAM-INCIDENT-DETAILS") {
		t.Fatalf("upstream error body was echoed: %s", recorder.Body.String())
	}
}

// P0: rate limiting is the one upstream status worth preserving, with a
// validated Retry-After.
func TestProxyMapsRateLimitWithValidatedRetryAfter(t *testing.T) {
	for _, test := range []struct {
		name       string
		retryAfter string
		wantHeader string
	}{
		{"valid", "7", "7"},
		{"invalid", "not-a-number", ""},
		{"too large", "999999", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if test.retryAfter != "" {
					w.Header().Set("Retry-After", test.retryAfter)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"quota"}`))
			}))
			defer upstream.Close()

			gateway := newTestGateway(t, upstream.URL)
			recorder := postChat(t, gateway.Routes(), `{"model":"m","messages":[]}`, testClientKey)

			if recorder.Code != http.StatusTooManyRequests {
				t.Fatalf("expected 429, got %d", recorder.Code)
			}
			if got := recorder.Header().Get("Retry-After"); got != test.wantHeader {
				t.Fatalf("Retry-After = %q, want %q", got, test.wantHeader)
			}
			if strings.Contains(recorder.Body.String(), "quota") {
				t.Fatalf("upstream body echoed: %s", recorder.Body.String())
			}
		})
	}
}

func TestProxyRejectsUnexpectedUpstreamContentType(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html>nope</html>`))
	}))
	defer upstream.Close()

	gateway := newTestGateway(t, upstream.URL)
	recorder := postChat(t, gateway.Routes(), `{"model":"m","messages":[]}`, testClientKey)
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "nope") {
		t.Fatalf("upstream body was echoed: %s", recorder.Body.String())
	}
}

func TestProxyRejectsUnexpectedContentEncoding(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "br")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	gateway := newTestGateway(t, upstream.URL)
	recorder := postChat(t, gateway.Routes(), `{"model":"m","messages":[]}`, testClientKey)
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", recorder.Code)
	}
}

func TestProxyQueueTimeoutRejectsWhenBusy(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	cfg := testConfig(upstream.URL)
	cfg.MaxConcurrency = 1
	cfg.QueueTimeout = 80 * time.Millisecond
	gateway, err := NewGateway(cfg)
	if err != nil {
		t.Fatal(err)
	}
	handler := gateway.Routes()

	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		postChat(t, handler, `{"model":"m","messages":[]}`, testClientKey)
	}()
	<-started

	recorder := postChat(t, handler, `{"model":"m","messages":[]}`, testClientKey)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 while busy, got %d", recorder.Code)
	}
	close(release) // let the first request finish
	<-firstDone
}

func TestProxyResponseSizeLimitStopsStream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":"` + strings.Repeat("x", 512) + `"}`))
	}))
	defer upstream.Close()

	cfg := testConfig(upstream.URL)
	cfg.MaxResponseBytes = 64
	gateway, err := NewGateway(cfg)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- postChat(t, gateway.Routes(), `{"model":"m","messages":[]}`, testClientKey) }()

	select {
	case recorder := <-done:
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected 200 headers, got %d", recorder.Code)
		}
		if recorder.Body.Len() > 64 {
			t.Fatalf("response exceeded the cap: %d bytes", recorder.Body.Len())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("size cap did not stop the stream")
	}
}

func TestProxyResponseIdleTimeoutStopsStream(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer upstream.Close()
	defer close(release)

	cfg := testConfig(upstream.URL)
	cfg.ResponseIdleTimeout = 100 * time.Millisecond
	gateway, err := NewGateway(cfg)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	recorder := postChat(t, gateway.Routes(), `{"model":"m","messages":[]}`, testClientKey)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("idle timeout did not fire, took %v", elapsed)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 headers, got %d", recorder.Code)
	}
}

func TestProxyCancellationPropagatesUpstream(t *testing.T) {
	started := make(chan struct{})
	finished := make(chan struct{})
	var once sync.Once

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		if flusher != nil {
			flusher.Flush()
		}
		once.Do(func() { close(started) })
		for {
			select {
			case <-r.Context().Done():
				close(finished)
				return
			case <-time.After(20 * time.Millisecond):
			}
			if _, err := w.Write([]byte("data: {}\n\n")); err != nil {
				close(finished)
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	defer upstream.Close()

	gateway := newTestGateway(t, upstream.URL)
	guard := httptest.NewServer(gateway.Routes())
	defer guard.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		guard.URL+"/v1/chat/completions", strings.NewReader(`{"model":"m","stream":true,"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testClientKey)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("initial request: %v", err)
	}
	buffer := make([]byte, 32)
	if _, err := response.Body.Read(buffer); err != nil {
		t.Fatalf("read first chunk: %v", err)
	}

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never started")
	}

	cancel()
	_ = response.Body.Close()

	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream request was not cancelled after the client disconnected")
	}
}

func TestProxyMaxConcurrencyIsEnforced(t *testing.T) {
	var inFlight, maxInFlight int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt32(&inFlight, 1)
		for {
			observed := atomic.LoadInt32(&maxInFlight)
			if current <= observed || atomic.CompareAndSwapInt32(&maxInFlight, observed, current) {
				break
			}
		}
		time.Sleep(150 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	cfg := testConfig(upstream.URL)
	cfg.MaxConcurrency = 1
	gateway, err := NewGateway(cfg)
	if err != nil {
		t.Fatal(err)
	}
	handler := gateway.Routes()

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			postChat(t, handler, `{"model":"m","messages":[]}`, testClientKey)
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&maxInFlight); got != 1 {
		t.Fatalf("max concurrent upstream requests = %d, want 1", got)
	}
}

func TestProxySharedRedactorHandlesConcurrentRequests(t *testing.T) {
	capture := &upstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	gateway := newTestGateway(t, upstream.URL)
	handler := gateway.Routes()

	var wg sync.WaitGroup
	codes := make([]int, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			body := `{"model":"m","messages":[{"role":"user","content":"password=hunter` + string(rune('a'+index)) + `"}]}`
			codes[index] = postChat(t, handler, body, testClientKey).Code
		}(i)
	}
	wg.Wait()

	for i, code := range codes {
		if code != http.StatusOK {
			t.Errorf("request %d = %d", i, code)
		}
	}
	if _, hits, _, _ := capture.snapshot(); hits != 8 {
		t.Fatalf("upstream hits = %d, want 8", hits)
	}
}

func TestProxyRoutingAndHealth(t *testing.T) {
	capture := &upstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	handler := newTestGateway(t, upstream.URL).Routes()

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("healthz = %d", health.Code)
	}

	for _, test := range []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodGet, "/v1/chat/completions", http.StatusMethodNotAllowed},
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/models", http.StatusNotFound},
		{http.MethodPost, "/", http.StatusNotFound},
		{http.MethodGet, "/scan", http.StatusNotFound}, // no extra routes yet
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(test.method, test.path, strings.NewReader(`{}`)))
		if recorder.Code != test.want {
			t.Errorf("%s %s = %d, want %d", test.method, test.path, recorder.Code, test.want)
		}
	}
	if _, hits, _, _ := capture.snapshot(); hits != 0 {
		t.Fatalf("non-chat routes reached upstream (%d hits)", hits)
	}
}

// A short contextual secret must be refused with a 400 and never forwarded.
func TestProxyRejectsShortSecretWithoutForwarding(t *testing.T) {
	capture := &upstreamCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	gateway := newTestGateway(t, upstream.URL)
	body := `{"model":"m","messages":[{"role":"user","content":"database password=\"abc\""}]}`
	recorder := postChat(t, gateway.Routes(), body, testClientKey)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "too short") {
		t.Fatalf("unexpected body: %s", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "abc") {
		t.Fatalf("error leaked the value: %s", recorder.Body.String())
	}
	if _, hits, _, _ := capture.snapshot(); hits != 0 {
		t.Fatalf("short secret request reached the upstream (%d hits)", hits)
	}
}
