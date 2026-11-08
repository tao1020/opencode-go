package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Gateway is a text-only redaction guard for OpenAI-compatible Chat
// Completions traffic. It never restores anything: masking is one-way, so a
// reviewer's outbound tool arguments cannot be rehydrated into real secrets.
type Gateway struct {
	upstream       *url.URL
	upstreamKey    string
	clientKeyHash  [32]byte
	redactor       Redactor
	client         *http.Client
	sem            chan struct{}
	maxBody        int64
	maxResponse    int64
	queueTimeout   time.Duration
	scanTimeout    time.Duration
	requestTimeout time.Duration
	responseIdle   time.Duration
	maskStore      *maskStore
	reversible     bool
}

func NewGateway(cfg Config) (*Gateway, error) {
	// No upstream means scan-only mode: /inspect works, the chat proxy does not.
	scanOnly := strings.TrimSpace(cfg.UpstreamURL) == ""
	var upstream *url.URL
	if !scanOnly {
		parsed, err := validateUpstream(cfg.UpstreamURL)
		if err != nil {
			return nil, err
		}
		upstream = parsed
		if cfg.UpstreamAPIKey == "" {
			return nil, errors.New("UPSTREAM_API_KEY is required when UPSTREAM_URL is set")
		}
	}
	if len(cfg.ClientAPIKey) < 16 {
		return nil, errors.New("client API key must be at least 16 characters")
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = defaultMaxBody
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = defaultMaxResponse
	}
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = defaultMaxConcurrency
	}
	if cfg.QueueTimeout <= 0 {
		cfg.QueueTimeout = defaultQueueTimeout
	}
	if cfg.ScanTimeout <= 0 {
		cfg.ScanTimeout = defaultScanTimeout
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = defaultRequestTimeout
	}
	if cfg.ResponseIdleTimeout <= 0 {
		cfg.ResponseIdleTimeout = defaultResponseIdleTimeout
	}

	// Build one detector per gateway. Credential mode shares a bounded position
	// cache; the legacy detector serializes its library calls.
	var redactor Redactor
	switch cfg.Detector {
	case "credentials":
		redactor = &credentialRedactor{}
	case "", "gitleaks":
		var err error
		redactor, err = buildRedactor()
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("GUARD_DETECTOR must be credentials or gitleaks")
	}
	store := newMaskStore(maskMaxScopes, maskMaxMappings, maskScopeTTL)
	if cfg.Detector == "credentials" {
		store.tokenKey = []byte(cfg.ClientAPIKey)
	}

	transport := &http.Transport{
		// Ignore HTTP(S)_PROXY: the upstream is fixed by configuration and must
		// not be redirectable through the environment.
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          32,
		ForceAttemptHTTP2:     true,
		// No implicit "Accept-Encoding: gzip": the body is copied through, and a
		// compressed response would arrive without a matching header.
		DisableCompression: true,
	}

	return &Gateway{
		upstream:       upstream,
		upstreamKey:    cfg.UpstreamAPIKey,
		clientKeyHash:  sha256.Sum256([]byte(cfg.ClientAPIKey)),
		redactor:       redactor,
		maxBody:        cfg.MaxBodyBytes,
		maxResponse:    cfg.MaxResponseBytes,
		queueTimeout:   cfg.QueueTimeout,
		scanTimeout:    cfg.ScanTimeout,
		requestTimeout: cfg.RequestTimeout,
		responseIdle:   cfg.ResponseIdleTimeout,
		maskStore:      store,
		reversible:     cfg.Reversible,
		sem:            make(chan struct{}, cfg.MaxConcurrency),
		client: &http.Client{
			Transport: transport,
			// A redirect could carry the request (and its Authorization header)
			// to a host that was never validated. Redirects are never followed.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			// No client-wide timeout: the per-request context bounds the whole
			// exchange, while streaming stays unbounded up to that limit.
		},
	}, nil
}

// Routes exposes the health probe, the neutral /inspect preflight, and the chat
// proxy (which answers 404 in scan-only mode).
func (g *Gateway) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "mode": g.mode()})
	})
	mux.HandleFunc("POST /inspect", g.handleInspect)
	mux.HandleFunc("POST /mask", g.handleMask)
	mux.HandleFunc("POST /v1/chat/completions", g.handleChat)
	return mux
}

func (g *Gateway) mode() string {
	if g.upstream == nil {
		return "scan-only"
	}
	return "proxy"
}

// handleInspect is the protocol-neutral preflight: it reports counts only and
// never returns payload text.
func (g *Gateway) handleInspect(w http.ResponseWriter, r *http.Request) {
	if !g.authorized(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), g.requestTimeout)
	defer cancel()

	if !g.acquire(ctx, w) {
		return
	}
	defer func() { <-g.sem }()

	body, ok := g.readBody(w, r)
	if !ok {
		return
	}

	scanCtx, scanCancel := context.WithTimeout(ctx, g.scanTimeout)
	defer scanCancel()

	result, err := InspectPayload(scanCtx, g.redactor, body)
	if err != nil {
		if r.Context().Err() != nil {
			return
		}
		// Never return finding details on failure.
		writeError(w, statusForError(err), publicError(err))
		return
	}

	response := inspectResponse{
		Version:  1,
		Findings: result.Findings,
		Clean:    result.Findings == 0 && !result.Unsupported,
	}
	if !response.Clean {
		if result.Unsupported {
			response.Reason = "unsupported"
		} else {
			response.Reason = "secrets"
		}
	}
	writeJSON(w, http.StatusOK, response)
}

// inspectResponse is the fixed /inspect contract. No payload text is included.
type inspectResponse struct {
	Version  int    `json:"version"`
	Clean    bool   `json:"clean"`
	Findings int    `json:"findings"`
	Reason   string `json:"reason,omitempty"`
}

func (g *Gateway) handleChat(w http.ResponseWriter, r *http.Request) {
	if !g.authorized(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if g.upstream == nil {
		writeError(w, http.StatusNotFound, "chat proxy is disabled in scan-only mode")
		return
	}

	// One generous deadline covers queueing, scanning, the upstream call and the
	// response stream, so no exchange can hang forever.
	ctx, cancel := context.WithTimeout(r.Context(), g.requestTimeout)
	defer cancel()

	if !g.acquire(ctx, w) {
		return
	}
	defer func() { <-g.sem }()

	body, ok := g.readBody(w, r)
	if !ok {
		return
	}

	scanCtx, scanCancel := context.WithTimeout(ctx, g.scanTimeout)
	defer scanCancel()

	if g.reversible {
		g.forwardReversible(w, r, ctx, scanCtx, body)
		return
	}

	sanitized, redactions, err := sanitize(scanCtx, g.redactor, body)
	if err != nil {
		if r.Context().Err() != nil {
			return // client is gone; nothing to write
		}
		writeError(w, statusForError(err), publicError(err))
		return
	}

	// Log only counts: never prompt text, never a secret, never a key.
	log.Printf("redacted %d string(s); forwarding %d bytes", redactions, len(sanitized))

	g.forward(w, ctx, sanitized, nil, "")
}

// forwardReversible masks the request through the /mask core and forwards it
// with a local restore map. There is no fallback: if masking cannot complete,
// the request is refused rather than sent unmasked.
func (g *Gateway) forwardReversible(w http.ResponseWriter, r *http.Request, ctx, scanCtx context.Context, body []byte) {
	// The reversible route is deliberately narrower than the gateway's model
	// catalog. Reject any other model before masking or provider I/O; there is
	// no transparent passthrough and no account/model auto-switch.
	parsed, err := parseStrictJSON(body)
	if err != nil {
		writeError(w, maskStatus(err), maskPublicError(err))
		return
	}
	request, ok := parsed.(map[string]any)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	model, _ := request["model"].(string)
	if model != reversibleModel {
		writeError(w, http.StatusBadRequest, "unsupported model: only "+reversibleModel+" is supported")
		return
	}

	scope := g.scopeForSession(r.Header.Get("X-Opencode-Session"))

	envelope, err := json.Marshal(map[string]any{
		"version": 1,
		"scope":   scope,
		"payload": json.RawMessage(body),
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	masked, err := g.maskPayload(scanCtx, envelope)
	if err != nil {
		if r.Context().Err() != nil {
			return
		}
		writeError(w, maskStatus(err), maskPublicError(err))
		return
	}
	// Masking replaces short values with longer tokens, so a request that fit
	// the inbound cap can grow past the outbound cap. Refuse it here: the same
	// payload cap must apply before anything reaches the provider.
	if int64(len(masked.Payload)) > g.maxBody {
		writeError(w, http.StatusServiceUnavailable, "masked request exceeds size limit")
		return
	}

	mappings := make(map[string]RestoreMapping, len(masked.Mappings))
	for _, mapping := range masked.Mappings {
		mappings[mapping.Token] = RestoreMapping{
			Original:     mapping.Original,
			OriginalType: mapping.OriginalType,
		}
	}

	log.Printf("masked %d value(s); forwarding %d bytes reversibly", len(masked.Mappings), len(masked.Payload))

	g.forward(w, ctx, masked.Payload, mappings, scope)
}

// scopeForSession derives an opaque per-session scope from the client key and
// the OpenCode session header. Without a session header every request gets a
// fresh random scope, so no two unrelated requests share a vault.
func (g *Gateway) scopeForSession(session string) string {
	if session == "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return ""
		}
		return hex.EncodeToString(raw)
	}
	mac := hmac.New(sha256.New, g.clientKeyHash[:])
	mac.Write([]byte(session))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

// acquire takes a concurrency slot, rejecting (rather than queueing forever)
// when the guard is busy.
func (g *Gateway) acquire(ctx context.Context, w http.ResponseWriter) bool {
	timer := time.NewTimer(g.queueTimeout)
	defer timer.Stop()

	select {
	case g.sem <- struct{}{}:
		return true
	case <-timer.C:
		writeError(w, http.StatusServiceUnavailable, "guard is busy")
		return false
	case <-ctx.Done():
		return false
	}
}

func statusForError(err error) int {
	switch {
	case errors.Is(err, errMedia):
		return http.StatusUnsupportedMediaType
	case errors.Is(err, errDuplicateKey), errors.Is(err, errInvalidBody),
		errors.Is(err, errSecretInStructural), errors.Is(err, errShortSecret):
		return http.StatusBadRequest
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		// A scan that did not finish is never treated as "nothing found".
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// publicError maps an internal error to a fixed message. Internal errors can
// contain key names or fragments, so err.Error() is never returned.
func publicError(err error) string {
	switch {
	case errors.Is(err, errMedia):
		return "media or binary content is not supported"
	case errors.Is(err, errDuplicateKey):
		return "duplicate object key"
	case errors.Is(err, errInvalidBody):
		return "invalid request body"
	case errors.Is(err, errSecretInStructural):
		return "secret in structural field"
	case errors.Is(err, errShortSecret):
		return "secret too short to redact safely"
	case errors.Is(err, context.DeadlineExceeded):
		return "scan timed out"
	case errors.Is(err, context.Canceled):
		return "request cancelled"
	default:
		return "request rejected"
	}
}

func (g *Gateway) authorized(r *http.Request) bool {
	var presented []byte
	if header := r.Header.Get("Authorization"); strings.HasPrefix(header, "Bearer ") {
		presented = []byte(strings.TrimPrefix(header, "Bearer "))
	}
	hash := sha256.Sum256(presented)
	// Compare digests so the comparison is constant time and does not leak the
	// expected key's length.
	return subtle.ConstantTimeCompare(hash[:], g.clientKeyHash[:]) == 1
}

func (g *Gateway) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, g.maxBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			// Reject, never forward a truncated body.
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return nil, false
		}
		writeError(w, http.StatusBadRequest, "unreadable request body")
		return nil, false
	}
	return body, true
}

// reversibleUserAgent is the fixed client identity sent upstream in reversible
// mode. Client headers are never forwarded.
const reversibleUserAgent = "opencode/1.16.2"

// reversibleModel is the only model the reversible Coder proxy accepts. The
// auxiliary title/compaction requests use the same model with a lower reasoning
// effort, so reasoning is not part of this gate.
const reversibleModel = "deepseek-v4.1-flash"

func (g *Gateway) forward(w http.ResponseWriter, ctx context.Context, body []byte, restore map[string]RestoreMapping, scope string) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, g.upstream.String(), bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusBadGateway, "could not build upstream request")
		return
	}
	// Exactly two headers cross the boundary. The client's Authorization header
	// is a virtual key; the real upstream credential is injected here and never
	// comes from the client.
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+g.upstreamKey)
	// Suppress Go's default User-Agent.
	request.Header.Set("User-Agent", "")
	if restore != nil {
		// Reversible mode presents a fixed client identity and an opaque
		// session pseudonym. No other client header (including any X-*) is sent.
		request.Header.Set("User-Agent", reversibleUserAgent)
		if scope != "" {
			request.Header.Set("x-opencode-session", scope)
		}
	}

	response, err := g.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				writeError(w, http.StatusGatewayTimeout, "upstream timed out")
			}
			return // otherwise the client is gone
		}
		writeError(w, http.StatusBadGateway, "upstream unreachable")
		return
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		// Never drain an upstream error body: a stalled body would block the
		// handler after headers were already received.
		if response.StatusCode == http.StatusTooManyRequests {
			if retryAfter, ok := validRetryAfter(response.Header.Get("Retry-After")); ok {
				w.Header().Set("Retry-After", retryAfter)
			}
			writeError(w, http.StatusTooManyRequests, "upstream rate limited")
			return
		}
		writeError(w, http.StatusBadGateway, "upstream returned an error")
		return
	}

	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		writeError(w, http.StatusBadGateway, "upstream returned an unsupported encoding")
		return
	}

	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && mediaType != "text/event-stream") {
		writeError(w, http.StatusBadGateway, "upstream returned an unsupported content type")
		return
	}

	if restore != nil {
		g.relayRestored(w, ctx, response, mediaType, restore)
		return
	}

	// The response is passed through byte for byte, including SSE tool-call
	// fragments. Nothing is scanned or rewritten on the way back.
	w.Header().Set("Content-Type", mediaType)
	w.WriteHeader(response.StatusCode)

	flusher, _ := w.(http.Flusher)
	if err := copyBounded(w, response.Body, flusher, g.responseIdle, g.maxResponse); err != nil {
		log.Printf("response stream ended: %v", err)
	}
}

// copyBounded streams a response with an idle timeout and a hard size cap. A
// stalled upstream closes the body and unblocks the read.
func copyBounded(dst io.Writer, src io.ReadCloser, flusher http.Flusher, idle time.Duration, maxBytes int64) error {
	timer := time.AfterFunc(idle, func() { _ = src.Close() })
	defer timer.Stop()

	buffer := make([]byte, 32*1024)
	var total int64
	for {
		n, err := src.Read(buffer)
		if n > 0 {
			total += int64(n)
			if total > maxBytes {
				return errors.New("response exceeded size limit")
			}
			if _, writeErr := dst.Write(buffer[:n]); writeErr != nil {
				return errors.New("client closed the stream")
			}
			if flusher != nil {
				flusher.Flush()
			}
			timer.Reset(idle)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return errors.New("upstream stream interrupted")
		}
	}
}

// validRetryAfter accepts only a small integer number of seconds.
func validRetryAfter(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds < 0 || seconds > 3600 {
		return "", false
	}
	return strconv.Itoa(seconds), true
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// validateUpstream enforces the fixed, pre-validated destination: HTTPS
// everywhere, plain HTTP only for loopback (tests).
func validateUpstream(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("UPSTREAM_URL is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("UPSTREAM_URL is not a valid URL")
	}
	if parsed.User != nil {
		return nil, errors.New("UPSTREAM_URL must not contain credentials")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("UPSTREAM_URL must not contain a query or fragment")
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(parsed.Hostname()) {
			return nil, errors.New("UPSTREAM_URL must use https unless the host is loopback")
		}
	default:
		return nil, errors.New("UPSTREAM_URL must be an http(s) URL")
	}
	if parsed.Host == "" {
		return nil, errors.New("UPSTREAM_URL is missing a host")
	}
	return parsed, nil
}

func isLoopbackHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	return false
}

// relayRestored writes the upstream response back with local token restoration.
//
// JSON is restored into a buffer before any header is written, so a restorer
// failure is still an ordinary 502. SSE is streamed as it arrives; if the
// restorer fails mid-stream the connection is aborted rather than terminated
// normally, so a client never sees a completed-looking tool call.
func (g *Gateway) relayRestored(w http.ResponseWriter, ctx context.Context, response *http.Response, mediaType string, mappings map[string]RestoreMapping) {
	restoreCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	guarded, stop := g.guardIdle(restoreCtx, cancel, response.Body)
	defer stop()

	if mediaType == "application/json" {
		raw, err := io.ReadAll(io.LimitReader(guarded, g.maxResponse+1))
		if err != nil || int64(len(raw)) > g.maxResponse {
			writeError(w, http.StatusBadGateway, "upstream returned an unsupported body")
			return
		}
		var restored bytes.Buffer
		if err := RestoreChatResponseTyped(restoreCtx, bytes.NewReader(raw), &restored, mediaType, mappings); err != nil {
			// Fixed message: never log response bytes, tokens or originals.
			log.Printf("restore failed: invalid JSON response")
			writeError(w, http.StatusBadGateway, "upstream response could not be restored")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)
		_, _ = w.Write(restored.Bytes())
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(response.StatusCode)
	writer := &restoreFlushWriter{w: w, controller: http.NewResponseController(w)}
	if err := RestoreChatResponseTyped(restoreCtx, guarded, writer, mediaType, mappings); err != nil {
		log.Printf("restore failed: SSE stream aborted")
		// No normal end-of-response: close the connection so the client cannot
		// treat the truncated stream as complete.
		panic(http.ErrAbortHandler)
	}
}

// restoreFlushWriter flushes after every write so SSE deltas leave promptly.
type restoreFlushWriter struct {
	w          http.ResponseWriter
	controller *http.ResponseController
}

func (f *restoreFlushWriter) Write(p []byte) (int, error) {
	written, err := f.w.Write(p)
	if err == nil {
		_ = f.controller.Flush()
	}
	return written, err
}

// guardIdle cancels the read when the upstream goes silent for longer than the
// configured idle timeout. The timer is stopped on return, so no goroutine or
// timer is left behind.
func (g *Gateway) guardIdle(ctx context.Context, cancel context.CancelFunc, body io.Reader) (io.Reader, func()) {
	timer := time.AfterFunc(g.responseIdle, cancel)
	return &idleGuardReader{reader: body, timer: timer, idle: g.responseIdle}, func() { timer.Stop() }
}

type idleGuardReader struct {
	reader io.Reader
	timer  *time.Timer
	idle   time.Duration
}

func (r *idleGuardReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.timer.Reset(r.idle)
	}
	return n, err
}
