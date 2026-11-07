package main

// Experimental reversible masking core (POST /mask), scoped to the OpenCode Go
// OpenAI Chat JSON shape: text blocks, DeepSeek `reasoning_content`, and
// tool-call arguments that are themselves JSON strings.
//
// It masks secrets and returns token→original mappings so the local client can
// restore what it displays. There is no /restore endpoint and no persistence:
// the caller owns the mappings for the request it just sent, and the vault is
// in-memory only.
//
// This file is isolated from the Chat proxy and /inspect semantics.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	maskVersion      = 1
	maskTokenPrefix  = "__PG_"
	maskTokenBytes   = 16
	maskTokenHexLen  = maskTokenBytes * 2
	maskMaxScopes    = 1024
	maskMaxMappings  = 20000
	maskScopeTTL     = time.Hour
	maskMinScopeLen  = 32
	maskMaxScopeLen  = 128
	maskMinPropagate = 4

	// Memory is bounded by retained bytes, not only by entry counts: a scope
	// could otherwise hold thousands of multi-megabyte originals.
	maskGlobalBudget   = 8 << 20 // 8 MiB of originals across all scopes
	maskPerScopeBudget = 4 << 20 // 4 MiB of originals in one scope
	maskMaxResponse    = 8 << 20 // 8 MiB encoded response, checked before writing
)

var (
	errMaskScope      = errors.New("invalid mask scope")
	errMaskCapacity   = errors.New("mask capacity exceeded")
	errMaskToolArgs   = errors.New("malformed tool arguments JSON")
	errMaskStructural = errors.New("secret in structural field")
)

var maskScopePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// maskTokenRE finds tokens already present in a payload, e.g. a value the client
// masked on an earlier turn and is now echoing back in replayState.
var maskTokenRE = regexp.MustCompile(`__PG_[0-9a-f]{32}__`)

// Context patterns locate a credential assignment precisely. A one-character
// password is safe to mask because only this span is replaced.
var (
	maskAssignRE  = regexp.MustCompile(`(?i)[a-z0-9_.-]*(?:password|passwd|pwd|passphrase|passcode|secret[_-]?key|secretkey|secret|token|api[_-]?key|apikey|signing[_-]?key|signingkey|encryption[_-]?key|encryptionkey|access[_-]?key|accesskey|private[_-]?key|privatekey|client[_-]?secret|clientsecret|credential|credentials|auth[_-]?token|authtoken|authorization|bearer)\s*(?:\\*["'])?\s*(?::=|[:=])\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s"',;}]*)`)
	maskProseENRE = regexp.MustCompile(`(?i)(?:\b|\\[nrt])(?:password|passwd|passphrase|passcode|secret|api[ _-]?key|access token|token)(?:\b|\\[nrt])\s*(?:(?:is|was|are|were)\s*[:=]?\s*|[:=]\s*)("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s"',;.)]+)`)
	maskProseZHRE = regexp.MustCompile(`(?:密码|口令|密钥|秘钥|令牌|凭证)\s*(?:(?:是|为|改成|设置为)\s*[:：＝=]?\s*|[:：＝=]\s*)("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|“[^”]*”|[^\s"'“”，。；、）)]+)`)
)

// maskAuthHeaderRE finds an authentication header and keeps the scheme readable
// while masking the credential that follows it. It works on plain text, so a
// curl -H argument quoted by a shell is covered too.
var maskAuthHeaderRE = regexp.MustCompile(`(?i)(?:\b|\\[nrt])((?:proxy-)?authorization\s*:\s*)(bearer|basic|digest|negotiate|token|bot)\s+("[^"]*"|'[^']*'|[^\s"'\\,;]+)`)

// authSchemeSpans returns the scheme spans of real Authorization headers in the
// text. Only these positions are exempt from the generic assignment rule: a
// value such as password="Bot" is an ordinary secret, not a scheme.
func authSchemeSpans(text string) []textSpan {
	var spans []textSpan
	for _, match := range maskEscapedAuthRE.FindAllStringSubmatchIndex(text, -1) {
		spans = append(spans, textSpan{start: match[2], end: match[3]})
	}
	for _, match := range maskAuthHeaderRE.FindAllStringSubmatchIndex(text, -1) {
		if match[4] >= 0 && match[5] > match[4] {
			spans = append(spans, textSpan{start: match[4], end: match[5]})
		}
	}
	return spans
}

// A source expression that reads a secret from the environment is not itself a
// secret. These well-formed forms are recognised lexically and left untouched,
// so the model sees working code instead of a masked identifier.
var maskReferenceREs = []*regexp.Regexp{
	regexp.MustCompile(`(?:\b|\\[nrt])os\.environ\[\s*(?:\\*["'])[A-Za-z_][A-Za-z0-9_]*(?:\\*["'])\s*\]`),
	regexp.MustCompile(`(?:\b|\\[nrt])os\.environ\.get\(\s*(?:\\*["'])[A-Za-z_][A-Za-z0-9_]*(?:\\*["'])\s*\)`),
	regexp.MustCompile(`(?:\b|\\[nrt])os\.(?:getenv|Getenv)\(\s*(?:\\*["'])[A-Za-z_][A-Za-z0-9_]*(?:\\*["'])\s*\)`),
	// Call prefix of the two-argument form: the callee and the variable name are
	// context, while the fallback literal after the comma is still scannable.
	regexp.MustCompile(`(?:\b|\\[nrt])os\.(?:getenv|Getenv|environ\.get)\(\s*(?:\\*["'])[A-Za-z_][A-Za-z0-9_]*(?:\\*["'])`),
	regexp.MustCompile(`(?:\b|\\[nrt])process\.env\.[A-Za-z_][A-Za-z0-9_]*`),
	regexp.MustCompile(`(?:\b|\\[nrt])process\.env\[\s*(?:\\*["'])[A-Za-z_][A-Za-z0-9_]*(?:\\*["'])\s*\]`),
	regexp.MustCompile(`\$\{[A-Z_][A-Z0-9_]*\}`),
	regexp.MustCompile(`\$[A-Z_][A-Z0-9_]*`),
}

type textSpan struct {
	start int
	end   int
}

func referenceSpans(text string) []textSpan {
	var spans []textSpan
	for _, re := range maskReferenceREs {
		for _, match := range re.FindAllStringIndex(text, -1) {
			spans = append(spans, textSpan{start: match[0], end: match[1]})
		}
	}
	return spans
}

func withinReference(spans []textSpan, start, end int) bool {
	for _, span := range spans {
		if start >= span.start && end <= span.end {
			return true
		}
	}
	return false
}

// isExactReference reports whether the whole value is one well-formed reference.
func isExactReference(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	for _, re := range maskReferenceREs {
		if loc := re.FindStringIndex(trimmed); loc != nil && loc[0] == 0 && loc[1] == len(trimmed) {
			return true
		}
	}
	return false
}

// scrubReferences blanks reference spans so the detector never reports an
// environment variable name as a secret.
func scrubReferences(text string) string {
	spans := referenceSpans(text)
	if len(spans) == 0 {
		return text
	}
	out := []byte(text)
	for _, span := range spans {
		for i := span.start; i < span.end && i < len(out); i++ {
			out[i] = ' '
		}
	}
	return string(out)
}

// maskAuthorizationHeaders masks only the credential part of an authentication
// header, so `Authorization: Bearer abc123` keeps its scheme and loses the
// secret. A short credential is masked here as a whole value, not by the
// whole-string propagation rule.
func (m *masker) maskAuthorizationHeaders(text string) (string, error) {
	matches := maskAuthHeaderRE.FindAllStringSubmatchIndex(text, -1)
	for i := len(matches) - 1; i >= 0; i-- {
		start, end := matches[i][6], matches[i][7]
		if start < 0 || end <= start {
			continue
		}
		raw := text[start:end]
		inner, prefix, suffix := raw, "", ""
		switch {
		case len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"':
			inner, prefix, suffix = raw[1:len(raw)-1], `"`, `"`
		case len(raw) >= 2 && raw[0] == '\'' && raw[len(raw)-1] == '\'':
			inner, prefix, suffix = raw[1:len(raw)-1], `'`, `'`
		}
		if inner == "" || isExactReference(inner) || m.containsKnownToken(inner) {
			continue
		}
		token, err := m.token(inner, "")
		if err != nil {
			return "", err
		}
		text = text[:start] + prefix + token + suffix + text[end:]
	}
	return text, nil
}

// maskUnknownTokens replaces a token-shaped string that this request did not
// mint and this scope does not own with a fresh opaque token. The fresh token
// maps back to the original literal, so restoration stays single-pass and no
// old token reaches the model. A client refuses an unknown token in tool
// arguments; a token left over from an earlier process would otherwise survive
// a restart and fail every turn that reuses the old history.
//
// It runs after credential and secret masking: a secret that embeds a token
// literal is masked as one value, never split into a nested mapping.
func (m *masker) maskUnknownTokens(text string) (string, error) {
	if !strings.Contains(text, maskTokenPrefix) {
		return text, nil
	}
	matches := maskTokenRE.FindAllStringIndex(text, -1)
	for i := len(matches) - 1; i >= 0; i-- {
		start, end := matches[i][0], matches[i][1]
		token := text[start:end]
		if m.isKnownToken(token) {
			continue
		}
		fresh, err := m.token(token, "")
		if err != nil {
			return "", err
		}
		text = text[:start] + fresh + text[end:]
	}
	return text, nil
}

// containsKnownToken reports whether the text embeds a token this request minted
// or this scope owns. Such a capture is already handled; re-masking it would
// nest tokens and break single-pass restoration.
func (m *masker) containsKnownToken(text string) bool {
	for _, token := range maskTokenRE.FindAllString(text, -1) {
		if m.isKnownToken(token) {
			return true
		}
	}
	return false
}

// maskReferenceDefaults masks a hardcoded fallback inside a two-argument
// environment lookup. The lookup itself stays readable; only the literal default
// is treated as a value.
func (m *masker) maskReferenceDefaults(text string) (string, error) {
	matches := maskRefDefaultRE.FindAllStringSubmatchIndex(text, -1)
	for i := len(matches) - 1; i >= 0; i-- {
		start, end := matches[i][2], matches[i][3]
		if start < 0 || end <= start {
			continue
		}
		raw := text[start:end]
		if isExactReference(raw) {
			continue
		}
		inner, prefix, suffix := raw, "", ""
		switch {
		case len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"':
			inner, prefix, suffix = raw[1:len(raw)-1], `"`, `"`
		case len(raw) >= 2 && raw[0] == '\'' && raw[len(raw)-1] == '\'':
			inner, prefix, suffix = raw[1:len(raw)-1], `'`, `'`
		}
		if inner == "" || m.containsKnownToken(inner) {
			continue
		}
		token, err := m.token(inner, "")
		if err != nil {
			return "", err
		}
		text = text[:start] + prefix + token + suffix + text[end:]
	}
	return text, nil
}

var maskRefDefaultRE = regexp.MustCompile(`(?:\b|\\[nrt])(?:os\.getenv|os\.Getenv|os\.environ\.get)\(\s*(?:\\*["'])[A-Za-z_][A-Za-z0-9_]*(?:\\*["'])\s*,\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^)]+?)\s*\)`)

// vaultKey separates a numeric literal from the same digits as a string, so
// 123 and "123" get different tokens.
type vaultKey struct {
	kind  string // "" for string, "number" for a JSON number
	value string // canonical JSON text
}

func stringKey(value string) vaultKey { return vaultKey{value: value} }
func numberKey(value string) vaultKey { return vaultKey{kind: "number", value: value} }

type vaultEntry struct {
	original     string
	originalType string // "number" or ""
}

// maskVault is per-scope state. All access happens under maskStore.mu, so there
// is exactly one lock and no store→vault ordering to deadlock on.
type maskVault struct {
	byOriginal map[vaultKey]string
	byToken    map[string]vaultEntry
	lastUsed   time.Time
	usedBytes  int64
}

// maskStore owns every vault and the memory budget.
type maskStore struct {
	mu             sync.Mutex
	scopes         map[string]*maskVault
	maxScopes      int
	maxPerScope    int
	ttl            time.Duration
	globalBudget   int64
	perScopeBudget int64
	maxResponse    int64
	globalUsed     int64
	now            func() time.Time
}

func newMaskStore(maxScopes, maxPerScope int, ttl time.Duration) *maskStore {
	if maxScopes <= 0 {
		maxScopes = maskMaxScopes
	}
	if maxPerScope <= 0 {
		maxPerScope = maskMaxMappings
	}
	if ttl <= 0 {
		ttl = maskScopeTTL
	}
	return &maskStore{
		scopes:         make(map[string]*maskVault),
		maxScopes:      maxScopes,
		maxPerScope:    maxPerScope,
		ttl:            ttl,
		globalBudget:   maskGlobalBudget,
		perScopeBudget: maskPerScopeBudget,
		maxResponse:    maskMaxResponse,
		now:            time.Now,
	}
}

func (s *maskStore) get(scope string) (*maskVault, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	// Idle scopes release their bytes back to the global budget.
	for key, vault := range s.scopes {
		if now.Sub(vault.lastUsed) > s.ttl {
			s.globalUsed -= vault.usedBytes
			delete(s.scopes, key)
		}
	}
	if vault, ok := s.scopes[scope]; ok {
		vault.lastUsed = now
		return vault, nil
	}
	if len(s.scopes) >= s.maxScopes {
		return nil, errMaskCapacity
	}
	vault := &maskVault{
		byOriginal: make(map[vaultKey]string),
		byToken:    make(map[string]vaultEntry),
		lastUsed:   now,
	}
	s.scopes[scope] = vault
	return vault, nil
}

// tokenFor mints (or returns) a token. Budget is checked before any map entry
// is allocated, so a refused request leaves no residue.
func (s *maskStore) tokenFor(scope string, vault *maskVault, key vaultKey) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if token, ok := vault.byOriginal[key]; ok {
		vault.lastUsed = now
		return token, nil
	}

	// A vault detached by TTL eviction still serves its in-flight request, but
	// must not spend the global budget.
	registered := s.scopes[scope] == vault
	cost := int64(len(key.value))

	if len(vault.byOriginal) >= s.maxPerScope {
		return "", errMaskCapacity
	}
	if vault.usedBytes+cost > s.perScopeBudget {
		return "", errMaskCapacity
	}
	if registered && s.globalUsed+cost > s.globalBudget {
		return "", errMaskCapacity
	}

	for attempt := 0; attempt < 8; attempt++ {
		raw := make([]byte, maskTokenBytes)
		if _, err := rand.Read(raw); err != nil {
			return "", errMaskCapacity
		}
		token := maskTokenPrefix + hex.EncodeToString(raw) + "__"
		if _, taken := vault.byToken[token]; taken {
			continue
		}
		vault.byOriginal[key] = token
		vault.byToken[token] = vaultEntry{original: key.value, originalType: key.kind}
		vault.usedBytes += cost
		vault.lastUsed = now
		if registered {
			s.globalUsed += cost
		}
		return token, nil
	}
	return "", errMaskCapacity
}

// lookup returns a token entry from this scope's vault only. A token minted for
// another scope is never resolved or reported here.
func (s *maskStore) lookup(vault *maskVault, token string) (vaultEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := vault.byToken[token]
	return entry, ok
}

// masker masks one payload and records the mappings it emitted.
type masker struct {
	ctx      context.Context
	scope    string
	store    *maskStore
	vault    *maskVault
	detector Redactor

	tokens    map[vaultKey]string
	minted    map[string]struct{}
	order     []vaultKey
	existing  []maskMapping
	seenToken map[string]struct{}
	propagate []string
	// short holds values under the propagation length that were discovered in a
	// credential context. They are replaced only when a whole string equals one
	// of them, never as a substring.
	shortSecrets map[string]struct{}
	media        bool
}

func (m *masker) token(value, kind string) (string, error) {
	key := stringKey(value)
	if kind == "number" {
		key = numberKey(value)
	}
	if token, ok := m.tokens[key]; ok {
		return token, nil
	}
	token, err := m.store.tokenFor(m.scope, m.vault, key)
	if err != nil {
		return "", err
	}
	m.tokens[key] = token
	m.minted[token] = struct{}{}
	m.order = append(m.order, key)
	return token, nil
}

// isKnownToken reports whether a token is one we minted in this request or one
// this scope already owns. Only those are left untouched.
func (m *masker) isKnownToken(token string) bool {
	if _, ok := m.minted[token]; ok {
		return true
	}
	_, ok := m.store.lookup(m.vault, token)
	return ok
}

// noteEchoedTokens keeps a token that a later turn sends back and re-reports its
// mapping, so the client can still restore it. Tokens are never re-masked and
// never nested.
func (m *masker) noteEchoedTokens(text string) {
	for _, token := range maskTokenRE.FindAllString(text, -1) {
		if _, done := m.seenToken[token]; done {
			continue
		}
		if _, mine := m.minted[token]; mine {
			continue // already reported as a fresh mapping
		}
		entry, ok := m.store.lookup(m.vault, token)
		if !ok {
			continue // unknown or another scope: leave as opaque text
		}
		m.seenToken[token] = struct{}{}
		m.existing = append(m.existing, maskMapping{
			Token:        token,
			Original:     entry.original,
			OriginalType: entry.originalType,
		})
	}
}

// collectDiscovered records a value found in a credential context. Long values
// propagate anywhere they reappear standalone; short ones only when an entire
// string equals them.
func (m *masker) collectDiscovered(long map[string]struct{}, value string) {
	value = strings.TrimSpace(value)
	if value == "" || isPropagationPlaceholder(value) {
		return
	}
	if len(value) >= maskMinPropagate {
		long[value] = struct{}{}
		return
	}
	m.shortSecrets[value] = struct{}{}
}

// Passive status prose describes handling, not a credential value. Blank only
// the credential noun while scanning, preserving byte offsets and all value
// text. Quoted values and assignments remain eligible for masking.
var passiveStatusRE = regexp.MustCompile(`(?i)\b(password|passwd|passphrase|passcode|secret|api[ _-]?key|access token|token)\s+(?:is|was|are|were)\s+left\s+(?:untouched|unchanged|unmodified)\b`)

func scrubStatusProse(text string) string {
	matches := passiveStatusRE.FindAllStringSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return text
	}
	out := []byte(text)
	for _, match := range matches {
		for i := match[2]; i < match[3]; i++ {
			out[i] = ' '
		}
	}
	return string(out)
}

func (m *masker) secrets(text string) ([]string, error) {
	if text == "" {
		return nil, m.ctx.Err()
	}
	return m.detector.Secrets(m.ctx, scrubStatusProse(text))
}

type maskMapping struct {
	Token    string `json:"token"`
	Original string `json:"original"`
	// OriginalType is "number" for a JSON number and omitted for a string.
	OriginalType string `json:"originalType,omitempty"`
}

type maskResponse struct {
	Version          int             `json:"version"`
	Payload          json.RawMessage `json:"payload"`
	Mappings         []maskMapping   `json:"mappings"`
	UninspectedMedia bool            `json:"uninspectedMedia"`
}

func validMaskScope(scope string) bool {
	if len(scope) < maskMinScopeLen || len(scope) > maskMaxScopeLen {
		return false
	}
	return maskScopePattern.MatchString(scope)
}

// handleMask implements POST /mask: same auth, body limit, queue and scan
// timeout as the other endpoints; nothing is forwarded upstream.
func (g *Gateway) handleMask(w http.ResponseWriter, r *http.Request) {
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

	response, err := g.maskPayload(scanCtx, body)
	if err != nil {
		if r.Context().Err() != nil {
			return
		}
		writeError(w, maskStatus(err), maskPublicError(err))
		return
	}

	encoded, err := json.Marshal(response)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "request rejected")
		return
	}
	// Bound the finished response before any of it is written: the payload can
	// grow because tokens are longer than the values they replace.
	if int64(len(encoded)) > g.maskStore.maxResponse {
		writeError(w, http.StatusServiceUnavailable, maskPublicError(errMaskCapacity))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}

func maskStatus(err error) int {
	switch {
	case errors.Is(err, errMaskCapacity),
		errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, context.Canceled):
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}

func maskPublicError(err error) string {
	switch {
	case errors.Is(err, errMaskScope):
		return "invalid or missing scope"
	case errors.Is(err, errMaskCapacity):
		return "mask capacity exceeded"
	case errors.Is(err, errMaskToolArgs):
		return "malformed tool arguments JSON"
	case errors.Is(err, errMaskStructural):
		return "secret in structural field"
	case errors.Is(err, errDuplicateKey), errors.Is(err, errInvalidBody):
		return "invalid request body"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "request cancelled"
	default:
		return "request rejected"
	}
}

func (g *Gateway) maskPayload(ctx context.Context, body []byte) (maskResponse, error) {
	parsed, err := parseStrictJSON(body)
	if err != nil {
		return maskResponse{}, err
	}
	envelope, ok := parsed.(map[string]any)
	if !ok {
		return maskResponse{}, errInvalidBody
	}

	version, ok := envelope["version"].(json.Number)
	if !ok || version.String() != "1" {
		return maskResponse{}, errInvalidBody
	}
	scope, ok := envelope["scope"].(string)
	if !ok || !validMaskScope(scope) {
		return maskResponse{}, errMaskScope
	}
	payload, exists := envelope["payload"]
	if !exists {
		return maskResponse{}, errInvalidBody
	}

	vault, err := g.maskStore.get(scope)
	if err != nil {
		return maskResponse{}, err
	}

	worker := &masker{
		ctx:          ctx,
		scope:        scope,
		store:        g.maskStore,
		vault:        vault,
		detector:     g.redactor,
		tokens:       make(map[vaultKey]string),
		minted:       make(map[string]struct{}),
		seenToken:    make(map[string]struct{}),
		shortSecrets: make(map[string]struct{}),
	}

	// Pass 1: discover string values that must be replaced wherever they reappear.
	propagate, err := worker.discover(payload, nil, false)
	if err != nil {
		return maskResponse{}, err
	}
	if err := ctx.Err(); err != nil {
		return maskResponse{}, err
	}
	worker.propagate = sortedValues(propagate)

	// Pass 2: mask.
	masked, err := worker.walk(payload, nil, false)
	if err != nil {
		return maskResponse{}, err
	}
	if err := ctx.Err(); err != nil {
		return maskResponse{}, err
	}

	emitted := make([]maskMapping, 0, len(worker.order)+len(worker.existing))
	for _, key := range worker.order {
		mapping := maskMapping{Token: worker.tokens[key], Original: key.value}
		if key.kind == "number" {
			mapping.OriginalType = "number"
		}
		emitted = append(emitted, mapping)
	}
	emitted = append(emitted, worker.existing...)

	encoded, err := json.Marshal(masked)
	if err != nil {
		return maskResponse{}, errInvalidBody
	}
	return maskResponse{
		Version:          maskVersion,
		Payload:          encoded,
		Mappings:         emitted,
		UninspectedMedia: worker.media,
	}, nil
}

func (m *masker) walk(node any, p path, inheritedSensitive bool) (any, error) {
	if err := m.ctx.Err(); err != nil {
		return nil, err
	}
	switch typed := node.(type) {
	case map[string]any:
		return m.walkObject(typed, p, inheritedSensitive)
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			masked, err := m.walk(item, p.push("[]"), inheritedSensitive)
			if err != nil {
				return nil, err
			}
			out[i] = masked
		}
		return out, nil
	case string:
		return m.maskField(typed, p, maskSchemaRequiredName(p), inheritedSensitive)
	case json.Number:
		if inheritedSensitive {
			return m.token(typed.String(), "number")
		}
		return typed, nil
	default:
		return node, nil
	}
}

func (m *masker) walkObject(object map[string]any, p path, inheritedSensitive bool) (map[string]any, error) {
	out := make(map[string]any, len(object))
	for key, value := range object {
		if err := m.ctx.Err(); err != nil {
			return nil, err
		}
		lower := strings.ToLower(key)

		// A key that itself carries a detected secret cannot be masked without
		// changing the payload shape, so the request is refused. Ordinary names
		// such as a schema property "password" are not findings.
		if found, err := m.secrets(key); err != nil {
			return nil, err
		} else if len(found) > 0 {
			return nil, errMaskStructural
		}

		// Media is preserved only at an actual content part and never inspected
		// byte-wise. The same key name in metadata is ordinary text and is
		// scanned like any other value.
		if p.inContentPart() {
			if _, isMedia := inspectMediaKeys[lower]; isMedia {
				m.media = true
				out[key] = value
				continue
			}
			if lower == "type" {
				if name, ok := value.(string); ok {
					if _, isMedia := inspectMediaTypes[strings.ToLower(name)]; isMedia {
						m.media = true
						out[key] = value
						continue
					}
				}
			}
		}

		structural := maskStructuralKey(p, key)
		sensitive := inheritedSensitive || sensitiveKeyRE.MatchString(key)
		_, literalKey := schemaValueKeys[lower]
		forceSensitive := sensitiveKeyRE.MatchString(key) || (inheritedSensitive && literalKey)

		switch typed := value.(type) {
		case string:
			masked, err := m.maskField(typed, p.push(key), structural, forceSensitive)
			if err != nil {
				return nil, err
			}
			out[key] = masked
		case json.Number:
			if forceSensitive {
				token, err := m.token(typed.String(), "number")
				if err != nil {
					return nil, err
				}
				out[key] = token
				continue
			}
			out[key] = typed
		case map[string]any:
			nested, err := m.walkObject(typed, p.push(key), sensitive)
			if err != nil {
				return nil, err
			}
			out[key] = nested
		case []any:
			nested, err := m.walk(typed, p.push(key), sensitive)
			if err != nil {
				return nil, err
			}
			out[key] = nested
		default:
			out[key] = value
		}
	}
	return out, nil
}

// Required property names are identities, like tool names. Masking one without
// renaming the properties map makes a valid tool schema impossible to satisfy.
// Defaults/enums/examples are data even when they contain a "required" key.
func maskSchemaRequiredName(p path) bool {
	n := len(p)
	if n < 3 || p[n-1] != "[]" || p[n-2] != "required" || !p.inSchemaPath() {
		return false
	}
	if p[0] != "tools" && p[0] != "functions" && p[0] != "response_format" {
		return false
	}
	for i, key := range p[:n-2] {
		if _, literal := schemaValueKeys[key]; !literal {
			continue
		}
		if i > 0 {
			switch p[i-1] {
			case "properties", "patternProperties", "$defs", "definitions", "dependentSchemas":
				continue // A user-chosen property/definition name, not a keyword.
			}
		}
		return false
	}
	return true
}

// maskStructuralKey protects only protocol identities: the model name and tool
// names. Ordinary user data is never structural.
func maskStructuralKey(p path, key string) bool {
	if p.inSchemaPath() {
		return false
	}
	if key == "model" && len(p) == 0 {
		return true
	}
	if key == "name" && (p.contains("tools") || p.contains("functions")) {
		return true
	}
	return false
}

func (m *masker) maskField(value string, p path, structural, forceSensitive bool) (string, error) {
	if value == "" {
		return value, nil
	}
	m.noteEchoedTokens(value)
	// A complete token from this scope already has its original mapping.
	// Sensitive fields must not wrap it in another token.
	if isMaskToken(value) && m.isKnownToken(value) {
		return value, nil
	}
	if isExactReference(value) {
		return value, nil
	}
	if strings.HasPrefix(value, "data:") && (p.insideContentPart() || p.contains("messages")) {
		m.media = true
		return value, nil
	}
	if structural {
		found, err := m.secrets(value)
		if err != nil {
			return "", err
		}
		if len(found) > 0 || hasContextSecret(value) {
			return "", errMaskStructural
		}
		return value, nil
	}
	if _, isShort := m.shortSecrets[value]; isShort {
		return m.token(value, "")
	}
	if forceSensitive {
		return m.token(value, "")
	}
	if isToolArgumentsKey(p) {
		return m.maskArguments(value, p)
	}
	return m.maskPlain(value)
}

// maskArguments rewrites the string fields of a JSON-encoded tool argument
// document, keeping it valid JSON. Malformed JSON where JSON is expected is
// rejected; plain-text arguments are masked as text.
func (m *masker) maskArguments(value string, p path) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return value, nil
	}
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return m.maskPlain(value)
	}
	parsed, err := parseStrictJSON([]byte(trimmed))
	if err != nil {
		return "", errMaskToolArgs
	}
	masked, err := m.walk(parsed, p, false)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(masked)
	if err != nil {
		return "", errMaskToolArgs
	}
	return string(encoded), nil
}

// maskPlain masks credential assignments at their exact span, then replaces
// request-wide string values of four or more characters.
func (m *masker) maskPlain(value string) (string, error) {
	masked, err := m.maskEscapedAssignments(value)
	if err != nil {
		return "", err
	}
	masked, err = m.maskReferenceDefaults(masked)
	if err != nil {
		return "", err
	}
	masked, err = m.maskAuthorizationHeaders(masked)
	if err != nil {
		return "", err
	}
	masked, err = m.maskContextSpans(masked)
	if err != nil {
		return "", err
	}
	for _, secret := range m.propagate {
		if !containsStandalone(masked, secret) {
			continue
		}
		token, err := m.token(secret, "")
		if err != nil {
			return "", err
		}
		masked = replaceStandalone(masked, secret, token)
	}
	return m.maskUnknownTokens(masked)
}

func (m *masker) maskContextSpans(text string) (string, error) {
	var err error
	for _, re := range []*regexp.Regexp{maskAssignRE, maskProseENRE, maskProseZHRE} {
		text, err = m.applySpanRegex(text, re)
		if err != nil {
			return "", err
		}
	}
	return text, nil
}

func (m *masker) applySpanRegex(text string, re *regexp.Regexp) (string, error) {
	matches := re.FindAllStringSubmatchIndex(scrubStatusProse(text), -1)
	if len(matches) == 0 {
		return text, nil
	}
	spans := referenceSpans(text)
	schemeSpans := authSchemeSpans(text)
	for i := len(matches) - 1; i >= 0; i-- {
		start, end := matches[i][2], matches[i][3]
		if start < 0 || end <= start {
			continue
		}
		raw := text[start:end]
		inner, prefix, suffix := raw, "", ""
		switch {
		case len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"':
			inner, prefix, suffix = raw[1:len(raw)-1], `"`, `"`
		case len(raw) >= 2 && raw[0] == '\'' && raw[len(raw)-1] == '\'':
			inner, prefix, suffix = raw[1:len(raw)-1], `'`, `'`
		case strings.HasPrefix(raw, "“") && strings.HasSuffix(raw, "”"):
			inner, prefix, suffix = strings.TrimSuffix(strings.TrimPrefix(raw, "“"), "”"), "“", "”"
		}
		// A quoted reference holds the expression inside the quotes; test both
		// the whole capture and the inner span.
		if withinReference(spans, start, end) || withinReference(spans, start+len(prefix), end-len(suffix)) {
			continue // a source reference, not a value
		}
		if inner == "" || (prefix == "" && !hasAlnum(inner)) || m.isKnownToken(inner) || m.containsKnownToken(inner) {
			continue
		}
		if withinReference(schemeSpans, start, end) {
			continue // the scheme word of a real Authorization header
		}
		token, err := m.token(inner, "")
		if err != nil {
			return "", err
		}
		text = text[:start] + prefix + token + suffix + text[end:]
	}
	return text, nil
}

// hasAlnum rejects punctuation-only captures such as the colon in
// "password is: hunter2" or the full-width colon in "密码是：hunter2".
func hasAlnum(value string) bool {
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// insideContentPart reports whether any ancestor is an array element of a
// content field, which is where real media blocks live.
func (p path) insideContentPart() bool {
	for i := 0; i+1 < len(p); i++ {
		if p[i] == "content" && p[i+1] == "[]" {
			return true
		}
	}
	return false
}

// isMaskToken reports whether a value is already one of our tokens, so a second
// pattern pass cannot mask a token as if it were a secret.
func isMaskToken(value string) bool {
	if !strings.HasPrefix(value, maskTokenPrefix) || !strings.HasSuffix(value, "__") {
		return false
	}
	body := strings.TrimSuffix(strings.TrimPrefix(value, maskTokenPrefix), "__")
	if len(body) != maskTokenHexLen {
		return false
	}
	for _, r := range body {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// discover collects string values that must be replaced wherever they reappear.
// Short values are excluded: they are only masked at their detected span.
// Numeric values are not propagated; their token carries a type instead.
func (m *masker) discover(node any, p path, inheritedSensitive bool) (map[string]struct{}, error) {
	if err := m.ctx.Err(); err != nil {
		return nil, err
	}
	found := make(map[string]struct{})

	switch typed := node.(type) {
	case map[string]any:
		for key, value := range typed {
			lower := strings.ToLower(key)
			if p.inContentPart() {
				if _, isMedia := inspectMediaKeys[lower]; isMedia {
					continue
				}
			}
			sensitive := inheritedSensitive || sensitiveKeyRE.MatchString(key)
			nested, err := m.discover(value, p.push(key), sensitive)
			if err != nil {
				return nil, err
			}
			for v := range nested {
				found[v] = struct{}{}
			}
		}
	case []any:
		for _, item := range typed {
			nested, err := m.discover(item, p.push("[]"), inheritedSensitive)
			if err != nil {
				return nil, err
			}
			for v := range nested {
				found[v] = struct{}{}
			}
		}
	case string:
		if typed == "" {
			return found, nil
		}
		// Tool arguments carry a nested document: discover inside it too.
		if isToolArgumentsKey(p) {
			if trimmed := strings.TrimSpace(typed); strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
				if parsed, err := parseStrictJSON([]byte(trimmed)); err == nil {
					nested, err := m.discover(parsed, p, false)
					if err != nil {
						return nil, err
					}
					for v := range nested {
						found[v] = struct{}{}
					}
				}
			}
		}
		if err := m.discoverEscaped(typed, found); err != nil {
			return nil, err
		}
		values, err := m.secrets(scrubReferences(typed))
		if err != nil {
			return nil, err
		}
		for _, v := range values {
			m.collectDiscovered(found, v)
		}
		if credentialLiteral(p, inheritedSensitive) && !isExactReference(typed) {
			m.collectDiscovered(found, typed)
		}
	}
	return found, nil
}

// sortedValues orders longest first so a short value never splits a longer one.
func sortedValues(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// replaceStandalone replaces whole-token occurrences only, so a secret never
// corrupts a longer word.
func replaceStandalone(text, value, replacement string) string {
	if value == "" || len(value) > len(text) {
		return text
	}
	var out strings.Builder
	offset := 0
	for offset+len(value) <= len(text) {
		index := strings.Index(text[offset:], value)
		if index < 0 {
			break
		}
		start := offset + index
		end := start + len(value)
		beforeOK := start == 0 || !isIdentByte(text[start-1])
		afterOK := end == len(text) || !isIdentByte(text[end])
		if !beforeOK || !afterOK {
			out.WriteString(text[offset : start+1])
			offset = start + 1
			continue
		}
		out.WriteString(text[offset:start])
		out.WriteString(replacement)
		offset = end
	}
	if offset == 0 {
		return text
	}
	out.WriteString(text[offset:])
	return out.String()
}

// isToolArgumentsKey reports whether this path is a tool-call arguments field.
func isToolArgumentsKey(p path) bool {
	if len(p) == 0 || p[len(p)-1] != "arguments" {
		return false
	}
	return p.contains("tool_calls") || p.contains("function_call") || p.contains("functions")
}

func hasContextSecret(value string) bool {
	for _, re := range []*regexp.Regexp{maskAssignRE, maskProseENRE, maskProseZHRE} {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}
