package main

import (
	"context"
	"crypto/sha256"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Additional credential labels are enabled only by the credentials profile.
// Protocol roles and general prose containing the word "user" stay readable.
const credentialExtraName = `(?:username|user_name|user|login|ak|sk|access[_-]?key[_-]?(?:id|secret)|secret[_-]?(?:id|access[_-]?key))`

var credentialExtraKeyRE = regexp.MustCompile(`(?i)^(?:[a-z0-9_.-]*[_.-])?` + credentialExtraName + `$`)
var credentialExtraAssignRE = regexp.MustCompile(`(?i)\b(?:[a-z0-9_.-]*[_.-])?` + credentialExtraName + `\s*(?:\\*["'])?\s*[:=]\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s"',;}]+)`)
var credentialUserZHRE = regexp.MustCompile(`(?:用户名|账号|帐号)\s*(?:(?:是|为)\s*[:：=]?\s*|[:：=]\s*)("[^"\n]*"|'[^'\n]*'|[^\s"'，。；]+)`)

// This detector uses immutable compiled expressions and no model, repository
// traversal, entropy engine or shared detector lock.
type credentialRedactor struct {
	mu          sync.Mutex
	cache       map[[32]byte][]textSpan
	cachedSpans int
}

// Hints locate the first possible match before applying each full rule.
var credentialRules = []struct {
	re    *regexp.Regexp
	group int
	hints []string
}{
	{maskAssignRE, 1, []string{"password", "passwd", "pwd", "passphrase", "passcode", "secret", "token", "key", "credential", "authorization", "bearer"}},
	{maskProseENRE, 1, []string{"password", "passwd", "passphrase", "passcode", "secret", "key", "token"}},
	{maskProseZHRE, 1, []string{"密码", "口令", "密钥", "秘钥", "令牌", "凭证"}},
	{maskRefDefaultRE, 1, []string{"os."}},
	{maskAuthHeaderRE, 3, []string{"authorization"}},
	{credentialExtraAssignRE, 1, []string{"username", "user_name", "user", "login", "ak", "sk", "access", "secret"}},
	{credentialUserZHRE, 1, []string{"用户名", "账号", "帐号"}},
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`), 0, []string{"akia", "asia"}},
	{regexp.MustCompile(`\b(?:LTAI|AKID)[A-Za-z0-9]{12,64}\b`), 0, []string{"ltai", "akid"}},
	{regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255}|sk-(?:ant-)?[A-Za-z0-9_-]{20,255})\b`), 0, []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "sk-"}},
	{regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----`), 0, []string{"-----begin"}},
	{regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://([^\s/:@]+):([^\s/@]+)@`), 1, []string{"://"}},
	{regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://([^\s/:@]+):([^\s/@]+)@`), 2, []string{"://"}},
}

func (r *credentialRedactor) spans(ctx context.Context, text string) ([]textSpan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := sha256.Sum256([]byte(text))
	r.mu.Lock()
	cached, ok := r.cache[key]
	r.mu.Unlock()
	if ok {
		return cached, nil
	}
	folded := []byte(text)
	for i, b := range folded {
		if b >= 'A' && b <= 'Z' {
			folded[i] = b + ('a' - 'A')
		}
	}
	lower := string(folded)
	references := referenceSpans(text)
	schemes := authSchemeSpans(text)
	var spans []textSpan
	if strings.Contains(text, "mysql") || strings.Contains(text, "mariadb") || strings.Contains(text, "login") {
		spans = commandCredentialSpans(text)
	}
	if strings.Contains(lower, "accesskey") || strings.Contains(lower, "security") || strings.Contains(lower, "secret") {
		spans = append(spans, cloudCredentialSpans(text)...)
	}
	for _, rule := range credentialRules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		offset := -1
		for _, hint := range rule.hints {
			if at := strings.Index(lower, hint); at >= 0 && (offset < 0 || at < offset) {
				offset = at
			}
		}
		if offset < 0 {
			continue
		}
		// Include the full identifier or URI scheme immediately before the marker.
		for offset > 0 && isIdentByte(text[offset-1]) {
			offset--
		}
		for _, match := range rule.re.FindAllStringSubmatchIndex(text[offset:], -1) {
			start, end := offset+match[rule.group*2], offset+match[rule.group*2+1]
			raw := text[start:end]
			inner := trimQuotes(raw)
			if raw != inner {
				start += strings.Index(raw, inner)
				end = start + len(inner)
			}
			if inner == "" || isMaskToken(inner) || withinReference(references, start, end) || withinReference(schemes, start, end) {
				continue
			}
			spans = append(spans, textSpan{start: start, end: end})
		}
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start == spans[j].start {
			return spans[i].end > spans[j].end
		}
		return spans[i].start < spans[j].start
	})
	out := spans[:0]
	for _, span := range spans {
		if len(out) == 0 || span.start >= out[len(out)-1].end {
			out = append(out, span)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Only positions and a digest are cached. Original text and secrets stay
	// outside this cache. Bound both the number of entries and retained spans.
	if len(out) <= 65536 {
		r.mu.Lock()
		if _, exists := r.cache[key]; !exists {
			if r.cache == nil || len(r.cache) >= 1024 || r.cachedSpans+len(out) > 65536 {
				r.cache = make(map[[32]byte][]textSpan)
				r.cachedSpans = 0
			}
			r.cache[key] = append([]textSpan(nil), out...)
			r.cachedSpans += len(out)
		}
		r.mu.Unlock()
	}
	return out, nil
}

func (r *credentialRedactor) Secrets(ctx context.Context, text string) ([]string, error) {
	spans, err := r.spans(ctx, text)
	if err != nil {
		return nil, err
	}
	found := make(map[string]struct{})
	for _, span := range spans {
		found[text[span.start:span.end]] = struct{}{}
	}
	return sortedValues(found), nil
}

func (m *masker) maskCredentialText(value string) (string, error) {
	value, err := m.maskEscapedAssignments(value)
	if err != nil {
		return "", err
	}
	detector := m.detector.(*credentialRedactor)
	spans, err := detector.spans(m.ctx, scrubStatusProse(value))
	if err != nil {
		return "", err
	}
	for i := len(spans) - 1; i >= 0; i-- {
		span := spans[i]
		original := value[span.start:span.end]
		if m.containsKnownToken(original) {
			continue
		}
		token, err := m.token(original, "")
		if err != nil {
			return "", err
		}
		value = value[:span.start] + token + value[span.end:]
	}
	for _, secret := range m.propagate {
		if !containsStandalone(value, secret) {
			continue
		}
		token, err := m.token(secret, "")
		if err != nil {
			return "", err
		}
		value = replaceStandalone(value, secret, token)
	}
	return m.maskUnknownTokens(value)
}

func (m *masker) sensitiveKey(key string) bool {
	return sensitiveKeyRE.MatchString(key) || m.credentials && credentialExtraKeyRE.MatchString(key)
}

func credentialsEnabled(detector Redactor) bool { _, ok := detector.(*credentialRedactor); return ok }
