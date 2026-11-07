package main

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/logging"
)

// This file holds Chat Completions policy: which locations are structural,
// which are media, and which fields are credential-named. Detection itself
// lives in inspect.go and is protocol-neutral.

func init() {
	// gitleaks logs rule ids, paths and matched fragments through zerolog.
	// Silence it before any detector is built; this guard never logs payloads.
	logging.Logger = zerolog.Nop()
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

// sensitiveKeyRE matches object keys whose value is a credential regardless of
// entropy (for example "password": "hunter2" or "db_password": 123456).
// Anchored, so "max_tokens" is not sensitive.
var sensitiveKeyRE = regexp.MustCompile(`(?i)^(?:[a-z0-9_.-]*[_.-])?` +
	`(?:password|passwd|pwd|passphrase|passcode|secret|secretkey|token|apikey|api_key|` +
	`access_key|accesskey|private_key|privatekey|client_secret|clientsecret|` +
	`credential|credentials|authorization|auth_token|authtoken|bearer|` +
	`signing_key|signingkey|encryption_key|encryptionkey)$`)

// schemaValueKeys are the JSON-schema keywords that hold literal values. Under
// a sensitive property name those literals are credentials.
var schemaValueKeys = map[string]struct{}{
	"default": {}, "enum": {}, "examples": {}, "const": {},
}

// mediaKeys only count as media inside an actual content block. A tool schema
// may legitimately define a property called "file" or "image".
var mediaKeys = map[string]struct{}{
	"image_url": {}, "input_image": {}, "input_audio": {}, "audio_url": {},
	"video_url": {}, "image": {}, "file": {}, "file_id": {}, "b64_json": {},
}

var mediaTypes = map[string]struct{}{
	"image_url": {}, "input_image": {}, "image": {}, "input_audio": {},
	"audio_url": {}, "audio": {}, "video_url": {}, "video": {},
}

// inSchemaPath reports whether a node lives inside a tool/function JSON schema
// rather than in protocol fields. Schema text is scanned but never rejected for
// shape, so a "read" tool may declare properties named file or image.
func (p path) inSchemaPath() bool {
	switch {
	case p.contains("parameters"),
		p.contains("properties"),
		p.contains("items"),
		p.contains("additionalProperties"),
		p.contains("definitions"),
		p.contains("$defs"),
		p.contains("json_schema"):
		return true
	}
	return false
}

// inContentPart reports whether the current object is an element of a
// messages[].content array, i.e. a real multimodal content block.
func (p path) inContentPart() bool {
	n := len(p)
	return n >= 2 && p[n-1] == "[]" && p[n-2] == "content"
}

// structuralKey reports whether a key is part of the wire protocol at this
// location. Secrets there are rejected, not masked: masking would corrupt the
// request silently. User metadata and schemas are excluded.
func (p path) structuralKey(key string) bool {
	if p.inSchemaPath() {
		return false
	}
	switch key {
	case "model":
		return len(p) == 0
	case "role", "tool_call_id", "id", "type":
		return p.contains("messages")
	case "name":
		return p.contains("tools") || p.contains("functions")
	}
	return false
}

// lastSchemaValueKey reports whether the nearest named ancestor is a schema
// value keyword, so "enum" elements inherit the sensitivity of the property.
func (p path) lastSchemaValueKey() bool {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == "[]" {
			continue
		}
		_, ok := schemaValueKeys[p[i]]
		return ok
	}
	return false
}

// applier masks a Chat request using the values discovered for the whole
// request.
type applier struct {
	ctx          context.Context
	secrets      []string
	shortSecrets []string
	count        int
}

// mask replaces known long secrets and reports whether a short secret is still
// present. A short value is never replaced request-wide, so its presence here
// means the request cannot be sanitized safely.
func (a *applier) mask(text string) (string, bool, bool) {
	masked := text
	for _, secret := range a.secrets {
		masked = strings.ReplaceAll(masked, secret, RedactedSecret)
	}
	leaked := false
	for _, secret := range a.shortSecrets {
		if containsStandalone(masked, secret) {
			leaked = true
			break
		}
	}
	if masked != text {
		a.count++
		return masked, true, leaked
	}
	return text, false, leaked
}

func (a *applier) keyHasSecret(key string) bool {
	for _, secret := range a.secrets {
		if strings.Contains(key, secret) {
			return true
		}
	}
	for _, secret := range a.shortSecrets {
		if containsStandalone(key, secret) {
			return true
		}
	}
	return false
}

func (a *applier) walk(node any, p path, inheritedSensitive bool) (any, error) {
	if err := a.ctx.Err(); err != nil {
		return nil, err
	}
	switch typed := node.(type) {
	case map[string]any:
		return a.walkObject(typed, p, inheritedSensitive)
	case []any:
		return a.walkArray(typed, p, inheritedSensitive)
	case string:
		return a.walkString(typed, p, inheritedSensitive)
	case json.Number:
		if inheritedSensitive {
			a.count++
			return RedactedSecret, nil
		}
		return typed, nil
	default:
		return node, nil
	}
}

func (a *applier) walkObject(object map[string]any, p path, inheritedSensitive bool) (map[string]any, error) {
	out := make(map[string]any, len(object))
	contentPart := p.inContentPart()

	for key, value := range object {
		if err := a.ctx.Err(); err != nil {
			return nil, err
		}
		lower := strings.ToLower(key)

		// A secret inside a key cannot be masked without changing the shape the
		// upstream receives.
		if a.keyHasSecret(key) {
			return nil, errSecretInStructural
		}

		if contentPart {
			_, isMediaKey := mediaKeys[lower]
			_, isMediaType := mediaTypes[lower]
			if isMediaKey || (lower == "type" && isMediaType) {
				return nil, errMedia
			}
		}

		sensitive := inheritedSensitive || sensitiveKeyRE.MatchString(key)
		structural := p.structuralKey(key)
		_, literalSchemaValue := schemaValueKeys[lower]
		forceSensitive := sensitiveKeyRE.MatchString(key) || (inheritedSensitive && literalSchemaValue)

		switch typed := value.(type) {
		case string:
			if forceSensitive && typed != "" {
				a.count++
				out[key] = RedactedSecret
				continue
			}
			masked, changed, leaked, err := a.maskString(typed, p)
			if err != nil {
				return nil, err
			}
			if leaked {
				return nil, errShortSecret
			}
			if changed && structural {
				return nil, errSecretInStructural
			}
			out[key] = masked
		case json.Number:
			if forceSensitive {
				a.count++
				out[key] = RedactedSecret
				continue
			}
			out[key] = typed
		case map[string]any:
			nested, err := a.walkObject(typed, p.push(key), sensitive)
			if err != nil {
				return nil, err
			}
			out[key] = nested
		case []any:
			nested, err := a.walkArray(typed, p.push(key), sensitive)
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

func (a *applier) walkArray(array []any, p path, inheritedSensitive bool) ([]any, error) {
	out := make([]any, len(array))
	for i, item := range array {
		if err := a.ctx.Err(); err != nil {
			return nil, err
		}
		nested, err := a.walk(item, p.push("[]"), inheritedSensitive)
		if err != nil {
			return nil, err
		}
		out[i] = nested
	}
	return out, nil
}

func (a *applier) walkString(value string, p path, inheritedSensitive bool) (string, error) {
	if !p.inSchemaPath() && strings.HasPrefix(value, "data:") {
		return "", errMedia
	}
	if inheritedSensitive && value != "" {
		// Bare array element under a sensitive key, or a schema literal
		// (default/enum/examples) under a sensitive property.
		if !p.inSchemaPath() || p.lastSchemaValueKey() {
			a.count++
			return RedactedSecret, nil
		}
	}
	masked, _, leaked := a.mask(value)
	if leaked {
		return "", errShortSecret
	}
	return masked, nil
}

func (a *applier) maskString(value string, p path) (string, bool, bool, error) {
	if !p.inSchemaPath() && strings.HasPrefix(value, "data:") {
		return "", false, false, errMedia
	}
	masked, changed, leaked := a.mask(value)
	return masked, changed, leaked, nil
}

// sanitize parses and redacts one Chat Completions request body. Errors carry
// no request content; the caller maps them to fixed messages.
func sanitize(ctx context.Context, detector Redactor, body []byte) ([]byte, int, error) {
	parsed, err := parseStrictJSON(body)
	if err != nil {
		return nil, 0, err
	}
	root, ok := parsed.(map[string]any)
	if !ok {
		return nil, 0, errInvalidBody
	}

	values, shorts, err := collectSecrets(ctx, detector, root, true)
	if err != nil {
		return nil, 0, err
	}
	if err := ctx.Err(); err != nil { // covers an empty or trivial payload too
		return nil, 0, err
	}

	apply := &applier{ctx: ctx, secrets: values, shortSecrets: shorts}
	masked, err := apply.walk(root, nil, false)
	if err != nil {
		return nil, 0, err
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}

	encoded, err := json.Marshal(masked)
	if err != nil {
		return nil, 0, errInvalidBody
	}
	return encoded, apply.count, nil
}

// gitleaksRedactor wraps a gitleaks detector built from the default rule set
// plus this guard's own password/credential rules. One instance is built at
// startup and shared. DetectContext returns a local findings slice and does not
// retain per-scan state, but the package does not document those internals as
// concurrency-safe, so scans are serialized.
type gitleaksRedactor struct {
	detector *detect.Detector
	mu       sync.Mutex
}

func buildRedactor() (Redactor, error) {
	cfg, err := defaultGitleaksConfig()
	if err != nil {
		return nil, err
	}
	if err := addCustomRules(&cfg); err != nil {
		return nil, err
	}
	detector := detect.NewDetector(cfg)
	detector.IgnoreGitleaksAllow = true
	detector.Redact = 0
	detector.Verbose = false
	return &gitleaksRedactor{detector: detector}, nil
}

// viper keeps global state, so config translation must not run concurrently.
var gitleaksConfigMu sync.Mutex

// translateDefaultConfig returns the embedded gitleaks config exactly as
// shipped, including its global allowlist.
func translateDefaultConfig() (config.Config, error) {
	gitleaksConfigMu.Lock()
	defer gitleaksConfigMu.Unlock()

	viper.SetConfigType("toml")
	if err := viper.ReadConfig(strings.NewReader(config.DefaultConfig)); err != nil {
		return config.Config{}, fmt.Errorf("read embedded gitleaks config: %w", err)
	}
	var vc config.ViperConfig
	if err := viper.Unmarshal(&vc); err != nil {
		return config.Config{}, fmt.Errorf("decode embedded gitleaks config: %w", err)
	}
	cfg, err := vc.Translate()
	if err != nil {
		return config.Config{}, fmt.Errorf("translate gitleaks config: %w", err)
	}
	return cfg, nil
}

// defaultGitleaksConfig is the guard's detector config.
func defaultGitleaksConfig() (config.Config, error) {
	cfg, err := translateDefaultConfig()
	if err != nil {
		return config.Config{}, err
	}
	// The global allowlist targets repository scans: file-path patterns and
	// "looks like a dummy" regexes. In a redaction guard those exceptions would
	// silently pass user-supplied credentials (for example password="example"),
	// so they are dropped. Per-rule allowlists still apply.
	cfg.Allowlists = nil
	return cfg, nil
}

func (g *gitleaksRedactor) Secrets(ctx context.Context, text string) ([]string, error) {
	if text == "" {
		return nil, ctx.Err()
	}
	g.mu.Lock()
	findings := g.detector.DetectContext(ctx, detect.Fragment{Raw: text})
	g.mu.Unlock()
	// DetectContext reports no error. A cancelled or expired context is the only
	// way to know the scan was cut short, and that must never read as "clean".
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		secret := finding.Secret
		if secret == "" {
			secret = finding.Match
		}
		if secret = trimQuotes(secret); secret != "" {
			out = append(out, secret)
		}
	}
	return out, nil
}

// customRule is a rule added on top of the embedded gitleaks defaults.
type customRule struct {
	id          string
	description string
	pattern     string
	secretGroup int
	keywords    []string
	allowSecret []string
}

const credentialName = `(?:password|passwd|pwd|passphrase|passcode|secret_key|secret|token|` +
	`api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|credential|` +
	`credentials|auth[_-]?token)`

// quotedNameAssignment captures the whole quoted literal, including spaces, so
// `password="correct horse battery staple"` is not truncated at the first
// space. Surrounding quotes are stripped afterwards by trimQuotes.
const quotedNameAssignment = `(?i)[a-z0-9_.-]*` + credentialName + `\s*["']?\s*[:=]\s*("(?:[^"\\]|\\.){1,}"|'(?:[^'\\]|\\.){1,}')`

// Assignment values go down to one character: `password=x` is structured enough
// to be a credential. Prose keeps a 3-character floor so "the password is a
// secret" does not treat the article as the value.
const bareNameAssignment = `(?i)[a-z0-9_.-]*` + credentialName + `\s*["']?\s*[:=]\s*([^\s"',;}]{1,})`
const quotedProseEN = `(?i)\b(?:password|passwd|passphrase|passcode|secret|api[ _-]?key|access token|token)\b\s*(?:is|was|are|were|:|=)\s*("(?:[^"\\]|\\.){1,}"|'(?:[^'\\]|\\.){1,}')`
const bareProseEN = `(?i)\b(?:password|passwd|passphrase|passcode|secret|api[ _-]?key|access token|token)\b\s*(?:is|was|are|were|:|=)\s*([^\s"',;.)]{3,})`

// proseZH also accepts Chinese quotation marks.
const proseZH = `(?:密码|口令|密钥|秘钥|令牌|凭证|访问密钥)\s*(?:是|为|改成|设置为|:|：|＝|=)\s*(?:"[^"]{1,}"|'[^']{1,}'|“[^”]{1,}”|[^\s"'“”，。；、）)]{3,})`

var credentialKeywords = []string{"password", "passwd", "pwd", "passphrase", "passcode", "secret", "token", "apikey", "api_key", "api-key", "credential", "access_key", "private_key", "client_secret"}
var proseKeywords = []string{"password", "passwd", "passphrase", "passcode", "secret", "token", "api key", "api_key", "access token"}

var customRules = []customRule{
	{
		id:          "custom-credential-assignment-quoted",
		description: "Credential name assigned a quoted literal",
		pattern:     quotedNameAssignment,
		secretGroup: 1,
		keywords:    credentialKeywords,
		allowSecret: defaultSecretAllowlist,
	},
	{
		id:          "custom-credential-assignment",
		description: "Credential name assigned an unquoted literal",
		pattern:     bareNameAssignment,
		secretGroup: 1,
		keywords:    credentialKeywords,
		allowSecret: defaultSecretAllowlist,
	},
	{
		id:          "custom-credential-prose-en-quoted",
		description: "Quoted password or token described in prose",
		pattern:     quotedProseEN,
		secretGroup: 1,
		keywords:    proseKeywords,
		allowSecret: defaultSecretAllowlist,
	},
	{
		id:          "custom-credential-prose-en",
		description: "Password or token described in prose",
		pattern:     bareProseEN,
		secretGroup: 1,
		keywords:    proseKeywords,
		allowSecret: defaultSecretAllowlist,
	},
	{
		id:          "custom-credential-prose-zh",
		description: "Password or key described in Chinese prose",
		pattern:     proseZH,
		secretGroup: 0,
		keywords:    []string{"密码", "口令", "密钥", "秘钥", "令牌", "凭证", "访问密钥"},
		allowSecret: defaultSecretAllowlist,
	},
	{
		id:          "custom-bearer-token",
		description: "Bearer token value",
		pattern:     `(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{12,})`,
		secretGroup: 1,
		keywords:    []string{"bearer"},
		allowSecret: defaultSecretAllowlist,
	},
}

// defaultSecretAllowlist keeps placeholders, environment references, type names
// and status words from being treated as credentials.
var defaultSecretAllowlist = []string{
	`(?i)^(?:required|missing|invalid|incorrect|empty|expired|changed|reset|wrong|unknown|hidden|optional|mandatory|provided|string|number|boolean|integer|null|true|false|none|todo|redacted|undefined)$`,
	`^\$\{?[A-Za-z_]`,
	`^%[A-Za-z_][A-Za-z0-9_]*%$`,
	`^\{\{.*\}\}$`,
	`^<[^>]*>$`,
	`^\*+$`,
	`^\[REDACTED_SECRET\]$`,
	`(?i)^(?:os|process|sys)\.(?:getenv|environ)`,
	`(?i)^(?:self|this|config|cfg|env|opts|options|settings)\.`,
}

func addCustomRules(cfg *config.Config) error {
	if cfg.Rules == nil {
		cfg.Rules = make(map[string]config.Rule)
	}
	if cfg.Keywords == nil {
		cfg.Keywords = make(map[string]struct{})
	}
	for _, rule := range customRules {
		if _, exists := cfg.Rules[rule.id]; exists {
			return fmt.Errorf("duplicate rule id %q", rule.id)
		}
		compiled, err := regexp.Compile(rule.pattern)
		if err != nil {
			return fmt.Errorf("compile %s: %w", rule.id, err)
		}
		allow := &config.Allowlist{Description: "guard allowlist", Regexes: compileAll(rule.allowSecret)}
		if err := allow.Validate(); err != nil {
			return fmt.Errorf("validate allowlist %s: %w", rule.id, err)
		}
		cfg.Rules[rule.id] = config.Rule{
			RuleID:      rule.id,
			Description: rule.description,
			Regex:       compiled,
			SecretGroup: rule.secretGroup,
			Keywords:    rule.keywords,
			Allowlists:  []*config.Allowlist{allow},
		}
		cfg.OrderedRules = append(cfg.OrderedRules, rule.id)
		for _, keyword := range rule.keywords {
			cfg.Keywords[strings.ToLower(keyword)] = struct{}{}
		}
	}
	return nil
}

func compileAll(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		out = append(out, regexp.MustCompile(pattern))
	}
	return out
}
