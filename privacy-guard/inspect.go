package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
)

// This file is protocol-neutral: it parses a payload, finds secret values, and
// masks string values. It makes no judgement about chat semantics, so the same
// primitives can inspect a non-ChatCompletions payload (for example a future
// local /scan preflight) without inheriting Chat rules.

// RedactedSecret replaces every detected secret. There is deliberately no
// reverse mapping: a value that leaves this process cannot be restored.
const RedactedSecret = "[REDACTED_SECRET]"

const maxJSONDepth = 64

// minGlobalSecretLen keeps a 3-character value from being replaced across a
// whole payload. Short secrets are still redacted in the field naming them by
// the Chat policy in redact.go.
const minGlobalSecretLen = 4

var (
	errDuplicateKey       = errors.New("duplicate object key")
	errInvalidBody        = errors.New("body must be a single JSON object")
	errSecretInStructural = errors.New("secret in structural field")
	errMedia              = errors.New("media or binary content is not supported")
	// errShortSecret marks a contextual secret too short to replace safely
	// across the request. Replacing a bare "7" would corrupt unrelated text, so
	// the request is refused instead of leaking or mangling it.
	errShortSecret = errors.New("short secret cannot be redacted safely")
)

// Redactor discovers secret values in one string.
type Redactor interface {
	Secrets(ctx context.Context, text string) ([]string, error)
}

// Inspection is the neutral detector result for one payload.
type Inspection struct {
	// Values are distinct secret values found anywhere in the payload, longest
	// first.
	Values []string
	// Redacted is the payload with every string value masked. Object keys are
	// left untouched on purpose: rewriting a key changes the payload shape.
	Redacted []byte
	// Hits is the number of strings masked.
	Hits int
}

// InspectText scans arbitrary text with no protocol assumptions.
func InspectText(ctx context.Context, detector Redactor, text string) (Inspection, error) {
	if text == "" {
		if err := ctx.Err(); err != nil {
			return Inspection{}, err
		}
		return Inspection{}, nil
	}
	values, err := detector.Secrets(ctx, text)
	if err != nil {
		return Inspection{}, err
	}
	values = normalizeValues(values)
	masked, hits := maskText(text, values)
	return Inspection{Values: values, Redacted: []byte(masked), Hits: hits}, nil
}

// InspectJSON scans any strict JSON payload, masks every string value, and
// reports the discovered values. Object keys are scanned for reporting but not
// rewritten; a caller that treats a key hit as fatal must inspect Values.
func InspectJSON(ctx context.Context, detector Redactor, body []byte) (Inspection, error) {
	parsed, err := parseStrictJSON(body)
	if err != nil {
		return Inspection{}, err
	}
	values, _, err := collectSecrets(ctx, detector, parsed, false)
	if err != nil {
		return Inspection{}, err
	}
	masked, hits := maskValues(parsed, values)
	if err := ctx.Err(); err != nil {
		return Inspection{}, err
	}
	encoded, err := json.Marshal(masked)
	if err != nil {
		return Inspection{}, errInvalidBody
	}
	return Inspection{Values: values, Redacted: encoded, Hits: hits}, nil
}

// parseStrictJSON decodes exactly one JSON value, rejecting duplicate keys at
// any depth and any trailing data. encoding/json's Unmarshal keeps the last of
// duplicated keys and tolerates trailing whitespace, so the token stream is
// walked by hand. Errors never carry payload content.
func parseStrictJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	value, err := decodeValue(decoder, 0)
	if err != nil {
		return nil, wrapParseError(err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errInvalidBody
	}
	return value, nil
}

// wrapParseError keeps the duplicate-key sentinel detectable while folding
// every other syntax problem into one 400-class error.
func wrapParseError(err error) error {
	if errors.Is(err, errDuplicateKey) || errors.Is(err, errInvalidBody) {
		return err
	}
	return errInvalidBody
}

func decodeValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, errInvalidBody
	}

	token, err := decoder.Token()
	if err != nil {
		return nil, wrapParseError(err)
	}

	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil // string, json.Number, bool or nil
	}

	switch delim {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, wrapParseError(err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errInvalidBody
			}
			if _, exists := object[key]; exists {
				return nil, errDuplicateKey
			}
			value, err := decodeValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if _, err := decoder.Token(); err != nil { // consume '}'
			return nil, wrapParseError(err)
		}
		return object, nil
	case '[':
		var array []any
		for decoder.More() {
			value, err := decodeValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if _, err := decoder.Token(); err != nil { // consume ']'
			return nil, wrapParseError(err)
		}
		return array, nil
	default:
		return nil, errInvalidBody
	}
}

// path is the key path to a node. Array elements are recorded as "[]".
type path []string

func (p path) push(segment string) path {
	next := make(path, len(p)+1)
	copy(next, p)
	next[len(p)] = segment
	return next
}

func (p path) contains(segment string) bool {
	for _, candidate := range p {
		if candidate == segment {
			return true
		}
	}
	return false
}

// discovery collects every credential value once so a payload can be masked
// consistently in a second pass. When sensitiveKeys is set, the literal value
// of a credential-named field is collected even if the detector cannot rank it
// ("password": "hunter2").
type discovery struct {
	detector      Redactor
	ctx           context.Context
	sensitiveKeys bool
	secrets       map[string]struct{}
	short         map[string]struct{}
}

// add records a value found by the detector anywhere it appears.
func (d *discovery) add(value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if len(value) < minGlobalSecretLen {
		// Too short to replace everywhere without corrupting unrelated text.
		d.short[value] = struct{}{}
		return
	}
	d.secrets[value] = struct{}{}
}

// addSensitive records a value the applier masks in its own field, so a short
// value needs no request-wide replacement and must not force a rejection.
func (d *discovery) addSensitive(value string) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) < minGlobalSecretLen {
		return
	}
	d.secrets[value] = struct{}{}
}

func (d *discovery) scan(text string) error {
	if text == "" {
		return d.ctx.Err()
	}
	found, err := d.detector.Secrets(d.ctx, text)
	if err != nil {
		return err
	}
	for _, secret := range found {
		d.add(secret)
	}
	return d.ctx.Err()
}

func (d *discovery) walk(node any, p path, inheritedSensitive bool) error {
	if err := d.ctx.Err(); err != nil {
		return err
	}
	switch typed := node.(type) {
	case map[string]any:
		for key, value := range typed {
			if err := d.scan(key); err != nil { // keys are reported, never rewritten
				return err
			}
			sensitive := inheritedSensitive
			if d.sensitiveKeys {
				sensitive = sensitive || sensitiveKeyRE.MatchString(key)
			}
			if err := d.walk(value, p.push(key), sensitive); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range typed {
			if err := d.walk(item, p.push("[]"), inheritedSensitive); err != nil {
				return err
			}
		}
	case string:
		if typed == "" {
			return d.ctx.Err()
		}
		found, err := d.detector.Secrets(d.ctx, typed)
		if err != nil {
			return err
		}
		literal := credentialLiteral(p, inheritedSensitive)
		for _, secret := range found {
			if literal {
				d.addSensitive(secret)
			} else {
				d.add(secret)
			}
		}
		if literal {
			d.addSensitive(typed)
		}
	case json.Number:
		// Numeric credentials are redacted in place by the Chat policy, never
		// propagated: replacing a bare number across a payload would corrupt
		// counts, ids and parameters.
	}
	return d.ctx.Err()
}

// credentialLiteral reports whether the string at this path is itself a
// credential because an ancestor field is credential-named. Inside a JSON
// schema only the literal keywords (default/enum/examples/const) qualify: a
// schema's own "type": "string" or "description" must not become a credential
// just because the property is called "password".
func credentialLiteral(p path, sensitiveAncestor bool) bool {
	if !sensitiveAncestor {
		return false
	}
	if p.inSchemaPath() {
		return p.lastSchemaValueKey()
	}
	return true
}

// collectSecrets returns distinct secret values, longest first.
func collectSecrets(ctx context.Context, detector Redactor, root any, sensitiveKeys bool) ([]string, []string, error) {
	found := &discovery{
		detector:      detector,
		ctx:           ctx,
		sensitiveKeys: sensitiveKeys,
		secrets:       make(map[string]struct{}),
		short:         make(map[string]struct{}),
	}
	if err := found.walk(root, nil, false); err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	// Short values must survive: they are not replaced, but their presence makes
	// the request unsafe to forward.
	return normalizeValues(mapKeys(found.secrets)), sortValues(mapKeys(found.short)), nil
}

func mapKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	return out
}

// sortValues deduplicates and orders longest first without dropping short
// values, which the proxy needs in order to refuse them.
func sortValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// normalizeValues deduplicates and sorts longest first, so a shorter secret
// cannot split a longer one during replacement.
func normalizeValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if len(value) < minGlobalSecretLen {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// maskText replaces every known value in text.
func maskText(text string, values []string) (string, int) {
	masked := text
	hits := 0
	for _, value := range values {
		if strings.Contains(masked, value) {
			masked = strings.ReplaceAll(masked, value, RedactedSecret)
			hits++
		}
	}
	return masked, hits
}

// maskValues masks string values in a decoded payload, leaving keys intact.
func maskValues(node any, values []string) (any, int) {
	switch typed := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		hits := 0
		for key, value := range typed {
			masked, count := maskValues(value, values)
			out[key] = masked
			hits += count
		}
		return out, hits
	case []any:
		out := make([]any, len(typed))
		hits := 0
		for i, value := range typed {
			masked, count := maskValues(value, values)
			out[i] = masked
			hits += count
		}
		return out, hits
	case string:
		return maskText(typed, values)
	default:
		return node, 0
	}
}

// containsStandalone reports whether value occurs in text as a separate token
// rather than embedded in a longer word. Short secrets ("a", "7") are unusable
// with plain substring matching: "a" appears inside "messages".
func containsStandalone(text, value string) bool {
	if value == "" || len(value) > len(text) {
		return false
	}
	for offset := 0; offset+len(value) <= len(text); {
		index := strings.Index(text[offset:], value)
		if index < 0 {
			return false
		}
		start := offset + index
		end := start + len(value)
		beforeOK := start == 0 || !isIdentByte(text[start-1])
		afterOK := end == len(text) || !isIdentByte(text[end])
		if beforeOK && afterOK {
			return true
		}
		offset = start + 1
	}
	return false
}

func isIdentByte(b byte) bool {
	return b == '_' ||
		(b >= '0' && b <= '9') ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z')
}

// trimQuotes removes one layer of surrounding quotes from a captured secret so
// the replacement leaves the quoting in place.
func trimQuotes(value string) string {
	pairs := [][2]string{{`"`, `"`}, {`'`, `'`}, {"“", "”"}, {"‘", "’"}}
	for _, pair := range pairs {
		open, close := pair[0], pair[1]
		if len(value) > len(open)+len(close) && strings.HasPrefix(value, open) && strings.HasSuffix(value, close) {
			return value[len(open) : len(value)-len(close)]
		}
	}
	return value
}

// NeutralFindings is the protocol-neutral result used by the /inspect
// preflight. It never carries payload text.
type NeutralFindings struct {
	// Findings is the number of distinct credential values discovered.
	Findings int
	// Unsupported is set when the payload contains content this guard cannot
	// inspect (real image/audio attachments or inline data URIs).
	Unsupported bool
}

// inspectMediaKeys mark an actual attachment in a neutral DSH payload. File
// handles are deliberately excluded: DSH has no native upload, so a "file"
// field is a handle the model never receives as bytes.
var inspectMediaKeys = map[string]struct{}{
	"image_url": {}, "input_image": {}, "input_audio": {},
	"audio_url": {}, "video_url": {}, "b64_json": {},
}

// inspectMediaTypes are content-block type values that mean real media.
var inspectMediaTypes = map[string]struct{}{
	"image": {}, "image_url": {}, "input_image": {},
	"audio": {}, "input_audio": {}, "audio_url": {},
	"video": {}, "video_url": {},
}

// InspectPayload scans a neutral payload: every string and every object key is
// inspected, no Chat-specific structural or media rule is applied, and schemas
// are never treated as attachments. Real media is reported as unsupported
// rather than silently inspected.
func InspectPayload(ctx context.Context, detector Redactor, payload []byte) (NeutralFindings, error) {
	parsed, err := parseStrictJSON(payload)
	if err != nil {
		return NeutralFindings{}, err
	}
	if _, ok := parsed.(map[string]any); !ok {
		return NeutralFindings{}, errInvalidBody
	}

	count, err := countCredentials(ctx, detector, parsed)
	if err != nil {
		return NeutralFindings{}, err
	}
	unsupported, err := unsupportedContent(ctx, parsed, nil)
	if err != nil {
		return NeutralFindings{}, err
	}
	if err := ctx.Err(); err != nil {
		return NeutralFindings{}, err
	}
	return NeutralFindings{Findings: count, Unsupported: unsupported}, nil
}

// countCredentials counts distinct credential values for /inspect. Unlike the
// proxy's replacement set it applies no minimum length and includes numeric
// literals, because a 3-character password or a numeric PIN must still make the
// preflight report a finding.
func countCredentials(ctx context.Context, detector Redactor, root any) (int, error) {
	counter := &credentialCounter{detector: detector, ctx: ctx, values: map[string]struct{}{}}
	if err := counter.walk(root, nil, false); err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return len(counter.values), nil
}

type credentialCounter struct {
	detector Redactor
	ctx      context.Context
	values   map[string]struct{}
}

func (c *credentialCounter) add(value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	c.values[value] = struct{}{}
}

func (c *credentialCounter) walk(node any, p path, sensitiveAncestor bool) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	switch typed := node.(type) {
	case map[string]any:
		for key, value := range typed {
			found, err := c.detector.Secrets(c.ctx, key)
			if err != nil {
				return err
			}
			for _, secret := range found {
				c.add(secret)
			}
			sensitive := sensitiveAncestor || sensitiveKeyRE.MatchString(key)
			if err := c.walk(value, p.push(key), sensitive); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range typed {
			if err := c.walk(item, p.push("[]"), sensitiveAncestor); err != nil {
				return err
			}
		}
	case string:
		if typed == "" {
			return c.ctx.Err()
		}
		found, err := c.detector.Secrets(c.ctx, typed)
		if err != nil {
			return err
		}
		for _, secret := range found {
			c.add(secret)
		}
		if credentialLiteral(p, sensitiveAncestor) {
			c.add(typed)
		}
	case json.Number:
		if credentialLiteral(p, sensitiveAncestor) {
			c.add(typed.String())
		}
	}
	return c.ctx.Err()
}

// blockArrayKeys are arrays whose elements are content blocks.
var blockArrayKeys = map[string]struct{}{"messages": {}, "content": {}, "blocks": {}, "parts": {}}

// knownBlockTypes are the block shapes the plugin may send. Anything else is
// refused: an unknown block could carry bytes this guard cannot inspect.
// Comparison ignores case, '-' and '_'.
var knownBlockTypes = map[string]struct{}{
	"text": {}, "reasoning": {},
	"toolcall": {}, "toolresult": {},
	"functioncall": {}, "functionresult": {},
	// DSH tool-set changes and file handles are text, not bytes. A file block
	// carrying inline data is still refused by the data: check.
	"tooladdition": {}, "toolremoval": {},
	"file": {}, "filehandle": {},
}

func normalizeBlockType(value string) string {
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, "-", "")
	value = strings.ReplaceAll(value, "_", "")
	return value
}

// inBlockArray reports whether the current object is an element of a block
// array (messages/content/blocks/parts).
func inBlockArray(p path) bool {
	n := len(p)
	if n < 2 || p[n-1] != "[]" {
		return false
	}
	_, ok := blockArrayKeys[p[n-2]]
	return ok
}

func unsupportedContent(ctx context.Context, node any, p path) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	switch typed := node.(type) {
	case map[string]any:
		if !p.inSchemaPath() {
			for key, value := range typed {
				if _, media := inspectMediaKeys[strings.ToLower(key)]; media {
					return true, nil
				}
				if strings.EqualFold(key, "type") {
					if name, ok := value.(string); ok {
						if _, media := inspectMediaTypes[strings.ToLower(name)]; media {
							return true, nil
						}
						// A typed block we do not recognise could carry bytes
						// this guard cannot inspect, so it is refused rather
						// than silently scanned as text.
						if inBlockArray(p) {
							if _, known := knownBlockTypes[normalizeBlockType(name)]; !known {
								return true, nil
							}
						}
					}
				}
			}
		}
		for key, value := range typed {
			bad, err := unsupportedContent(ctx, value, p.push(key))
			if err != nil || bad {
				return bad, err
			}
		}
	case []any:
		for _, item := range typed {
			bad, err := unsupportedContent(ctx, item, p.push("[]"))
			if err != nil || bad {
				return bad, err
			}
		}
	case string:
		if !p.inSchemaPath() && strings.HasPrefix(typed, "data:") {
			return true, nil
		}
	}
	return false, ctx.Err()
}
