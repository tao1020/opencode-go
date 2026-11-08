package main

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// Contextual masking still hides these values at the assignment itself. Only
// request-wide propagation excludes placeholders, protocol words and delimiters.
var propagationAllowREs = compileAll(append(append([]string(nil), defaultSecretAllowlist...),
	`(?i)^(?:example|object|array|text|function|system|developer|user|assistant|tool)$`, `^\\+$`))

func isPropagationPlaceholder(value string) bool {
	for _, re := range propagationAllowREs {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

// The prefix ends at the opening quote, so consecutive headers cannot swallow
// each other's credential spans.
var maskEscapedAuthRE = regexp.MustCompile(`(?i)(?:\b|\\[nrt])(?:proxy-)?authorization\s*:\s*(bearer|basic|digest|negotiate|token|bot)\s+(\\+")`)

// escapedContextSpans finds values inside JSON-escaped quotes without decoding
// or reserializing their surrounding source. All offsets refer to original bytes.
func escapedContextSpans(text string) []textSpan {
	return credentialContextSpans(text, false)
}

func credentialContextSpans(text string, credentials bool) []textSpan {
	if !strings.Contains(text, `\"`) {
		return nil
	}
	var spans []textSpan
	rules := []struct {
		re    *regexp.Regexp
		group int
	}{{maskAssignRE, 1}, {maskProseENRE, 1}, {maskProseZHRE, 1}, {maskRefDefaultRE, 1}, {maskEscapedAuthRE, 2}}
	if credentials {
		rules = append(rules, struct {
			re    *regexp.Regexp
			group int
		}{credentialExtraAssignRE, 1}, struct {
			re    *regexp.Regexp
			group int
		}{credentialUserZHRE, 1})
	}
	for _, rule := range rules {
		for _, match := range rule.re.FindAllStringSubmatchIndex(text, -1) {
			start := match[rule.group*2]
			if start < 0 {
				continue
			}
			quote := start
			for quote < len(text) && text[quote] == '\\' {
				quote++
			}
			n := quote - start
			if n%2 == 0 || quote >= len(text) || text[quote] != '"' {
				continue
			}
			// The trailing one bits identify the JSON delimiter (1, 3, 7,
			// ...). Higher bits are preceding literal backslashes, not another
			// quoting layer: an opening run of 5 has a delimiter width of 1.
			width := ((n + 1) & -(n + 1)) - 1
			for i := quote + 1; i < len(text); {
				if text[i] != '\\' {
					i++
					continue
				}
				run := i
				for i < len(text) && text[i] == '\\' {
					i++
				}
				// Embedded escaped quotes have a different parity. Keep any
				// encoded trailing backslashes in the value, not its delimiter.
				if i < len(text) && text[i] == '"' && (i-run)%(2*(width+1)) == width {
					spans = append(spans, textSpan{start: quote + 1, end: i - width})
					break
				}
			}
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
		if len(out) == 0 || (span != out[len(out)-1] && span.start >= out[len(out)-1].end) {
			out = append(out, span)
		}
	}
	return out
}

// discoverEscaped reuses the detector once for a bounded batch. Artificial JSON
// quotes keep candidates separate; only exact original candidates can propagate.
// Short literals and known placeholder words remain confined to their source span.
func (m *masker) discoverEscaped(text string, found map[string]struct{}) error {
	candidates := make(map[string]struct{})
	var batch strings.Builder
	for _, span := range credentialContextSpans(text, m.credentials) {
		value := text[span.start:span.end]
		if len(value) < maskMinPropagate || isExactReference(value) || m.containsKnownToken(value) || isPropagationPlaceholder(value) {
			continue
		}
		if _, exists := candidates[value]; exists {
			continue
		}
		if len(value) > maskPerScopeBudget || len(candidates) >= maskMaxMappings {
			return errMaskCapacity
		}
		candidates[value] = struct{}{}
		quoted, err := json.Marshal(value)
		if err != nil {
			return err
		}
		// Use the existing encoded-data budget for the derived scan input too.
		if batch.Len()+len(quoted)+10 > maskMaxResponse {
			return errMaskCapacity
		}
		if err := m.ctx.Err(); err != nil {
			return err
		}
		batch.WriteString("password=")
		batch.Write(quoted)
		batch.WriteByte('\n')
	}
	if len(candidates) == 0 {
		return nil
	}
	values, err := m.secrets(batch.String())
	if err != nil {
		return err
	}
	for _, encoded := range values {
		var value string
		if json.Unmarshal([]byte(`"`+encoded+`"`), &value) != nil {
			continue
		}
		if _, exact := candidates[value]; exact {
			m.collectDiscovered(found, value)
		}
	}
	return nil
}

func (m *masker) maskEscapedAssignments(text string) (string, error) {
	spans := credentialContextSpans(text, m.credentials)
	for i := len(spans) - 1; i >= 0; i-- {
		span := spans[i]
		value := text[span.start:span.end]
		if value == "" || isExactReference(value) || m.containsKnownToken(value) {
			continue
		}
		token, err := m.token(value, "")
		if err != nil {
			return "", err
		}
		text = text[:span.start] + token + text[span.end:]
	}
	return text, nil
}
