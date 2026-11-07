package main

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// The real OpenCode CLI sends a JSON-quoted prompt inside message.content.
// The outer request JSON decoding does not remove that additional quoting.
func TestMaskOpenCodeCLIQuotedPrompt(t *testing.T) {
	const secret = "SyntheticCLI1234567890abcdef!"
	prompt := `This is a synthetic test. password="` + secret + `". Return only JSON.`
	quoted, err := json.Marshal(prompt)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{"messages": []any{map[string]any{"role": "user", "content": string(quoted)}}}
	gateway := maskGateway(t)
	recorder, masked := postMask(t, gateway.Routes(), maskEnvelope(t, testMaskScope, payload), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("mask returned status %d", recorder.Code)
	}
	serialized, err := json.Marshal(masked.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serialized), secret) {
		t.Fatal("CLI-quoted password remains in the upstream payload")
	}
	var decoded any
	if err := json.Unmarshal(masked.Payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restoreTree(decoded, masked.Mappings), payload) {
		t.Fatal("CLI-quoted prompt did not round-trip exactly")
	}
}

func maskQuotedFixture(t *testing.T, text string, layers int) (string, []maskMapping) {
	t.Helper()
	for range layers {
		encoded, err := json.Marshal(text)
		if err != nil {
			t.Fatal(err)
		}
		text = string(encoded)
	}
	payload := map[string]any{"messages": []any{map[string]any{"role": "user", "content": text}}}
	recorder, masked := postMask(t, maskGateway(t).Routes(), maskEnvelope(t, testMaskScope, payload), testClientKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d", recorder.Code)
	}
	var decoded struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(masked.Payload, &decoded); err != nil {
		t.Fatal(err)
	}
	content := decoded.Messages[0].Content
	byToken := map[string]string{}
	for _, mapping := range masked.Mappings {
		byToken[mapping.Token] = mapping.Original
	}
	restored := maskTokenRE.ReplaceAllStringFunc(content, func(token string) string {
		if original, ok := byToken[token]; ok {
			return original
		}
		return token
	})
	if restored != text {
		t.Fatal("fixture did not round-trip in one pass")
	}
	return content, masked.Mappings
}

func TestEscapedAssignmentBoundaries(t *testing.T) {
	for _, secret := range []string{`SyntheticValue123!`, `ab\"cd\\ef`, `ab\\`, `token=inside`, `a`, `!@#`, `with spaces`} {
		for _, layers := range []int{1, 2} {
			t.Run(secret+strings.Repeat("Q", layers), func(t *testing.T) {
				content, mappings := maskQuotedFixture(t, `before password="`+secret+`" after`, layers)
				encodedSecret := secret
				for range layers {
					raw, _ := json.Marshal(encodedSecret)
					encodedSecret = string(raw[1 : len(raw)-1])
				}
				if len(mappings) != 1 || mappings[0].Original != encodedSecret {
					t.Fatal("wrong escaped value span")
				}
				if len(encodedSecret) >= maskMinPropagate && strings.Contains(content, encodedSecret) {
					t.Fatal("escaped value remains")
				}
			})
		}
	}
	for _, text := range []string{`{"apiKey":"SyntheticValue123!"}`, `password is: "SyntheticValue123!"`, `密码是："SyntheticValue123!"`, "before\npassword is: \"SyntheticValue123!\"", "before\nos.getenv(\"TOKEN\", \"SyntheticValue123!\")"} {
		content, _ := maskQuotedFixture(t, text, 1)
		if strings.Contains(content, "SyntheticValue123!") {
			t.Fatal("escaped context remains")
		}
	}
}

func TestEscapedEnvironmentReferences(t *testing.T) {
	for _, text := range []string{`password="${TOKEN}"`, `password="$TOKEN"`, `password=os.environ["DB_PASSWORD"]`, `password=os.getenv("DB_PASSWORD")`, `password=process.env["DB_PASSWORD"]`} {
		t.Run(text, func(t *testing.T) {
			_, mappings := maskQuotedFixture(t, text, 1)
			if len(mappings) != 0 {
				t.Fatal("environment reference was masked")
			}
		})
	}
	content, _ := maskQuotedFixture(t, `password=os.getenv("DB_PASSWORD", "SyntheticFallback123!")`, 1)
	if strings.Contains(content, "SyntheticFallback123!") {
		t.Fatal("escaped fallback remains")
	}
}

func TestEscapedAuthorizationHeaders(t *testing.T) {
	for _, layers := range []int{1, 2} {
		text := "Authorization: Bearer \"SyntheticFirst123!\"\nAuthorization: Basic \"SyntheticSecond456!\""
		content, mappings := maskQuotedFixture(t, text, layers)
		if len(mappings) != 2 || strings.Contains(content, "SyntheticFirst123!") || strings.Contains(content, "SyntheticSecond456!") {
			t.Fatal("escaped authorization credentials remain")
		}
		if !strings.Contains(content, "Authorization: Bearer") || !strings.Contains(content, "Authorization: Basic") {
			t.Fatal("authorization scheme changed")
		}
	}
	_, mappings := maskQuotedFixture(t, `Authorization: Bearer "${TOKEN}"`, 1)
	if len(mappings) != 0 {
		t.Fatal("header variable reference was masked")
	}
}

func TestEscapedSamplesPreserveToolSchema(t *testing.T) {
	for _, value := range []string{"string", "example", "true", "a", "object", "user", "function", "filePath"} {
		t.Run(value, func(t *testing.T) {
			prompt, _ := json.Marshal(`Example password="` + value + `"`)
			tools := []any{map[string]any{"type": "function", "function": map[string]any{"name": "read", "parameters": map[string]any{"type": "object", "properties": map[string]any{"a": map[string]any{"type": "string", "default": "string"}, "filePath": map[string]any{"type": "string"}}, "required": []any{"a", "filePath"}}}}}
			payload := map[string]any{"messages": []any{map[string]any{"role": "user", "content": string(prompt)}}, "tools": tools, "status": "example", "flag": "true", "copy": "a"}
			recorder, masked := postMask(t, maskGateway(t).Routes(), maskEnvelope(t, testMaskScope, payload), testClientKey)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status %d", recorder.Code)
			}
			var decoded map[string]any
			if err := json.Unmarshal(masked.Payload, &decoded); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decoded["tools"], tools) || decoded["status"] != "example" || decoded["flag"] != "true" || decoded["copy"] != "a" {
				t.Fatal("escaped sample changed unrelated schema or status values")
			}
			message := decoded["messages"].([]any)[0].(map[string]any)
			if message["role"] != "user" {
				t.Fatal("escaped sample changed the protocol role")
			}
			if len(masked.Mappings) != 1 || masked.Mappings[0].Original != value {
				t.Fatal("sample span must be masked exactly once")
			}
		})
	}
}

func TestEscapedSecretPropagatesToRepeatedValue(t *testing.T) {
	const secret = "SyntheticRepeatedSecret123!"
	prompt, _ := json.Marshal(`password="` + secret + `"`)
	payload := map[string]any{"messages": []any{map[string]any{"role": "user", "content": string(prompt)}}, "echo": secret}
	recorder, masked := postMask(t, maskGateway(t).Routes(), maskEnvelope(t, testMaskScope, payload), testClientKey)
	if recorder.Code != http.StatusOK || strings.Contains(string(masked.Payload), secret) {
		t.Fatal("known escaped secret remains elsewhere in the same request")
	}
}

func TestEscapedLiteralBackslashes(t *testing.T) {
	for _, slashes := range []int{1, 2, 3, 4} {
		text := "before password=" + strings.Repeat("\\", slashes) + `"secret123` + strings.Repeat("\\", slashes) + `" after`
		content, _ := maskQuotedFixture(t, text, 1)
		if strings.Contains(content, "secret123") {
			t.Fatal("literal-backslash quoted value remains")
		}
	}
}

func TestSchemaRequiredNameBoundaries(t *testing.T) {
	for _, tc := range []struct {
		p    path
		want bool
	}{
		{path{"tools", "[]", "function", "parameters", "required", "[]"}, true},
		{path{"functions", "[]", "parameters", "properties", "default", "required", "[]"}, true},
		{path{"response_format", "json_schema", "schema", "required", "[]"}, true},
		{path{"tools", "[]", "function", "parameters", "default", "required", "[]"}, false},
		{path{"tools", "[]", "function", "parameters", "enum", "[]", "required", "[]"}, false},
		{path{"messages", "[]", "tool_calls", "[]", "arguments", "tools", "parameters", "required", "[]"}, false},
	} {
		if maskSchemaRequiredName(tc.p) != tc.want {
			t.Fatalf("wrong required-name classification: %v", tc.p)
		}
	}
	const secret = "SyntheticSchemaData123!"
	prompt, _ := json.Marshal(`password="` + secret + `"`)
	payload := map[string]any{"messages": []any{map[string]any{"role": "user", "content": string(prompt)}}, "tools": []any{map[string]any{"type": "function", "function": map[string]any{"name": "read", "parameters": map[string]any{"type": "object", "default": map[string]any{"required": []any{secret}}}}}}}
	recorder, masked := postMask(t, maskGateway(t).Routes(), maskEnvelope(t, testMaskScope, payload), testClientKey)
	if recorder.Code != http.StatusOK || strings.Contains(string(masked.Payload), secret) {
		t.Fatal("literal schema data was incorrectly treated as a property identity")
	}
}

func TestQuotedPunctuationRemainsProtected(t *testing.T) {
	for _, value := range []string{`!!!!`, `\\\\`, `***`} {
		_, mappings := maskQuotedFixture(t, `password="`+value+`"`, 0)
		if len(mappings) != 1 || mappings[0].Original != value {
			t.Fatal("quoted punctuation secret was not masked exactly")
		}
	}
}

func TestEscapedDiscoveryBatchIsolation(t *testing.T) {
	values := []string{"FirstSecret\\\"\npassword=UnrelatedCandidate123!", "SecondSecret456!"}
	var source strings.Builder
	want := map[string]struct{}{}
	for _, value := range values {
		literal, _ := json.Marshal(value)
		source.WriteString("password=")
		source.Write(literal)
		source.WriteByte(';')
		raw, _ := json.Marshal(string(literal[1 : len(literal)-1]))
		want[string(raw[1:len(raw)-1])] = struct{}{}
	}
	quoted, _ := json.Marshal(source.String())
	worker := &masker{ctx: context.Background(), detector: maskGateway(t).redactor}
	found := map[string]struct{}{}
	if err := worker.discoverEscaped(string(quoted), found); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(found, want) {
		t.Fatal("batch discovery changed candidate boundaries or admitted a partial finding")
	}
}

func TestEscapedDiscoveryBudgetAndCancellation(t *testing.T) {
	worker := &masker{ctx: context.Background(), detector: maskGateway(t).redactor}
	text := `password=\"` + strings.Repeat("<", maskMaxResponse/6+1) + `\"`
	if err := worker.discoverEscaped(text, map[string]struct{}{}); err != errMaskCapacity {
		t.Fatalf("expanded scan budget: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	worker.ctx = ctx
	if err := worker.discoverEscaped(`password=\"SyntheticCancellation123!\"`, map[string]struct{}{}); err != context.Canceled {
		t.Fatalf("cancelled discovery: %v", err)
	}
}

func FuzzEscapedValueSpan(f *testing.F) {
	for _, seed := range []string{"", "abc", "a\\\"b\\\\", "line\nnext", "密码", "token=inside", "Authorization: Basic \"abc\""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, secret string) {
		if len(secret) > 1024 {
			t.Skip()
		}
		literal, _ := json.Marshal(secret)
		// Even literal backslashes before the opening quote become odd runs
		// such as 5/9/13 after JSON quoting, without belonging to the value.
		text := "before password=" + strings.Repeat("\\", 2*(len(secret)%4)) + string(literal) + " after"
		value := string(literal[1 : len(literal)-1])
		for range 3 {
			encoded, _ := json.Marshal(text)
			text = string(encoded)
			encoded, _ = json.Marshal(value)
			value = string(encoded[1 : len(encoded)-1])
			spans := escapedContextSpans(text)
			if len(spans) != 1 || text[spans[0].start:spans[0].end] != value {
				t.Fatal("escaped span does not equal the raw encoded value")
			}
		}
	})
}
