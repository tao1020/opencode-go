package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

var (
	sharedRedactor     Redactor
	sharedRedactorOnce sync.Once
)

func redactorForTest(t *testing.T) Redactor {
	t.Helper()
	sharedRedactorOnce.Do(func() {
		built, err := buildRedactor()
		if err != nil {
			panic("build redactor: " + err.Error())
		}
		sharedRedactor = built
	})
	return sharedRedactor
}

func mustSanitize(t *testing.T, body string) string {
	t.Helper()
	out, _, err := sanitize(context.Background(), redactorForTest(t), []byte(body))
	if err != nil {
		t.Fatalf("sanitize(%s): %v", body, err)
	}
	return string(out)
}

func TestParseStrictJSONRejectsDuplicateKeysAnywhere(t *testing.T) {
	cases := map[string]string{
		"top level": `{"a":1,"a":2}`,
		"nested":    `{"a":{"b":{"c":1,"c":2}}}`,
		"in array":  `{"a":[{"x":1,"x":2}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseStrictJSON([]byte(body))
			if !errors.Is(err, errDuplicateKey) {
				t.Fatalf("expected duplicate-key error, got %v", err)
			}
		})
	}
}

func TestParseErrorsNeverContainKeysOrContent(t *testing.T) {
	secretKey := "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
	_, err := parseStrictJSON([]byte(`{"` + secretKey + `":1,"` + secretKey + `":2}`))
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), secretKey) || strings.Contains(err.Error(), "ghp_") {
		t.Fatalf("parse error leaked the key: %v", err)
	}
	if got := publicError(err); strings.Contains(got, secretKey) {
		t.Fatalf("public error leaked the key: %q", got)
	}
}

func TestSanitizeRequiresAnObject(t *testing.T) {
	if _, _, err := sanitize(context.Background(), redactorForTest(t), []byte(`[1,2,3]`)); !errors.Is(err, errInvalidBody) {
		t.Fatalf("expected invalid-body error, got %v", err)
	}
}

func TestParseStrictJSONRejectsTrailingDataAndTruncation(t *testing.T) {
	for _, body := range []string{`{"a":1} {}`, `{"a":1}]`, `{"a":1}garbage`, `{"a":1`} {
		_, err := parseStrictJSON([]byte(body))
		if err == nil {
			t.Fatalf("expected an error for %q", body)
		}
		if !errors.Is(err, errInvalidBody) && !errors.Is(err, errDuplicateKey) {
			t.Fatalf("%q: unexpected error class %v", body, err)
		}
	}
}

func TestSanitizeRedactsPasswordsProseAndCredentials(t *testing.T) {
	body := `{"model":"m","messages":[` +
		`{"role":"user","content":"my password is hunter2"},` +
		`{"role":"user","content":"the staging root password is Tr0ub4dor&3"},` +
		`{"role":"user","content":"password: correcthorsebatterystaple"},` +
		`{"role":"user","content":"export PGPASSWORD=supersecret123"},` +
		`{"role":"user","content":"密码是 SuperSecret123!"},` +
		`{"role":"user","content":"token ghp_16C7e42F292c6912E7710c838347Ae178B4a"}]}`

	text := mustSanitize(t, body)
	for _, secret := range []string{"hunter2", "Tr0ub4dor&3", "correcthorsebatterystaple", "supersecret123", "SuperSecret123", "ghp_16C7e42F292c6912E7710c838347Ae178B4a"} {
		if strings.Contains(text, secret) {
			t.Errorf("secret %q survived redaction: %s", secret, text)
		}
	}
	if strings.Count(text, RedactedSecret) < 6 {
		t.Errorf("expected at least 6 replacements, got %d: %s", strings.Count(text, RedactedSecret), text)
	}
}

// Finding 3: a value discovered in one field must be masked everywhere in the
// same request, including when it appears as a bare word elsewhere.
func TestSanitizeAppliesDiscoveryAcrossWholeRequest(t *testing.T) {
	body := `{"model":"m","metadata":{"password":"hunter2"},"messages":[` +
		`{"role":"user","content":"the deploy used hunter2 again"},` +
		`{"role":"assistant","content":"noted: hunter2"}]}`

	text := mustSanitize(t, body)
	if strings.Contains(text, "hunter2") {
		t.Fatalf("discovered value still present in another field: %s", text)
	}
	if strings.Count(text, RedactedSecret) != 3 {
		t.Fatalf("expected 3 replacements, got %d: %s", strings.Count(text, RedactedSecret), text)
	}
}

// Finding 2: credential-named numeric and array fields must not pass through.
func TestSanitizeRedactsSensitiveNumericAndArrayFields(t *testing.T) {
	body := `{"model":"m","metadata":{"password":123456,"api_key":[987654321,"abc12345"]},"messages":[{"role":"user","content":"hello"}]}`
	text := mustSanitize(t, body)

	for _, value := range []string{"123456", "987654321", "abc12345"} {
		if strings.Contains(text, value) {
			t.Errorf("sensitive value %q survived: %s", value, text)
		}
	}
	if !strings.Contains(text, RedactedSecret) {
		t.Fatalf("no redaction marker: %s", text)
	}
}

// Finding 4: quoted literals must be captured in full, including spaces, for
// both prose and assignment forms, and inside JSON-stringified tool arguments.
func TestSanitizeRedactsWholeQuotedLiterals(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		secret string
	}{
		{
			name:   "assignment double quotes with spaces",
			body:   `{"model":"m","messages":[{"role":"user","content":"password=\"correct horse battery staple\""}]}`,
			secret: "correct horse battery staple",
		},
		{
			name:   "assignment single quotes",
			body:   `{"model":"m","messages":[{"role":"user","content":"api_key='a very long secret value'"}]}`,
			secret: "a very long secret value",
		},
		{
			name:   "prose double quotes",
			body:   `{"model":"m","messages":[{"role":"user","content":"the password is \"two words here\""}]}`,
			secret: "two words here",
		},
		{
			name:   "escaped quote inside literal",
			body:   `{"model":"m","messages":[{"role":"user","content":"password=\"pa\\\"ss word\""}]}`,
			secret: "pa\\\"ss word",
		},
		{
			name:   "json stringified tool arguments",
			body:   `{"model":"m","messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"bash","arguments":"{\"password\":\"hunter2\"}"}}]}]}`,
			secret: "hunter2",
		},
		{
			name:   "chinese prose with quotes",
			body:   `{"model":"m","messages":[{"role":"user","content":"密码是“两个词的密码”"}]}`,
			secret: "两个词的密码",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			text := mustSanitize(t, test.body)
			if strings.Contains(text, test.secret) {
				t.Fatalf("quoted secret %q survived: %s", test.secret, text)
			}
			if !strings.Contains(text, RedactedSecret) {
				t.Fatalf("no redaction marker: %s", text)
			}
		})
	}
}

// Finding 7: the gitleaks global allowlist must not silence credentials that
// merely look like plausible dummy values.
func TestSanitizeDoesNotInheritGlobalAllowlistDummies(t *testing.T) {
	for _, body := range []string{
		`{"model":"m","messages":[{"role":"user","content":"password=\"example\""}]}`,
		`{"model":"m","messages":[{"role":"user","content":"password=\"changeme\""}]}`,
		`{"model":"m","messages":[{"role":"user","content":"token=abcdefghijklmnop"}]}`,
		// The shipped global allowlist regex (?i)^true|false|null$ is
		// mis-grouped: it matches any secret containing "false", which would
		// have silently passed this value.
		`{"model":"m","messages":[{"role":"user","content":"password=\"falseAlarm-SuperSecret123\""}]}`,
	} {
		text := mustSanitize(t, body)
		if !strings.Contains(text, RedactedSecret) {
			t.Errorf("credential-shaped literal was not redacted: %s -> %s", body, text)
		}
	}
}

// Finding 1: a tool schema may legitimately declare file/image properties and
// must not be rejected as media; its literals are still scanned.
func TestSanitizeAcceptsToolSchemaWithFileAndImageProperties(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":"read it"}],"tools":[` +
		`{"type":"function","function":{"name":"read","description":"Read a file from disk",` +
		`"parameters":{"type":"object","properties":{` +
		`"file":{"type":"string","description":"path to read"},` +
		`"image":{"type":"string","description":"image path"}},` +
		`"required":["file"]}}}]}`

	text := mustSanitize(t, body)
	for _, keep := range []string{`"file"`, `"image"`, `"read"`, "path to read"} {
		if !strings.Contains(text, keep) {
			t.Errorf("schema field %s was altered: %s", keep, text)
		}
	}
}

func TestSanitizeRedactsSchemaLiteralsUnderSensitiveProperty(t *testing.T) {
	body := `{"model":"m","messages":[],"tools":[{"type":"function","function":{"name":"login",` +
		`"parameters":{"type":"object","properties":{"password":{"type":"string","default":"hunter2","enum":["hunter2","letmein"]}}}}}]}`

	text := mustSanitize(t, body)
	for _, secret := range []string{"hunter2", "letmein"} {
		if strings.Contains(text, secret) {
			t.Errorf("schema literal %q survived: %s", secret, text)
		}
	}
}

// Finding 1: structural rejection is location-aware, not name-based.
func TestSanitizeStructuralFieldsAreLocationAware(t *testing.T) {
	t.Run("tool function name is structural", func(t *testing.T) {
		body := `{"model":"m","messages":[],"tools":[{"type":"function","function":{"name":"ghp_16C7e42F292c6912E7710c838347Ae178B4a","parameters":{"type":"object","properties":{}}}}]}`
		_, _, err := sanitize(context.Background(), redactorForTest(t), []byte(body))
		if !errors.Is(err, errSecretInStructural) {
			t.Fatalf("expected structural error, got %v", err)
		}
	})

	t.Run("model is structural", func(t *testing.T) {
		body := `{"model":"ghp_16C7e42F292c6912E7710c838347Ae178B4a","messages":[]}`
		_, _, err := sanitize(context.Background(), redactorForTest(t), []byte(body))
		if !errors.Is(err, errSecretInStructural) {
			t.Fatalf("expected structural error, got %v", err)
		}
	})

	t.Run("user metadata name is masked, not rejected", func(t *testing.T) {
		body := `{"model":"m","messages":[],"metadata":{"name":"ghp_16C7e42F292c6912E7710c838347Ae178B4a"}}`
		text := mustSanitize(t, body)
		if strings.Contains(text, "ghp_16C7e42F292c6912E7710c838347Ae178B4a") {
			t.Fatalf("metadata name was not masked: %s", text)
		}
	})
}

func TestSanitizeRejectsSecretInObjectKey(t *testing.T) {
	body := `{"model":"m","ghp_16C7e42F292c6912E7710c838347Ae178B4a":1}`
	_, _, err := sanitize(context.Background(), redactorForTest(t), []byte(body))
	if !errors.Is(err, errSecretInStructural) {
		t.Fatalf("expected structural-secret error for key, got %v", err)
	}
}

func TestSanitizeRejectsMediaOnlyInContentBlocks(t *testing.T) {
	t.Run("image content block", func(t *testing.T) {
		body := `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}]}`
		if _, _, err := sanitize(context.Background(), redactorForTest(t), []byte(body)); !errors.Is(err, errMedia) {
			t.Fatalf("expected media error, got %v", err)
		}
	})
	t.Run("data uri", func(t *testing.T) {
		body := `{"model":"m","messages":[{"role":"user","content":"data:image/png;base64,AAAA"}]}`
		if _, _, err := sanitize(context.Background(), redactorForTest(t), []byte(body)); !errors.Is(err, errMedia) {
			t.Fatalf("expected media error, got %v", err)
		}
	})
	t.Run("media error does not echo the value", func(t *testing.T) {
		body := `{"model":"m","messages":[{"role":"user","content":"data:secretpayload"}]}`
		_, _, err := sanitize(context.Background(), redactorForTest(t), []byte(body))
		if err == nil || strings.Contains(err.Error(), "secretpayload") {
			t.Fatalf("media error leaked the value: %v", err)
		}
	})
}

func TestSanitizeIgnoresGitleaksAllowComments(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":"token ghp_16C7e42F292c6912E7710c838347Ae178B4a // gitleaks:allow"}]}`
	if strings.Contains(mustSanitize(t, body), "ghp_16C7e42F292c6912E7710c838347Ae178B4a") {
		t.Fatal("gitleaks:allow muted the guard")
	}
}

func TestSanitizePreservesOrdinaryIdentifiers(t *testing.T) {
	body := `{"model":"gpt-4o-mini","max_tokens":512,"messages":[{"role":"user","content":"commit 9fceb02 fixed max_tokens handling in redact.go for request id 550e8400"}]}`
	out, redactions, err := sanitize(context.Background(), redactorForTest(t), []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if redactions != 0 {
		t.Errorf("expected no redactions, got %d: %s", redactions, out)
	}
	for _, keep := range []string{"9fceb02", "max_tokens", "redact.go", "gpt-4o-mini", "550e8400"} {
		if !strings.Contains(string(out), keep) {
			t.Errorf("ordinary identifier %q was altered: %s", keep, out)
		}
	}
}

// Finding 6: cancellation is honoured for empty input and after the walk.
func TestSanitizeReportsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := sanitize(ctx, redactorForTest(t), []byte(`{"model":"m","messages":[]}`)); err == nil {
		t.Fatal("expected an error for a cancelled context")
	}
	if _, _, err := sanitize(ctx, redactorForTest(t), []byte(`{"model":"m","messages":[{"role":"user","content":""}]}`)); err == nil {
		t.Fatal("expected an error for a cancelled context with empty strings")
	}
}

// The neutral inspector must work on payloads that are not Chat requests and
// must not apply Chat-specific rejection.
func TestInspectJSONIsProtocolNeutral(t *testing.T) {
	payload := []byte(`{"file":"x","image":"y","note":"password=Sup3rSecret!"}`)
	inspection, err := InspectJSON(context.Background(), redactorForTest(t), payload)
	if err != nil {
		t.Fatalf("neutral inspection must not reject: %v", err)
	}
	if strings.Contains(string(inspection.Redacted), "Sup3rSecret!") {
		t.Fatalf("secret survived neutral inspection: %s", inspection.Redacted)
	}
	if len(inspection.Values) == 0 {
		t.Fatal("expected discovered values")
	}
	if !json.Valid(inspection.Redacted) {
		t.Fatalf("redacted payload is not valid JSON: %s", inspection.Redacted)
	}
}

func TestInspectTextIsProtocolNeutral(t *testing.T) {
	inspection, err := InspectText(context.Background(), redactorForTest(t), "the api key is sk-proj-AbCdEf1234567890abcdef1234567890")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(inspection.Redacted), "sk-proj-") {
		t.Fatalf("secret survived: %s", inspection.Redacted)
	}
}

func TestRedactorIsSafeForConcurrentUse(t *testing.T) {
	detector := redactorForTest(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := detector.Secrets(context.Background(), "password=hunter2 token ghp_16C7e42F292c6912E7710c838347Ae178B4a"); err != nil {
				t.Errorf("concurrent scan failed: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestValidateUpstream(t *testing.T) {
	for _, raw := range []string{"https://api.example.com/v1/chat/completions", "http://127.0.0.1:9999/v1/chat/completions"} {
		if _, err := validateUpstream(raw); err != nil {
			t.Errorf("%s should be valid: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"http://api.example.com/v1/chat/completions",
		"ftp://api.example.com/v1",
		"https://user:pass@api.example.com/v1/chat/completions",
		"https://api.example.com/v1/chat/completions?x=1",
		"",
	} {
		if _, err := validateUpstream(raw); err == nil {
			t.Errorf("%s should be rejected", raw)
		}
	}
}

func TestValidateListenAddrIsLoopbackOnly(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8788", "[::1]:8788"} {
		if err := validateListenAddr(addr); err != nil {
			t.Errorf("%s should be allowed: %v", addr, err)
		}
	}
	for _, addr := range []string{"0.0.0.0:8788", ":8788", "10.1.2.3:8788", "example.com:8788"} {
		if err := validateListenAddr(addr); err == nil {
			t.Errorf("%s should be rejected", addr)
		}
	}
}

// A tool schema with a password property must not add its "type"/"description"
// strings to the request-wide replacement set.
func TestSanitizeSchemaPasswordPropertyDoesNotPoisonRequest(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":"use type string here"}],` +
		`"tools":[{"type":"function","function":{"name":"login","parameters":{"type":"object",` +
		`"properties":{"password":{"type":"string","description":"the account password"}}}}}]}`

	out, redactions, err := sanitize(context.Background(), redactorForTest(t), []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if redactions != 0 {
		t.Fatalf("schema metadata became a credential (%d redactions): %s", redactions, out)
	}
	if !strings.Contains(string(out), `"type":"string"`) || !strings.Contains(string(out), "use type string here") {
		t.Fatalf("schema metadata was altered: %s", out)
	}
	if !strings.Contains(string(out), "the account password") {
		t.Fatalf("description was altered: %s", out)
	}
}

// A short contextual secret cannot be replaced request-wide without corrupting
// unrelated text, so it must fail closed rather than be forwarded.
func TestSanitizeRejectsShortContextualSecrets(t *testing.T) {
	for _, secret := range []string{"abc", "xy", "7", "a"} {
		t.Run(secret, func(t *testing.T) {
			body := `{"model":"m","messages":[{"role":"user","content":"database password=\"` + secret + `\""}]}`
			_, _, err := sanitize(context.Background(), redactorForTest(t), []byte(body))
			if !errors.Is(err, errShortSecret) {
				t.Fatalf("expected short-secret rejection for %q, got %v", secret, err)
			}
		})
	}
}

func TestSanitizeRejectsShortProseSecret(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":"the password is \"ab\""}]}`
	if _, _, err := sanitize(context.Background(), redactorForTest(t), []byte(body)); !errors.Is(err, errShortSecret) {
		t.Fatalf("expected short-secret rejection, got %v", err)
	}
}

// An empty credential value carries nothing and must not be rejected.
func TestSanitizeAllowsEmptyCredentialValues(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":"password=\"\""}],"metadata":{"password":""}}`
	out, _, err := sanitize(context.Background(), redactorForTest(t), []byte(body))
	if err != nil {
		t.Fatalf("empty credential value must be allowed: %v", err)
	}
	if !strings.Contains(string(out), `password=\"\"`) && !strings.Contains(string(out), `password=""`) {
		t.Fatalf("empty value was altered: %s", out)
	}
}

// A short value inside its own credential-named field is masked in place, so it
// needs no request-wide replacement and is not a rejection case.
func TestSanitizeMasksShortSensitiveFieldInPlace(t *testing.T) {
	body := `{"model":"m","messages":[],"metadata":{"password":"abc","api_key":"7"}}`
	out, _, err := sanitize(context.Background(), redactorForTest(t), []byte(body))
	if err != nil {
		t.Fatalf("short sensitive field should be masked, not rejected: %v", err)
	}
	if strings.Contains(string(out), `"abc"`) || strings.Contains(string(out), `"7"`) {
		t.Fatalf("short sensitive values survived: %s", out)
	}
}

// Long quoted literals still take the normal global-replacement path.
func TestSanitizeRedactsLongQuotedLiteral(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":"password=\"correct horse battery staple\""}]}`
	out, _, err := sanitize(context.Background(), redactorForTest(t), []byte(body))
	if err != nil {
		t.Fatalf("long literal must be redacted, not rejected: %v", err)
	}
	if strings.Contains(string(out), "correct horse battery staple") {
		t.Fatalf("long quoted secret survived: %s", out)
	}
}

// Unquoted assignment values are structured, so even one character counts.
func TestSanitizeRejectsShortUnquotedAssignment(t *testing.T) {
	for _, value := range []string{"a", "ab", "xy7"} {
		body := `{"model":"m","messages":[{"role":"user","content":"db password=` + value + `"}]}`
		if _, _, err := sanitize(context.Background(), redactorForTest(t), []byte(body)); !errors.Is(err, errShortSecret) {
			t.Fatalf("expected short-secret rejection for %q, got %v", value, err)
		}
	}
}
