package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestCredentialModeRoundTripAndStableRestart(t *testing.T) {
	cfg := Config{ClientAPIKey: testClientKey, Detector: "credentials"}
	input := map[string]any{"role": "user", "username": "alice", "password": "abc12345", "ak": "LTAIabcdefghijklmnop", "sk": "SyntheticSecretKey123456", "content": "ordinary alice abc12345"}
	var first maskResponse
	for i := 0; i < 2; i++ {
		g, err := NewGateway(cfg)
		if err != nil {
			t.Fatal(err)
		}
		rec, res := postMask(t, g.Routes(), maskEnvelope(t, testMaskScope, input), testClientKey)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		if !reflect.DeepEqual(restoreTree(mustDecode(t, res.Payload), res.Mappings), input) {
			t.Fatal("round trip changed values")
		}
		if len(res.Mappings) != 4 {
			t.Fatalf("want four credentials, got %d", len(res.Mappings))
		}
		for _, v := range []string{"alice", "abc12345", "LTAIabcdefghijklmnop", "SyntheticSecretKey123456"} {
			if strings.Contains(string(res.Payload), v) {
				t.Fatal("credential remained visible")
			}
		}
		if i == 0 {
			first = res
		} else if string(first.Payload) != string(res.Payload) {
			t.Fatal("restart changed masked history")
		}
	}
}

func mustDecode(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCredentialModeNewSecretMasksEarlierText(t *testing.T) {
	g, err := NewGateway(Config{ClientAPIKey: testClientKey, Detector: "credentials"})
	if err != nil {
		t.Fatal(err)
	}
	_, a := postMask(t, g.Routes(), maskEnvelope(t, testMaskScope, map[string]any{"content": "ordinary abc12345"}), testClientKey)
	if len(a.Mappings) != 0 {
		t.Fatal("ordinary text was masked")
	}
	_, b := postMask(t, g.Routes(), maskEnvelope(t, testMaskScope, map[string]any{"content": "ordinary abc12345", "password": "abc12345"}), testClientKey)
	if strings.Contains(string(b.Payload), "abc12345") {
		t.Fatal("new secret leaked from earlier text")
	}
}

func TestCredentialModeLexicalInputs(t *testing.T) {
	cases := []struct {
		text   string
		values []string
	}{
		{`username="alice" password="short"`, []string{"alice", "short"}},
		{`{"user":"alice","AccessKeyId":"SyntheticAccessId123","SecretAccessKey":"SyntheticSecretKey123"}`, []string{"alice", "SyntheticAccessId123", "SyntheticSecretKey123"}},
		{`{"command":"echo \"username=alice password=short\""}`, []string{"alice", "short"}},
		{`用户名是 alice，密码是 short`, []string{"alice", "short"}},
		{`postgres://alice:password123@db.example/test`, []string{"alice", "password123"}},
		{`Authorization: Bearer SyntheticBearer1234567890`, []string{"SyntheticBearer1234567890"}},
		{`AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF AWS_SECRET_ACCESS_KEY=someSecret1234567890`, []string{"AKIA1234567890ABCDEF", "someSecret1234567890"}},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			g, err := NewGateway(Config{ClientAPIKey: testClientKey, Detector: "credentials"})
			if err != nil {
				t.Fatal(err)
			}
			input := map[string]any{"content": tc.text}
			rec, r := postMask(t, g.Routes(), maskEnvelope(t, testMaskScope, input), testClientKey)
			if rec.Code != 200 {
				t.Fatalf("status %d", rec.Code)
			}
			for _, v := range tc.values {
				if strings.Contains(string(r.Payload), v) {
					t.Fatalf("credential remained: %q", v)
				}
			}
			if !reflect.DeepEqual(restoreTree(mustDecode(t, r.Payload), r.Mappings), input) {
				t.Fatal("round trip failed")
			}
		})
	}
}

func TestCredentialModeScopesAndInvalidConfig(t *testing.T) {
	if _, err := NewGateway(Config{ClientAPIKey: testClientKey, Detector: "typo"}); err == nil {
		t.Fatal("invalid mode accepted")
	}
	tokens := map[string]bool{}
	for _, scope := range []string{testMaskScope, strings.Repeat("b", 32)} {
		for _, key := range []string{testClientKey, strings.Repeat("c", 32)} {
			g, err := NewGateway(Config{ClientAPIKey: key, Detector: "credentials"})
			if err != nil {
				t.Fatal(err)
			}
			_, r := postMask(t, g.Routes(), maskEnvelope(t, scope, map[string]any{"password": "samePassword123"}), key)
			token := r.Mappings[0].Token
			if tokens[token] {
				t.Fatal("scopes or installations shared tokens")
			}
			tokens[token] = true
		}
	}
}

func BenchmarkCredentialLongHistory(b *testing.B) {
	text := strings.Repeat("ordinary source code and tool output with no private values\n", 4000) + `password="SyntheticBenchmark123!"`
	body, _ := json.Marshal(map[string]any{"version": 1, "scope": testMaskScope, "payload": map[string]any{"messages": []any{map[string]any{"role": "user", "content": text}}}})
	for _, mode := range []string{"gitleaks", "credentials"} {
		b.Run(mode, func(b *testing.B) {
			g, err := NewGateway(Config{ClientAPIKey: testClientKey, Detector: mode})
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := g.maskPayload(context.Background(), body); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestCredentialCacheCancellationAndBounds(t *testing.T) {
	r := &credentialRedactor{}
	if _, err := r.Secrets(context.Background(), `password="cached-secret"`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Secrets(ctx, `password="cached-secret"`); err != context.Canceled {
		t.Fatal("cached result ignored cancellation")
	}
	for i := 0; i < 1100; i++ {
		if _, err := r.Secrets(context.Background(), fmt.Sprintf("ordinary %d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.cache) > 1024 || r.cachedSpans > 65536 {
		t.Fatal("cache exceeded bounds")
	}
}

func TestCredentialModeUnicodeBeforeAssignment(t *testing.T) {
	r := &credentialRedactor{}
	values, err := r.Secrets(context.Background(), `ȺȺȺ 中文 password="real-secret"`)
	if err != nil || !reflect.DeepEqual(values, []string{"real-secret"}) {
		t.Fatalf("invalid offsets: %v %v", values, err)
	}
}

func TestCredentialConcurrentRequests(t *testing.T) {
	g, err := NewGateway(Config{ClientAPIKey: testClientKey, Detector: "credentials"})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(maskEnvelope(t, testMaskScope, map[string]any{"password": "sharedSecret123", "username": "test_alice"}))
	expected, err := g.maskPayload(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 30; j++ {
				result, err := g.maskPayload(context.Background(), body)
				if err != nil || string(result.Payload) != string(expected.Payload) {
					t.Error("concurrent request lost stable masking")
					return
				}
			}
		}()
	}
	workers.Wait()
}

func TestCredentialAliasesRequireFieldBoundaries(t *testing.T) {
	g, err := NewGateway(Config{ClientAPIKey: testClientKey, Detector: "credentials"})
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"reasoning_effort": "high", "content": `risk: high task: medium mask: low ask: first role: user`}
	_, r := postMask(t, g.Routes(), maskEnvelope(t, testMaskScope, input), testClientKey)
	if len(r.Mappings) != 0 {
		t.Fatal("ordinary word ending in sk or ak was classified as a credential")
	}
	input["password"] = "high"
	_, r = postMask(t, g.Routes(), maskEnvelope(t, testMaskScope, input), testClientKey)
	result := mustDecode(t, r.Payload).(map[string]any)
	if result["reasoning_effort"] != "high" || result["password"] == "high" {
		t.Fatal("protocol enum or password protection changed")
	}
}
