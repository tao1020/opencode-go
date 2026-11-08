package main

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

func TestBareCredentialRule(t *testing.T) {
	for _, v := range []string{"a8Km2zQ7vN4pR9xL6cW3", "vN4pR9xL6cW3_a8Km2zQ7"} {
		if !looksLikeBareCredential(v) {
			t.Fatalf("missed synthetic credential %q", v)
		}
	}
	for _, v := range []string{"configuration", "get_user_configuration", "GetCustomerAccountByID2026", strings.Repeat("aA1", 12), strings.Repeat("abcdef0123456789", 4), "__PG_0123456789abcdef0123456789abcdef__"} {
		if looksLikeBareCredential(v) {
			t.Fatalf("ordinary value masked %q", v)
		}
	}
}

func TestBareCredentialMessageScopeAndRoundTrip(t *testing.T) {
	g, err := NewGateway(Config{ClientAPIKey: testClientKey, Detector: "credentials"})
	if err != nil {
		t.Fatal(err)
	}
	secret := "a8Km2zQ7vN4pR9xL6cW3"
	payload := map[string]any{"messages": []any{map[string]any{"role": "tool", "content": "result\n" + secret + "\n"}}, "tools": []any{map[string]any{"type": "function", "function": map[string]any{"name": "GetCustomerAccountByID2026"}}}}
	_, res := postMask(t, g.Routes(), maskEnvelope(t, testMaskScope, payload), testClientKey)
	if len(res.Mappings) != 1 || res.Mappings[0].Original != secret {
		t.Fatal("bare credential not mapped")
	}
	if strings.Contains(string(res.Payload), secret) {
		t.Fatal("bare credential leaked")
	}
	if restoreTree(mustDecode(t, res.Payload), res.Mappings).(map[string]any)["messages"].([]any)[0].(map[string]any)["content"] != "result\n"+secret+"\n" {
		t.Fatal("round trip failed")
	}
	_, res = postMask(t, g.Routes(), maskEnvelope(t, testMaskScope, map[string]any{"tools": []any{map[string]any{"type": "function", "function": map[string]any{"name": secret}}}}), testClientKey)
	if len(res.Mappings) != 0 {
		t.Fatal("tool name treated as bare credential")
	}
}

func TestBareCredentialLabeledCorpus(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	alphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
	detected := 0
	for i := 0; i < 500; i++ {
		raw := make([]byte, 32)
		for j := range raw {
			raw[j] = alphabet[r.Intn(len(alphabet))]
		}
		if looksLikeBareCredential(string(raw)) {
			detected++
		}
	}
	falsePositives := 0
	for i := 0; i < 1000; i++ {
		v := fmt.Sprintf("GetCustomerConfigurationByAccountID%04d", i)
		if looksLikeBareCredential(v) {
			falsePositives++
		}
	}
	t.Logf("synthetic random credentials detected %d/500; generated ordinary identifiers flagged %d/1000", detected, falsePositives)
	if falsePositives > 0 || detected < 475 {
		t.Fatal("bounded fixture regression")
	}
}

func TestBareCredentialCancellation(t *testing.T) {
	g, err := NewGateway(Config{ClientAPIKey: testClientKey, Detector: "credentials"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := g.maskPayload(ctx, []byte(maskEnvelope(t, testMaskScope, map[string]any{"messages": []any{map[string]any{"content": "a8Km2zQ7vN4pR9xL6cW3"}}}))); err == nil {
		t.Fatal("cancelled request accepted")
	}
}
