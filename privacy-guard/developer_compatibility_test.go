package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// A detector must preserve expressions which reference secrets without holding
// the secret value: otherwise the model receives broken source code.
func TestDeveloperEnvironmentReferencesPreserved(t *testing.T) {
	g := maskGateway(t)
	for _, code := range []string{
		`password = os.environ["DB_PASSWORD"]`,
		`password = os.getenv("DB_PASSWORD")`,
		`password := os.Getenv("DB_PASSWORD")`,
		`const password = process.env.DB_PASSWORD;`,
		`const config = {password: process.env.DB_PASSWORD};`,
		`password="${DB_PASSWORD}"`,
		`Authorization: Bearer $TOKEN`,
		`Authorization: Bearer ${TOKEN}`,
	} {
		t.Run(code, func(t *testing.T) {
			payload := map[string]any{"messages": []any{map[string]any{"role": "user", "content": code}}}
			recorder, response := postMask(t, g.Routes(), maskEnvelope(t, testMaskScope, payload), testClientKey)
			if recorder.Code != http.StatusOK {
				t.Fatalf("unexpected status %d", recorder.Code)
			}
			var decoded struct {
				Messages []struct {
					Content string `json:"content"`
				} `json:"messages"`
			}
			if err := json.Unmarshal(response.Payload, &decoded); err != nil {
				t.Fatal(err)
			}
			if len(decoded.Messages) != 1 || decoded.Messages[0].Content != code {
				t.Fatal("non-secret environment reference was rewritten")
			}
		})
	}
}

func TestDeveloperUnknownTokenLiteralInHeaderIsMasked(t *testing.T) {
	g := maskGateway(t)
	literal := "__PG_0123456789abcdef0123456789abcdef__"
	code := "Authorization: Bearer " + literal
	recorder, response := postMask(t, g.Routes(), maskEnvelope(t, testMaskScope, map[string]string{"content": code}), testClientKey)
	if recorder.Code != http.StatusOK || len(response.Mappings) != 1 {
		t.Fatal("literal credential was not masked exactly once")
	}
	var decoded map[string]string
	if err := json.Unmarshal(response.Payload, &decoded); err != nil {
		t.Fatal(err)
	}
	m := response.Mappings[0]
	if m.Original != literal || strings.Contains(decoded["content"], literal) {
		t.Fatal("unknown token-shaped credential bypassed masking")
	}
	if strings.ReplaceAll(decoded["content"], m.Token, m.Original) != code {
		t.Fatal("one-pass header restoration changed the original")
	}
}
