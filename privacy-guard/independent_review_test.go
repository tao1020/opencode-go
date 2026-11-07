package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// Independent transport review: explicit short passwords in normal text must
// not disappear from the request-wide discovery set and escape the proxy.
func TestIndependentShortPasswordInText(t *testing.T) {
	detector, err := buildRedactor()
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"abc", "xy", "7"} {
		t.Run(secret, func(t *testing.T) {
			content := "database password=\"" + secret + "\""
			body, err := json.Marshal(map[string]any{"model": "test", "messages": []any{map[string]any{"role": "user", "content": content}}})
			if err != nil {
				t.Fatal(err)
			}
			out, _, err := sanitize(context.Background(), detector, body)
			if err != nil {
				return
			} // rejecting unsafe input is an acceptable outcome
			var decoded struct {
				Messages []struct {
					Content string `json:"content"`
				} `json:"messages"`
			}
			if err := json.Unmarshal(out, &decoded); err != nil {
				t.Fatal(err)
			}
			if len(decoded.Messages) != 1 {
				t.Fatal("message shape changed")
			}
			if strings.Contains(decoded.Messages[0].Content, "\""+secret+"\"") {
				t.Fatal("explicit short password forwarded unchanged")
			}
		})
	}
}
