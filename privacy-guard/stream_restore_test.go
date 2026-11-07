package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func restoreTestToken(seed int) string {
	const hex = "0123456789abcdef"
	var b strings.Builder
	b.WriteString("__PG_")
	for i := 0; i < 32; i++ {
		b.WriteByte(hex[(seed+i)%len(hex)])
	}
	b.WriteString("__")
	return b.String()
}

func restoreTestJSONString(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func restoreTestEvent(payload any) string {
	encoded, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return "data: " + string(encoded) + "\n\n"
}

func restoreTestMakeChunk(id string, choices ...map[string]any) map[string]any {
	return map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": 1,
		"model":   "test-model",
		"choices": choices,
	}
}

func restoreTestMakeChoice(index int, delta map[string]any, finish any) map[string]any {
	return map[string]any{
		"index":         index,
		"delta":         delta,
		"finish_reason": finish,
	}
}

func restoreTestParseData(t *testing.T, output string) []string {
	t.Helper()
	var events []string
	for _, block := range strings.Split(output, "\n\n") {
		if block == "" {
			continue
		}
		var data []string
		for _, line := range strings.Split(block, "\n") {
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			value := strings.TrimPrefix(line, "data:")
			value = strings.TrimPrefix(value, " ")
			data = append(data, value)
		}
		if len(data) > 0 {
			joined := strings.Join(data, "\n")
			if joined == "[DONE]" {
				continue
			}
			events = append(events, joined)
		}
	}
	return events
}

type restoreTestToolCall struct {
	Index    int    `json:"index"`
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string  `json:"name"`
		Arguments *string `json:"arguments"`
	} `json:"function"`
}

type restoreTestDelta struct {
	Role             string                `json:"role"`
	Content          *string               `json:"content"`
	ReasoningContent *string               `json:"reasoning_content"`
	Reasoning        *string               `json:"reasoning"`
	Refusal          *string               `json:"refusal"`
	ToolCalls        []restoreTestToolCall `json:"tool_calls"`
}

type restoreTestChoice struct {
	Index        int              `json:"index"`
	Delta        restoreTestDelta `json:"delta"`
	FinishReason *string          `json:"finish_reason"`
}

type restoreTestChunk struct {
	ID      string              `json:"id"`
	Object  string              `json:"object"`
	Choices []restoreTestChoice `json:"choices"`
	Usage   json.RawMessage     `json:"usage"`
}

func restoreTestDecodeChunk(t *testing.T, payload string) restoreTestChunk {
	t.Helper()
	var chunk restoreTestChunk
	if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
		t.Fatalf("decode chunk %q: %v", payload, err)
	}
	return chunk
}

func restoreTestDeltaText(delta restoreTestDelta, channel string) *string {
	switch channel {
	case "content":
		return delta.Content
	case "reasoning_content":
		return delta.ReasoningContent
	case "reasoning":
		return delta.Reasoning
	case "refusal":
		return delta.Refusal
	default:
		return nil
	}
}

func restoreTestCollectText(t *testing.T, events []string, choiceIndex int, channel string) string {
	t.Helper()
	var out strings.Builder
	for _, payload := range events {
		chunk := restoreTestDecodeChunk(t, payload)
		for _, choice := range chunk.Choices {
			if choice.Index != choiceIndex {
				continue
			}
			if text := restoreTestDeltaText(choice.Delta, channel); text != nil {
				out.WriteString(*text)
			}
		}
	}
	return out.String()
}

func restoreTestCollectArgumentFragments(t *testing.T, events []string) map[int]string {
	t.Helper()
	fragments := make(map[int]string)
	for _, payload := range events {
		chunk := restoreTestDecodeChunk(t, payload)
		for _, choice := range chunk.Choices {
			for _, call := range choice.Delta.ToolCalls {
				if call.Function.Arguments != nil {
					fragments[call.Index] += *call.Function.Arguments
				}
			}
		}
	}
	return fragments
}

func restoreTestDecodeUseNumber(t *testing.T, text string) any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode JSON %q: %v", text, err)
	}
	return value
}

// ---------------------------------------------------------------------------
// Streaming text
// ---------------------------------------------------------------------------

func TestRestoreStreamTextSplitEveryPosition(t *testing.T) {
	token := restoreTestToken(1)
	original := "pa\"ss\\word\n密码😀"
	mappings := map[string]string{token: original}
	want := "A" + original + "B"

	for cut := 0; cut <= len(token); cut++ {
		cut := cut
		t.Run(strings.Repeat("x", cut), func(t *testing.T) {
			first := restoreTestMakeChunk("chatcmpl-1", restoreTestMakeChoice(0, map[string]any{
				"content": "A" + token[:cut],
			}, nil))
			second := restoreTestMakeChunk("chatcmpl-1", restoreTestMakeChoice(0, map[string]any{
				"content": token[cut:] + "B",
			}, "stop"))
			input := restoreTestEvent(first) + restoreTestEvent(second) + "data: [DONE]\n\n"

			var output bytes.Buffer
			if err := RestoreChatResponse(context.Background(), strings.NewReader(input), &output, "text/event-stream; charset=utf-8", mappings); err != nil {
				t.Fatalf("restore: %v", err)
			}
			events := restoreTestParseData(t, output.String())
			if got := restoreTestCollectText(t, events, 0, "content"); got != want {
				t.Fatalf("content = %q, want %q", got, want)
			}

			finishAt := -1
			contentAt := -1
			for index, payload := range events {
				chunk := restoreTestDecodeChunk(t, payload)
				for _, choice := range chunk.Choices {
					if choice.FinishReason != nil && *choice.FinishReason != "" {
						finishAt = index
						if choice.Delta.Content != nil {
							t.Fatalf("finish event still carries content: %q", *choice.Delta.Content)
						}
					}
					if choice.Delta.Content != nil && *choice.Delta.Content != "" {
						contentAt = index
					}
				}
			}
			if finishAt < 0 {
				t.Fatal("missing finish_reason event")
			}
			if contentAt < 0 || contentAt >= finishAt {
				t.Fatalf("suffix content event at %d, finish at %d; want content first", contentAt, finishAt)
			}
		})
	}
}

func TestRestoreStreamTwoChoices(t *testing.T) {
	token0 := restoreTestToken(2)
	token1 := restoreTestToken(3)
	mappings := map[string]string{token0: "first-secret", token1: "second-secret"}
	want0 := "A" + "first-secret" + "B"
	want1 := "X" + "second-secret" + "Y" + "Z"

	event1 := restoreTestMakeChunk("chatcmpl-2",
		restoreTestMakeChoice(0, map[string]any{"content": "A" + token0[:7]}, nil),
		restoreTestMakeChoice(1, map[string]any{"content": "X" + token1[:5]}, nil))
	event2 := restoreTestMakeChunk("chatcmpl-2",
		restoreTestMakeChoice(0, map[string]any{"content": token0[7:] + "B"}, nil),
		restoreTestMakeChoice(1, map[string]any{"content": token1[5:11]}, nil))
	event3 := restoreTestMakeChunk("chatcmpl-2",
		restoreTestMakeChoice(0, map[string]any{}, "stop"),
		restoreTestMakeChoice(1, map[string]any{"content": token1[11:] + "Y"}, nil))
	event4 := restoreTestMakeChunk("chatcmpl-2",
		restoreTestMakeChoice(1, map[string]any{"content": "Z"}, "stop"))
	input := restoreTestEvent(event1) + restoreTestEvent(event2) + restoreTestEvent(event3) + restoreTestEvent(event4) + "data: [DONE]\n\n"

	var output bytes.Buffer
	if err := RestoreChatResponse(context.Background(), strings.NewReader(input), &output, "text/event-stream", mappings); err != nil {
		t.Fatalf("restore: %v", err)
	}
	events := restoreTestParseData(t, output.String())
	if got := restoreTestCollectText(t, events, 0, "content"); got != want0 {
		t.Fatalf("choice 0 = %q, want %q", got, want0)
	}
	if got := restoreTestCollectText(t, events, 1, "content"); got != want1 {
		t.Fatalf("choice 1 = %q, want %q", got, want1)
	}
}

func TestRestoreStreamCommentsAndMultilineData(t *testing.T) {
	token := restoreTestToken(4)
	original := "multi\nline\"value"
	chunk := restoreTestMakeChunk("chatcmpl-3", restoreTestMakeChoice(0, map[string]any{
		"content": "A" + token,
	}, nil))
	encoded, err := json.Marshal(chunk)
	if err != nil {
		t.Fatal(err)
	}
	split := bytes.Index(encoded, []byte(`"choices"`))
	if split < 0 {
		t.Fatal("choices not found")
	}

	input := ": keepalive\n\n" +
		"event: message\nid: 7\nretry: 1000\n" +
		"data: " + string(encoded[:split]) + "\n" +
		"data: " + string(encoded[split:]) + "\n\n" +
		": note inside\n" +
		"data: [DONE]\n\n"

	var output bytes.Buffer
	if err := RestoreChatResponse(context.Background(), strings.NewReader(input), &output, "text/event-stream", map[string]string{token: original}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	text := output.String()
	for _, wanted := range []string{": keepalive", "event: message", "id: 7", "retry: 1000", ": note inside"} {
		if !strings.Contains(text, wanted) {
			t.Fatalf("output lost %q: %q", wanted, text)
		}
	}
	events := restoreTestParseData(t, text)
	if got := restoreTestCollectText(t, events, 0, "content"); got != "A"+original {
		t.Fatalf("content = %q", got)
	}
}

func TestRestoreStreamFinishCarriesUsage(t *testing.T) {
	token := restoreTestToken(30)
	finish := "stop"
	event := restoreTestMakeChunk("chatcmpl-16", restoreTestMakeChoice(0, map[string]any{
		"content": token,
	}, finish))
	event["usage"] = map[string]any{"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}
	input := restoreTestEvent(event) + "data: [DONE]\n\n"

	var output bytes.Buffer
	if err := RestoreChatResponse(context.Background(), strings.NewReader(input), &output, "text/event-stream", map[string]string{token: "secret"}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	events := restoreTestParseData(t, output.String())
	if got := restoreTestCollectText(t, events, 0, "content"); got != "secret" {
		t.Fatalf("content = %q", got)
	}
	usageEvents := 0
	for _, payload := range events {
		chunk := restoreTestDecodeChunk(t, payload)
		if len(chunk.Usage) == 0 {
			continue
		}
		usageEvents++
		var usage map[string]json.Number
		if err := json.Unmarshal(chunk.Usage, &usage); err != nil {
			t.Fatal(err)
		}
		if usage["total_tokens"].String() != "3" {
			t.Fatalf("usage = %s", chunk.Usage)
		}
		if len(chunk.Choices) != 0 {
			// The original finish event keeps its usage, but the flushed text
			// event must not inherit it.
			for _, choice := range chunk.Choices {
				if choice.FinishReason == nil || *choice.FinishReason == "" {
					t.Fatalf("synthetic chunk carries usage: %s", payload)
				}
			}
		}
	}
	if usageEvents == 0 {
		t.Fatal("usage dropped")
	}
}

func TestRestoreStreamUsagePassthrough(t *testing.T) {
	token := restoreTestToken(5)
	finish := "stop"
	contentChunk := restoreTestMakeChunk("chatcmpl-4", restoreTestMakeChoice(0, map[string]any{
		"content": token,
	}, nil))
	finishChunk := restoreTestMakeChunk("chatcmpl-4", restoreTestMakeChoice(0, map[string]any{}, finish))
	usageChunk := map[string]any{
		"id":      "chatcmpl-4",
		"object":  "chat.completion.chunk",
		"created": 1,
		"model":   "test-model",
		"choices": []any{},
		"usage": map[string]any{
			"prompt_tokens":     1,
			"completion_tokens": 2,
			"total_tokens":      3,
		},
	}
	input := restoreTestEvent(contentChunk) + restoreTestEvent(finishChunk) + restoreTestEvent(usageChunk) + "data: [DONE]\n\n"

	var output bytes.Buffer
	if err := RestoreChatResponse(context.Background(), strings.NewReader(input), &output, "text/event-stream", map[string]string{token: "secret"}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	events := restoreTestParseData(t, output.String())
	usageEvents := 0
	for _, payload := range events {
		chunk := restoreTestDecodeChunk(t, payload)
		if len(chunk.Usage) > 0 {
			usageEvents++
			var usage map[string]json.Number
			if err := json.Unmarshal(chunk.Usage, &usage); err != nil {
				t.Fatal(err)
			}
			if usage["total_tokens"].String() != "3" {
				t.Fatalf("usage total_tokens = %s", usage["total_tokens"])
			}
		}
		if len(chunk.Choices) > 0 && len(chunk.Usage) > 0 {
			t.Fatalf("synthetic chunk carries usage: %s", payload)
		}
	}
	if usageEvents != 1 {
		t.Fatalf("usage events = %d, want 1", usageEvents)
	}
}

// ---------------------------------------------------------------------------
// Tool calls
// ---------------------------------------------------------------------------

func TestRestoreStreamInterleavedToolCalls(t *testing.T) {
	tokenA := restoreTestToken(6)
	tokenB := restoreTestToken(7)
	originalA := "pa\"ss\\word\n密码"
	originalB := "second\"secret"

	argsAValue, err := json.Marshal(map[string]any{"city": tokenA, "note": "line\n\"quoted\""})
	if err != nil {
		t.Fatal(err)
	}
	argsBValue, err := json.Marshal(map[string]any{"q": "x" + tokenB + "y"})
	if err != nil {
		t.Fatal(err)
	}
	argsA, argsB := string(argsAValue), string(argsBValue)

	posA := strings.Index(argsA, tokenA)
	posB := strings.Index(argsB, tokenB)
	if posA < 0 || posB < 0 {
		t.Fatal("token not found in arguments")
	}
	cutA1, cutA2 := posA+7, posA+16
	cutB1, cutB2 := posB+9, posB+23

	event1 := restoreTestMakeChunk("chatcmpl-5", restoreTestMakeChoice(0, map[string]any{
		"tool_calls": []any{
			map[string]any{"index": 0, "id": "call_0", "type": "function", "function": map[string]any{"name": "weather", "arguments": argsA[:cutA1]}},
			map[string]any{"index": 1, "id": "call_1", "type": "function", "function": map[string]any{"name": "lookup", "arguments": argsB[:cutB1]}},
		},
	}, nil))
	event2 := restoreTestMakeChunk("chatcmpl-5", restoreTestMakeChoice(0, map[string]any{
		"tool_calls": []any{
			map[string]any{"index": 0, "function": map[string]any{"arguments": argsA[cutA1:cutA2]}},
			map[string]any{"index": 1, "function": map[string]any{"arguments": argsB[cutB1:cutB2]}},
		},
	}, nil))
	event3 := restoreTestMakeChunk("chatcmpl-5", restoreTestMakeChoice(0, map[string]any{
		"tool_calls": []any{
			map[string]any{"index": 0, "function": map[string]any{"arguments": argsA[cutA2:]}},
			map[string]any{"index": 1, "function": map[string]any{"arguments": argsB[cutB2:]}},
		},
	}, "tool_calls"))

	input := restoreTestEvent(event1) + restoreTestEvent(event2) + restoreTestEvent(event3) + "data: [DONE]\n\n"
	var output bytes.Buffer
	if err := RestoreChatResponse(context.Background(), strings.NewReader(input), &output, "text/event-stream", map[string]string{
		tokenA: originalA,
		tokenB: originalB,
	}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	events := restoreTestParseData(t, output.String())
	if len(events) == 0 {
		t.Fatal("no events")
	}

	finishAt := -1
	flushAt := -1
	idCount := map[string]int{}
	nameCount := map[string]int{}
	typeCount := map[string]int{}
	for index, payload := range events {
		chunk := restoreTestDecodeChunk(t, payload)
		for _, choice := range chunk.Choices {
			if choice.FinishReason != nil && *choice.FinishReason != "" {
				finishAt = index
			}
			for _, call := range choice.Delta.ToolCalls {
				if call.ID != "" {
					idCount[call.ID]++
				}
				if call.Function.Name != "" {
					nameCount[call.Function.Name]++
				}
				if call.Type != "" {
					typeCount[call.Type]++
				}
				if call.Function.Arguments != nil {
					if *call.Function.Arguments == "" {
						continue
					}
					var doc any
					if err := json.Unmarshal([]byte(*call.Function.Arguments), &doc); err != nil {
						t.Fatalf("emitted invalid tool arguments %q: %v", *call.Function.Arguments, err)
					}
					if finishAt < 0 {
						flushAt = index
					}
				}
			}
		}
	}
	if finishAt < 0 {
		t.Fatal("missing tool_calls finish")
	}
	if flushAt < 0 || flushAt >= finishAt {
		t.Fatalf("tool arguments at %d, finish at %d; want arguments first", flushAt, finishAt)
	}
	for id, count := range idCount {
		if count != 1 {
			t.Fatalf("id %q emitted %d times", id, count)
		}
	}
	for name, count := range nameCount {
		if count != 1 {
			t.Fatalf("name %q emitted %d times", name, count)
		}
	}
	for typ, count := range typeCount {
		if count != 2 {
			t.Fatalf("type %q emitted %d times, want once per tool", typ, count)
		}
	}

	fragments := restoreTestCollectArgumentFragments(t, events)
	if len(fragments) != 2 {
		t.Fatalf("tool indexes = %v, want 2", fragments)
	}
	docA := restoreTestDecodeUseNumber(t, fragments[0]).(map[string]any)
	if docA["city"] != originalA {
		t.Fatalf("tool 0 city = %#v, want %q", docA["city"], originalA)
	}
	docB := restoreTestDecodeUseNumber(t, fragments[1]).(map[string]any)
	if docB["q"] != "x"+originalB+"y" {
		t.Fatalf("tool 1 q = %#v", docB["q"])
	}
}

func TestRestoreStreamToolStructuralOnFinish(t *testing.T) {
	token := restoreTestToken(28)
	original := "finish-secret"
	args, err := json.Marshal(map[string]any{"secret": token})
	if err != nil {
		t.Fatal(err)
	}
	event := restoreTestMakeChunk("chatcmpl-14", restoreTestMakeChoice(0, map[string]any{
		"content": "A" + token,
		"tool_calls": []any{map[string]any{
			"index":    0,
			"id":       "call_finish",
			"type":     "function",
			"function": map[string]any{"name": "echo", "arguments": string(args)},
		}},
	}, "tool_calls"))
	input := restoreTestEvent(event) + "data: [DONE]\n\n"

	var output bytes.Buffer
	if err := RestoreChatResponse(context.Background(), strings.NewReader(input), &output, "text/event-stream", map[string]string{token: original}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	events := restoreTestParseData(t, output.String())
	if got := restoreTestCollectText(t, events, 0, "content"); got != "A"+original {
		t.Fatalf("content = %q", got)
	}
	finishAt := -1
	structureAt := -1
	argsAt := -1
	idCount := 0
	for index, payload := range events {
		chunk := restoreTestDecodeChunk(t, payload)
		for _, choice := range chunk.Choices {
			if choice.FinishReason != nil && *choice.FinishReason != "" {
				finishAt = index
			}
			for _, call := range choice.Delta.ToolCalls {
				if call.ID == "call_finish" {
					idCount++
					structureAt = index
				}
				if call.Function.Arguments != nil && *call.Function.Arguments != "" {
					argsAt = index
					var argsDoc map[string]any
					if err := json.Unmarshal([]byte(*call.Function.Arguments), &argsDoc); err != nil {
						t.Fatalf("invalid arguments: %v", err)
					}
					if argsDoc["secret"] != original {
						t.Fatalf("arguments secret = %#v", argsDoc["secret"])
					}
				}
			}
		}
	}
	if finishAt < 0 || structureAt < 0 || argsAt < 0 {
		t.Fatalf("finish=%d structure=%d args=%d", finishAt, structureAt, argsAt)
	}
	if structureAt >= argsAt || argsAt >= finishAt {
		t.Fatalf("order structure=%d args=%d finish=%d", structureAt, argsAt, finishAt)
	}
	if idCount != 1 {
		t.Fatalf("id emitted %d times", idCount)
	}
}

// A no-argument tool call may be represented by an empty or whitespace-only
// arguments string. Those are the provider's exact bytes: they are not JSON
// documents to parse, and the call must not be dropped.
func TestRestoreStreamNoArgumentToolPreserved(t *testing.T) {
	token := restoreTestToken(31)
	mappings := map[string]string{token: "secret"}
	cases := []struct {
		name string
		args string
	}{
		{name: "empty", args: ""},
		{name: "space", args: " "},
		{name: "newline-tab", args: "\n\t"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			event := restoreTestMakeChunk("chatcmpl-noarg", restoreTestMakeChoice(0, map[string]any{
				"tool_calls": []any{map[string]any{
					"index":    0,
					"id":       "call_noarg",
					"type":     "function",
					"function": map[string]any{"name": "noop", "arguments": tc.args},
				}},
			}, "tool_calls"))
			input := restoreTestEvent(event) + "data: [DONE]\n\n"

			var output bytes.Buffer
			if err := RestoreChatResponse(context.Background(), strings.NewReader(input), &output, "text/event-stream", mappings); err != nil {
				t.Fatalf("restore: %v", err)
			}
			events := restoreTestParseData(t, output.String())
			found := false
			for _, payload := range events {
				chunk := restoreTestDecodeChunk(t, payload)
				for _, choice := range chunk.Choices {
					for _, call := range choice.Delta.ToolCalls {
						if call.Function.Arguments == nil {
							continue
						}
						found = true
						if *call.Function.Arguments != tc.args {
							t.Fatalf("arguments = %q, want exact provider bytes %q", *call.Function.Arguments, tc.args)
						}
					}
				}
			}
			if !found {
				t.Fatal("no-argument tool call was dropped")
			}
		})
	}

	t.Run("malformed nonempty still fails", func(t *testing.T) {
		event := restoreTestMakeChunk("chatcmpl-badargs", restoreTestMakeChoice(0, map[string]any{
			"tool_calls": []any{map[string]any{
				"index":    0,
				"id":       "call_bad",
				"type":     "function",
				"function": map[string]any{"name": "noop", "arguments": `{"a":`},
			}},
		}, "tool_calls"))
		input := restoreTestEvent(event) + "data: [DONE]\n\n"
		var output bytes.Buffer
		if err := RestoreChatResponse(context.Background(), strings.NewReader(input), &output, "text/event-stream", mappings); err == nil {
			t.Fatal("malformed non-empty arguments must still fail")
		}
	})
}

func TestRestoreStreamFlushBeforeDone(t *testing.T) {
	token := restoreTestToken(29)
	original := "done-secret"
	event1 := restoreTestMakeChunk("chatcmpl-15", restoreTestMakeChoice(0, map[string]any{
		"content": "A" + token[:13],
	}, nil))
	event2 := restoreTestMakeChunk("chatcmpl-15", restoreTestMakeChoice(0, map[string]any{
		"content": token[13:] + "B",
	}, nil))
	input := restoreTestEvent(event1) + restoreTestEvent(event2) + "data: [DONE]\n\n"

	var output bytes.Buffer
	if err := RestoreChatResponse(context.Background(), strings.NewReader(input), &output, "text/event-stream", map[string]string{token: original}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	events := restoreTestParseData(t, output.String())
	if got := restoreTestCollectText(t, events, 0, "content"); got != "A"+original+"B" {
		t.Fatalf("content = %q", got)
	}
	doneAt := strings.LastIndex(output.String(), "data: [DONE]")
	contentAt := strings.LastIndex(output.String(), `"content"`)
	if doneAt < 0 || contentAt < 0 || contentAt >= doneAt {
		t.Fatalf("content at %d, DONE at %d; want content first", contentAt, doneAt)
	}
}

// ---------------------------------------------------------------------------
// Typed mappings
// ---------------------------------------------------------------------------

func TestRestoreTypedMappingNumbersNonStream(t *testing.T) {
	numberToken := restoreTestToken(8)
	plainNumberToken := restoreTestToken(9)
	badNumberToken := restoreTestToken(10)
	stringToken := restoreTestToken(11)
	expToken := restoreTestToken(12)

	argsDoc, err := json.Marshal(map[string]any{
		"port":     numberToken,
		"plain":    plainNumberToken,
		"bad":      badNumberToken,
		"id":       stringToken,
		"exp":      expToken,
		"embedded": "x" + numberToken + "y",
		"nested":   []any{numberToken, map[string]any{"n": numberToken}},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"id":                 "chatcmpl-6",
		"object":             "chat.completion",
		"created":            1,
		"model":              "test-model",
		"system_fingerprint": "fp_test",
		"choices": []any{map[string]any{
			"index": 0,
			"message": map[string]any{
				"role":              "assistant",
				"content":           "port=" + numberToken,
				"reasoning_content": numberToken,
				"tool_calls": []any{map[string]any{
					"id":   "call_0",
					"type": "function",
					"function": map[string]any{
						"name":      "configure",
						"arguments": string(argsDoc),
					},
				}},
			},
			"finish_reason": "tool_calls",
		}},
		"usage": map[string]any{"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
	}
	encodedBody, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	mappings := map[string]RestoreMapping{
		numberToken:      {Original: "123", OriginalType: "number"},
		plainNumberToken: {Original: "456"},
		badNumberToken:   {Original: "01", OriginalType: "number"},
		stringToken:      {Original: "0045", OriginalType: "string"},
		expToken:         {Original: "-1.5e2", OriginalType: "number"},
	}

	var output bytes.Buffer
	if err := RestoreChatResponseTyped(context.Background(), bytes.NewReader(encodedBody), &output, "application/json", mappings); err != nil {
		t.Fatalf("restore: %v", err)
	}
	decoded := restoreTestDecodeUseNumber(t, output.String()).(map[string]any)
	choice := decoded["choices"].([]any)[0].(map[string]any)
	message := choice["message"].(map[string]any)

	if message["content"] != "port=123" {
		t.Fatalf("content = %#v", message["content"])
	}
	if message["reasoning_content"] != "123" {
		t.Fatalf("reasoning = %#v", message["reasoning_content"])
	}
	call := message["tool_calls"].([]any)[0].(map[string]any)
	argsText := call["function"].(map[string]any)["arguments"].(string)
	args := restoreTestDecodeUseNumber(t, argsText).(map[string]any)

	assertNumber := func(key, want string) {
		t.Helper()
		number, ok := args[key].(json.Number)
		if !ok || number.String() != want {
			t.Fatalf("args[%q] = %#v, want number %s", key, args[key], want)
		}
	}
	assertNumber("port", "123")
	if args["plain"] != "456" {
		t.Fatalf("untyped mapping = %#v, want string", args["plain"])
	}
	assertNumber("exp", "-1.5e2")
	if args["bad"] != "01" {
		t.Fatalf("invalid number original = %#v, want string", args["bad"])
	}
	if args["id"] != "0045" {
		t.Fatalf("id = %#v, want string", args["id"])
	}
	if args["embedded"] != "x123y" {
		t.Fatalf("embedded = %#v", args["embedded"])
	}
	nested := args["nested"].([]any)
	if nested[0].(json.Number).String() != "123" {
		t.Fatalf("nested[0] = %#v", nested[0])
	}
	if nested[1].(map[string]any)["n"].(json.Number).String() != "123" {
		t.Fatalf("nested[1].n = %#v", nested[1])
	}
	usage := decoded["usage"].(map[string]any)
	if usage["total_tokens"].(json.Number).String() != "3" {
		t.Fatalf("usage = %#v", usage)
	}
}

func TestRestoreTypedMappingNumbersStream(t *testing.T) {
	numberToken := restoreTestToken(13)
	stringToken := restoreTestToken(14)
	argsDoc, err := json.Marshal(map[string]any{
		"port": numberToken,
		"name": stringToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	argsText := string(argsDoc)
	pos := strings.Index(argsText, numberToken)
	if pos < 0 {
		t.Fatal("token not found")
	}
	cut := pos + 11
	event1 := restoreTestMakeChunk("chatcmpl-7", restoreTestMakeChoice(0, map[string]any{
		"tool_calls": []any{map[string]any{
			"index":    0,
			"id":       "call_0",
			"type":     "function",
			"function": map[string]any{"name": "configure", "arguments": argsText[:cut]},
		}},
	}, nil))
	event2 := restoreTestMakeChunk("chatcmpl-7", restoreTestMakeChoice(0, map[string]any{
		"tool_calls": []any{map[string]any{
			"index":    0,
			"function": map[string]any{"arguments": argsText[cut:]},
		}},
	}, "tool_calls"))
	input := restoreTestEvent(event1) + restoreTestEvent(event2) + "data: [DONE]\n\n"
	mappings := map[string]RestoreMapping{
		numberToken: {Original: "8080", OriginalType: "number"},
		stringToken: {Original: "8080", OriginalType: "string"},
	}

	var output bytes.Buffer
	if err := RestoreChatResponseTyped(context.Background(), strings.NewReader(input), &output, "text/event-stream", mappings); err != nil {
		t.Fatalf("restore: %v", err)
	}
	events := restoreTestParseData(t, output.String())
	fragments := restoreTestCollectArgumentFragments(t, events)
	args := restoreTestDecodeUseNumber(t, fragments[0]).(map[string]any)
	number, ok := args["port"].(json.Number)
	if !ok || number.String() != "8080" {
		t.Fatalf("port = %#v", args["port"])
	}
	if args["name"] != "8080" {
		t.Fatalf("name = %#v", args["name"])
	}
}

// TestRestoreOneShotSubstitution makes sure a restored original that itself
// looks like a placeholder is never expanded a second time.
func TestRestoreOneShotSubstitution(t *testing.T) {
	outer := restoreTestToken(15)
	inner := restoreTestToken(16)
	original := "left " + inner + " right"
	mappings := map[string]RestoreMapping{
		outer: {Original: original},
		inner: {Original: "MUST-NOT-APPEAR"},
	}
	toolArgs, err := json.Marshal(map[string]any{"value": outer})
	if err != nil {
		t.Fatal(err)
	}
	argsText := string(toolArgs)
	pos := strings.Index(argsText, outer)
	if pos < 0 {
		t.Fatal("token not found")
	}
	cut := pos + 13

	event1 := restoreTestMakeChunk("chatcmpl-8", restoreTestMakeChoice(0, map[string]any{
		"content": "A" + outer[:cut],
		"tool_calls": []any{map[string]any{
			"index":    0,
			"id":       "call_0",
			"type":     "function",
			"function": map[string]any{"name": "echo", "arguments": argsText[:strings.Index(argsText, outer)+7]},
		}},
	}, nil))
	event2 := restoreTestMakeChunk("chatcmpl-8", restoreTestMakeChoice(0, map[string]any{
		"content": outer[cut:] + "B",
		"tool_calls": []any{map[string]any{
			"index":    0,
			"function": map[string]any{"arguments": argsText[strings.Index(argsText, outer)+7:]},
		}},
	}, "tool_calls"))
	input := restoreTestEvent(event1) + restoreTestEvent(event2) + "data: [DONE]\n\n"

	var output bytes.Buffer
	if err := RestoreChatResponseTyped(context.Background(), strings.NewReader(input), &output, "text/event-stream", mappings); err != nil {
		t.Fatalf("restore: %v", err)
	}
	events := restoreTestParseData(t, output.String())
	content := restoreTestCollectText(t, events, 0, "content")
	if content != "A"+original+"B" {
		t.Fatalf("content = %q", content)
	}
	if strings.Contains(output.String(), "MUST-NOT-APPEAR") {
		t.Fatalf("restored original was rescanned: %q", output.String())
	}
	fragments := restoreTestCollectArgumentFragments(t, events)
	args := restoreTestDecodeUseNumber(t, fragments[0]).(map[string]any)
	if args["value"] != original {
		t.Fatalf("tool value = %#v, want literal original", args["value"])
	}
}

// ---------------------------------------------------------------------------
// Unknown / malformed input
// ---------------------------------------------------------------------------

func TestRestoreUnknownContentTokenUnchanged(t *testing.T) {
	known := restoreTestToken(17)
	unknown := restoreTestToken(18)
	event := restoreTestMakeChunk("chatcmpl-9", restoreTestMakeChoice(0, map[string]any{
		"content": "A" + unknown + "B",
	}, "stop"))
	input := restoreTestEvent(event) + "data: [DONE]\n\n"

	var output bytes.Buffer
	if err := RestoreChatResponse(context.Background(), strings.NewReader(input), &output, "text/event-stream", map[string]string{known: "secret"}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	events := restoreTestParseData(t, output.String())
	if got := restoreTestCollectText(t, events, 0, "content"); got != "A"+unknown+"B" {
		t.Fatalf("content = %q", got)
	}
}

func TestRestoreUnknownToolTokenIsError(t *testing.T) {
	known := restoreTestToken(19)
	unknown := restoreTestToken(20)
	args, err := json.Marshal(map[string]any{"secret": unknown})
	if err != nil {
		t.Fatal(err)
	}

	streamEvent := restoreTestMakeChunk("chatcmpl-10", restoreTestMakeChoice(0, map[string]any{
		"tool_calls": []any{map[string]any{
			"index":    0,
			"id":       "call_0",
			"type":     "function",
			"function": map[string]any{"name": "echo", "arguments": string(args)},
		}},
	}, "tool_calls"))
	streamInput := restoreTestEvent(streamEvent) + "data: [DONE]\n\n"

	var streamOutput bytes.Buffer
	err = RestoreChatResponse(context.Background(), strings.NewReader(streamInput), &streamOutput, "text/event-stream", map[string]string{known: "secret"})
	if err == nil {
		t.Fatal("stream unknown tool token: want error")
	}
	if strings.Contains(err.Error(), unknown) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("error leaks data: %v", err)
	}
	if strings.Contains(streamOutput.String(), `"arguments"`) && strings.Contains(streamOutput.String(), unknown) {
		t.Fatalf("unresolved token emitted as arguments: %q", streamOutput.String())
	}

	body := map[string]any{
		"choices": []any{map[string]any{
			"index": 0,
			"message": map[string]any{
				"role": "assistant",
				"tool_calls": []any{map[string]any{
					"id":   "call_0",
					"type": "function",
					"function": map[string]any{
						"name":      "echo",
						"arguments": string(args),
					},
				}},
			},
		}},
	}
	encodedBody, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var jsonOutput bytes.Buffer
	err = RestoreChatResponse(context.Background(), bytes.NewReader(encodedBody), &jsonOutput, "application/json", map[string]string{known: "secret"})
	if err == nil {
		t.Fatal("JSON unknown tool token: want error")
	}
	if jsonOutput.Len() != 0 {
		t.Fatalf("JSON error wrote output: %q", jsonOutput.String())
	}
}

func TestRestoreMalformedInput(t *testing.T) {
	malformedArgs := restoreTestMakeChunk("chatcmpl-mal", restoreTestMakeChoice(0, map[string]any{
		"tool_calls": []any{map[string]any{
			"index":    0,
			"id":       "call_0",
			"type":     "function",
			"function": map[string]any{"name": "echo", "arguments": `{"a":`},
		}},
	}, "tool_calls"))

	cases := []struct {
		name        string
		contentType string
		input       string
	}{
		{
			name:        "malformed SSE JSON",
			contentType: "text/event-stream",
			input:       "data: {\"choices\":[\n\n",
		},
		{
			name:        "malformed stream tool arguments",
			contentType: "text/event-stream",
			input:       restoreTestEvent(malformedArgs) + "data: [DONE]\n\n",
		},
		{
			name:        "malformed non-stream tool arguments",
			contentType: "application/json",
			input:       `{"choices":[{"index":0,"message":{"tool_calls":[{"id":"call_0","type":"function","function":{"name":"echo","arguments":"{\"a\":"}}]}}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			err := RestoreChatResponse(context.Background(), strings.NewReader(tc.input), &output, tc.contentType, map[string]string{restoreTestToken(21): "secret"})
			if err == nil {
				t.Fatal("want error")
			}
			for _, raw := range []string{"choices", `{"a":`, "call_0"} {
				if strings.Contains(err.Error(), raw) {
					t.Fatalf("error leaks %q: %v", raw, err)
				}
			}
		})
	}
}

func TestRestoreCaps(t *testing.T) {
	mappings := map[string]string{restoreTestToken(22): "secret"}

	t.Run("line", func(t *testing.T) {
		input := "data: " + strings.Repeat("x", restoreMaxLineBytes+1) + "\n\n"
		var output bytes.Buffer
		err := RestoreChatResponse(context.Background(), strings.NewReader(input), &output, "text/event-stream", mappings)
		if err == nil || !strings.Contains(err.Error(), "line") {
			t.Fatalf("error = %v, want line cap", err)
		}
	})

	t.Run("event", func(t *testing.T) {
		var input strings.Builder
		input.WriteString("data: start\n")
		for i := 0; i < 1100; i++ {
			input.WriteString("data: ")
			input.WriteString(strings.Repeat("x", 1000))
			input.WriteByte('\n')
		}
		input.WriteByte('\n')
		var output bytes.Buffer
		err := RestoreChatResponse(context.Background(), strings.NewReader(input.String()), &output, "text/event-stream", mappings)
		if err == nil || !strings.Contains(err.Error(), "event") {
			t.Fatalf("error = %v, want event cap", err)
		}
	})

	t.Run("response", func(t *testing.T) {
		pad := strings.Repeat("x", 500_000)
		event := restoreTestEvent(map[string]any{
			"id":      "chatcmpl-11",
			"choices": []any{},
			"pad":     pad,
		})
		var input strings.Builder
		for input.Len() <= restoreMaxResponseBytes {
			input.WriteString(event)
		}
		var output io.Writer = io.Discard
		err := RestoreChatResponse(context.Background(), strings.NewReader(input.String()), output, "text/event-stream", mappings)
		if err == nil || !strings.Contains(err.Error(), "size limit") {
			t.Fatalf("error = %v, want response cap", err)
		}
	})

	t.Run("tool arguments", func(t *testing.T) {
		fragment := strings.Repeat("x", 200_000)
		var input strings.Builder
		for i := 0; i < 7; i++ {
			call := map[string]any{
				"index": 0,
				"function": map[string]any{
					"arguments": fragment,
				},
			}
			if i == 0 {
				call["id"] = "call_0"
				call["type"] = "function"
				call["function"] = map[string]any{"name": "echo", "arguments": fragment}
			}
			event := restoreTestMakeChunk("chatcmpl-12", restoreTestMakeChoice(0, map[string]any{
				"tool_calls": []any{call},
			}, nil))
			input.WriteString(restoreTestEvent(event))
		}
		input.WriteString("data: [DONE]\n\n")
		var output bytes.Buffer
		err := RestoreChatResponse(context.Background(), strings.NewReader(input.String()), &output, "text/event-stream", mappings)
		if err == nil || !strings.Contains(err.Error(), "tool arguments") {
			t.Fatalf("error = %v, want tool argument cap", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Non-streaming JSON
// ---------------------------------------------------------------------------

func TestRestoreNonStreamObject(t *testing.T) {
	contentToken := restoreTestToken(23)
	reasoningToken := restoreTestToken(24)
	toolToken := restoreTestToken(25)
	contentOriginal := "before \"quoted\" \\ line\n密码😀"
	contentPrefix := "prefix:"
	wantContent := contentPrefix + contentOriginal
	reasoningOriginal := "reasoning 秘密"
	toolOriginal := "pa\"ss\\word\n密码"

	args, err := json.Marshal(map[string]any{
		"secret": toolToken,
		"note":   "line\n\"quote\"",
		"nested": []any{map[string]any{"v": toolToken}},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"id":                 "chatcmpl-13",
		"object":             "chat.completion",
		"created":            1,
		"model":              "test-model",
		"system_fingerprint": "fp_test",
		"choices": []any{map[string]any{
			"index": 0,
			"message": map[string]any{
				"role":              "assistant",
				"content":           contentPrefix + contentToken,
				"reasoning_content": reasoningToken,
				"tool_calls": []any{map[string]any{
					"id":   "call_0",
					"type": "function",
					"function": map[string]any{
						"name":      "echo",
						"arguments": string(args),
					},
				}},
			},
			"finish_reason": "tool_calls",
		}},
		"usage": map[string]any{"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
	}
	encodedBody, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	mappings := map[string]string{
		contentToken:   contentOriginal,
		reasoningToken: reasoningOriginal,
		toolToken:      toolOriginal,
	}

	var output bytes.Buffer
	if err := RestoreChatResponse(context.Background(), bytes.NewReader(encodedBody), &output, "application/json", mappings); err != nil {
		t.Fatalf("restore: %v", err)
	}
	decoded := restoreTestDecodeUseNumber(t, output.String()).(map[string]any)
	if decoded["system_fingerprint"] != "fp_test" {
		t.Fatalf("unknown field lost: %#v", decoded["system_fingerprint"])
	}
	usage := decoded["usage"].(map[string]any)
	if usage["total_tokens"].(json.Number).String() != "3" {
		t.Fatalf("usage lost: %#v", usage)
	}
	choice := decoded["choices"].([]any)[0].(map[string]any)
	message := choice["message"].(map[string]any)
	if message["content"] != wantContent {
		t.Fatalf("content = %#v, want %#v", message["content"], wantContent)
	}
	if message["reasoning_content"] != reasoningOriginal {
		t.Fatalf("reasoning = %#v", message["reasoning_content"])
	}
	call := message["tool_calls"].([]any)[0].(map[string]any)
	if call["id"] != "call_0" {
		t.Fatalf("tool id = %#v", call["id"])
	}
	if call["function"].(map[string]any)["name"] != "echo" {
		t.Fatalf("tool name = %#v", call["function"])
	}
	argsText := call["function"].(map[string]any)["arguments"].(string)
	restoredArgs := restoreTestDecodeUseNumber(t, argsText).(map[string]any)
	if restoredArgs["secret"] != toolOriginal {
		t.Fatalf("tool secret = %#v", restoredArgs["secret"])
	}
	nested := restoredArgs["nested"].([]any)[0].(map[string]any)
	if nested["v"] != toolOriginal {
		t.Fatalf("nested secret = %#v", nested["v"])
	}
}

func TestRestoreNonStreamUnchangedWithMappings(t *testing.T) {
	input := "{\n  \"id\": \"x\",\n  \"choices\": [{\"index\": 0, \"message\": {\"content\": \"no token\"}}]\n}\n"
	var output bytes.Buffer
	if err := RestoreChatResponse(context.Background(), strings.NewReader(input), &output, "application/json", map[string]string{restoreTestToken(26): "secret"}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if output.String() != input {
		t.Fatalf("unchanged JSON was rewritten:\n got %q\nwant %q", output.String(), input)
	}
}

// ---------------------------------------------------------------------------
// Pass-through and cancellation
// ---------------------------------------------------------------------------

func TestRestorePassThroughNoMappings(t *testing.T) {
	sse := ": comment\n\nevent: message\nid: 1\ndata: {\"choices\":[]}\n\ndata: [DONE]\n\n: after done\n"
	jsonBody := "{\n  \"choices\": [\n    {\"index\": 0, \"message\": {\"content\": \"unchanged\"}}\n  ]\n}\n"

	cases := []struct {
		name        string
		contentType string
		input       string
	}{
		{name: "SSE", contentType: "text/event-stream", input: sse},
		{name: "JSON", contentType: "application/json", input: jsonBody},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := RestoreChatResponse(context.Background(), strings.NewReader(tc.input), &output, tc.contentType, nil); err != nil {
				t.Fatalf("restore: %v", err)
			}
			if output.String() != tc.input {
				t.Fatalf("pass-through changed bytes:\n got %q\nwant %q", output.String(), tc.input)
			}

			output.Reset()
			if err := RestoreChatResponseTyped(context.Background(), strings.NewReader(tc.input), &output, tc.contentType, map[string]RestoreMapping{}); err != nil {
				t.Fatalf("typed restore: %v", err)
			}
			if output.String() != tc.input {
				t.Fatalf("typed pass-through changed bytes")
			}
		})
	}
}

func TestRestoreCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var output bytes.Buffer
	err := RestoreChatResponse(ctx, strings.NewReader("data: [DONE]\n\n"), &output, "text/event-stream", map[string]string{restoreTestToken(27): "secret"})
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if output.Len() != 0 {
		t.Fatalf("cancelled call wrote output: %q", output.String())
	}
}
