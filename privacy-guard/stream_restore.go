package main

// Local restoration of OpenAI Chat Completions responses that were produced
// from a masked request.
//
// The masker replaces a secret with a token of the form __PG_<32 hex>__ and
// gives the caller a per-request token→original map. Masking happens before the
// request leaves the machine. This file consumes that map only after the
// response has come back, and only in the caller's process: no mapping, token,
// or original is ever written to a request or sent anywhere. The map must stay
// local to the request (never a package variable, never persisted globally).
//
// Only the Chat Completions shape is supported: streamed/delta `content`,
// `reasoning_content`, `reasoning`, `refusal`, and tool-call `arguments`; and
// the non-streaming `message` equivalents (`tool_calls`; legacy `function_call`
// is left untouched because current clients use `tool_calls`). Responses and
// Anthropic shapes are out of scope.
//
// This layer protects the model-provider request. It does not sandbox tools:
// a restored secret can still be printed by `gh`, `curl`, or any other tool the
// caller runs. That boundary is intentional and outside this function.
//
// # Errors
//
// Errors never include response bytes, tokens, originals, or upstream text.
// They are intentionally generic; callers may log the returned error but should
// not expose it verbatim to an untrusted client.
//
// # Cancellation
//
// The context is checked before each read, line, event, and choice. It cannot
// interrupt a Read that is already blocked inside an arbitrary io.Reader. The
// caller owns the reader and must close/cancel the underlying connection (for
// example by cancelling the HTTP request) to unblock it.
//
// # Limits
//
// A single SSE line and a single SSE event are each capped at 1 MiB; one
// response is capped at 32 MiB; one tool-call argument accumulation is capped
// at 1 MiB. Exceeding a cap returns an error before the oversized data is
// parsed.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

const (
	restoreMaxLineBytes      = 1 << 20
	restoreMaxEventBytes     = 1 << 20
	restoreMaxResponseBytes  = 32 << 20
	restoreMaxToolArgBytes   = 1 << 20
	restoreMaxChoices        = 1024
	restoreMaxToolsPerChoice = 256
	restoreMaxToolDepth      = 128

	restoreTokenPrefix   = "__PG_"
	restoreTokenHexChars = 32
)

// restoreTextChannels returns the Chat delta/message text fields that may
// contain a masked token. `reasoning_content` is DeepSeek's field; `reasoning`
// and `refusal` are accepted variants seen on other OpenAI-compatible servers.
// Returning a literal keeps the restorer free of package-level mutable state.
func restoreTextChannels() [4]string {
	return [4]string{"content", "reasoning_content", "reasoning", "refusal"}
}

// RestoreMapping describes one request-local token replacement.
//
// OriginalType is optional. An empty value or "string" restores Original as a
// string in every supported field. "number" additionally restores an exact
// whole-string token inside tool-call arguments as a JSON number, but only when
// Original is a valid JSON number. Text channels always restore Original as a
// string, and a token embedded in a larger string is never converted.
//
// Replacement is deliberately one-shot: a token inside Original is written
// literally and never rescanned, so a secret that happens to look like a
// placeholder cannot be expanded again.
type RestoreMapping struct {
	Original     string `json:"original"`
	OriginalType string `json:"originalType,omitempty"`
}

// RestoreChatResponse restores locally-masked tokens in one OpenAI Chat
// Completions response. It is the string-only convenience wrapper around
// RestoreChatResponseTyped.
//
// `contentType` selects the framing: `text/event-stream` is parsed as SSE,
// anything else is treated as one non-streaming JSON object. When `mappings` is
// empty the response is copied through byte for byte under the same size cap,
// because there is nothing to restore.
//
// `mappings` maps a complete token (__PG_<32 hex>__) to its original string. It
// is read-only and request-local. The caller must not mutate it while this
// function runs, and must never send it upstream.
//
// Streaming text tokens that are split across SSE events are restored with a
// tiny per-choice/per-channel suffix buffer that holds only an incomplete
// prefix or token. Tool-call arguments are accumulated per (choice, tool index)
// and are restored only once, after the full arguments JSON is available at
// finish_reason or end of stream. This avoids restoring half a JSON document
// into something a client might execute. An unknown complete token in tool
// arguments is an error; ordinary content keeps unknown tokens unchanged.
//
// The function returns nil after a complete SSE stream (including [DONE]) or a
// fully written non-streaming response. It returns a generic error on malformed
// framing/JSON, invalid or unmapped tool arguments, a size cap, cancellation,
// or a write failure.
func RestoreChatResponse(ctx context.Context, reader io.Reader, writer io.Writer, contentType string, mappings map[string]string) error {
	typed := make(map[string]RestoreMapping, len(mappings))
	for token, original := range mappings {
		typed[token] = RestoreMapping{Original: original}
	}
	return RestoreChatResponseTyped(ctx, reader, writer, contentType, typed)
}

// RestoreChatResponseTyped is RestoreChatResponse with optional value types.
// Use OriginalType "number" when a masked value was a JSON number (for example
// a port or an ID) so a tool argument that consists of exactly that token is
// restored as a JSON number instead of a quoted string. Text is always restored
// as text, and numbers are never coerced when the token is part of a larger
// string.
func RestoreChatResponseTyped(ctx context.Context, reader io.Reader, writer io.Writer, contentType string, mappings map[string]RestoreMapping) error {
	if ctx == nil {
		return restoreError("nil context")
	}
	if reader == nil || writer == nil {
		return restoreError("nil stream")
	}
	if err := ctx.Err(); err != nil {
		return restoreCancelled(err)
	}
	flusher, _ := writer.(interface{ Flush() })

	if len(mappings) == 0 {
		return restoreCopyBounded(ctx, writer, reader, flusher)
	}
	if restoreIsEventStream(contentType) {
		return restoreEventStream(ctx, reader, writer, flusher, mappings)
	}
	return restoreJSONResponse(ctx, reader, writer, flusher, mappings)
}

func restoreError(kind string) error {
	return errors.New("stream restore: " + kind)
}

func restoreCancelled(err error) error {
	return fmt.Errorf("stream restore: cancelled: %w", err)
}

func restoreIsEventStream(contentType string) bool {
	base := strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0])
	return strings.EqualFold(base, "text/event-stream")
}

func restoreWriteAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return restoreError("write failed")
		}
		if n <= 0 {
			return restoreError("write failed")
		}
	}
	return nil
}

func restoreFlush(flusher interface{ Flush() }) {
	if flusher != nil {
		flusher.Flush()
	}
}

// restoreCopyBounded is the no-mapping fast path. It is byte-exact and keeps
// the 32 MiB response cap.
func restoreCopyBounded(ctx context.Context, dst io.Writer, src io.Reader, flusher interface{ Flush() }) error {
	buffer := make([]byte, 32*1024)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return restoreCancelled(err)
		}
		n, err := src.Read(buffer)
		if n > 0 {
			total += int64(n)
			if total > restoreMaxResponseBytes {
				return restoreError("response exceeds size limit")
			}
			if writeErr := restoreWriteAll(dst, buffer[:n]); writeErr != nil {
				return writeErr
			}
			restoreFlush(flusher)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return restoreError("read failed")
		}
	}
}

// ---------------------------------------------------------------------------
// SSE framing
// ---------------------------------------------------------------------------

type restoreSSEReader struct {
	br    *bufio.Reader
	total int64
}

func newRestoreSSEReader(r io.Reader) *restoreSSEReader {
	return &restoreSSEReader{br: bufio.NewReaderSize(r, 64*1024)}
}

// readLine returns one line without its terminator. `eof` is true when this is
// the final line (which may have no newline). Lines may end in LF, CRLF, or CR.
func (r *restoreSSEReader) readLine() ([]byte, bool, error) {
	line := make([]byte, 0, 256)
	for {
		b, err := r.br.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return line, true, nil
			}
			return nil, false, restoreError("read failed")
		}
		r.total++
		if r.total > restoreMaxResponseBytes {
			return nil, false, restoreError("response exceeds size limit")
		}
		switch b {
		case '\n':
			return line, false, nil
		case '\r':
			if next, peekErr := r.br.Peek(1); peekErr == nil && next[0] == '\n' {
				if _, readErr := r.br.ReadByte(); readErr != nil {
					return nil, false, restoreError("read failed")
				}
				r.total++
				if r.total > restoreMaxResponseBytes {
					return nil, false, restoreError("response exceeds size limit")
				}
			}
			return line, false, nil
		default:
			if len(line) >= restoreMaxLineBytes {
				return nil, false, restoreError("SSE line exceeds size limit")
			}
			line = append(line, b)
		}
	}
}

type restoreSSEEvent struct {
	fields  []string // non-data lines, including comments, preserved verbatim
	data    []string // data values with the optional single leading space removed
	rawData []string // original data lines, used when nothing changed
	hasData bool
	size    int
}

func (e *restoreSSEEvent) addLine(line []byte) error {
	e.size += len(line) + 1
	if e.size > restoreMaxEventBytes {
		return restoreError("SSE event exceeds size limit")
	}
	raw := string(line)
	field, value, found := strings.Cut(raw, ":")
	if field != "data" {
		e.fields = append(e.fields, raw)
		return nil
	}
	if found && strings.HasPrefix(value, " ") {
		value = value[1:]
	}
	e.data = append(e.data, value)
	e.rawData = append(e.rawData, raw)
	e.hasData = true
	return nil
}

func (e *restoreSSEEvent) empty() bool {
	return len(e.fields) == 0 && !e.hasData
}

func writeRestoreSSEEvent(w io.Writer, flusher interface{ Flush() }, fields, dataLines []string) error {
	var buf bytes.Buffer
	for _, field := range fields {
		buf.WriteString(field)
		buf.WriteByte('\n')
	}
	for _, line := range dataLines {
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	buf.WriteByte('\n')
	if err := restoreWriteAll(w, buf.Bytes()); err != nil {
		return err
	}
	restoreFlush(flusher)
	return nil
}

func restoreNextSSEEvent(ctx context.Context, r *restoreSSEReader) (*restoreSSEEvent, bool, error) {
	event := &restoreSSEEvent{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, restoreCancelled(err)
		}
		line, eof, err := r.readLine()
		if err != nil {
			return nil, false, err
		}
		if len(line) == 0 {
			if !event.empty() {
				return event, eof, nil
			}
			if eof {
				return nil, true, nil
			}
			continue
		}
		if err := event.addLine(line); err != nil {
			return nil, false, err
		}
		if eof {
			return event, true, nil
		}
	}
}

func restoreEventStream(ctx context.Context, reader io.Reader, writer io.Writer, flusher interface{ Flush() }, mappings map[string]RestoreMapping) error {
	stream := newRestoreSSEReader(reader)
	state := newRestoreStreamState(mappings)
	for {
		event, eof, err := restoreNextSSEEvent(ctx, stream)
		if err != nil {
			return err
		}
		if event != nil {
			if err := restoreHandleSSEEvent(ctx, event, state, writer, flusher); err != nil {
				return err
			}
			if state.done {
				return nil
			}
		}
		if eof {
			events, err := state.flushAllEvents()
			if err != nil {
				return err
			}
			for _, payload := range events {
				if err := writeRestoreSSEEvent(writer, flusher, nil, []string{"data: " + string(payload)}); err != nil {
					return err
				}
			}
			return nil
		}
	}
}

func restoreHandleSSEEvent(ctx context.Context, event *restoreSSEEvent, state *restoreStreamState, writer io.Writer, flusher interface{ Flush() }) error {
	if !event.hasData {
		return writeRestoreSSEEvent(writer, flusher, event.fields, nil)
	}

	data := strings.Join(event.data, "\n")
	if data == "[DONE]" {
		events, err := state.flushAllEvents()
		if err != nil {
			return err
		}
		for _, payload := range events {
			if err := writeRestoreSSEEvent(writer, flusher, nil, []string{"data: " + string(payload)}); err != nil {
				return err
			}
		}
		if err := writeRestoreSSEEvent(writer, flusher, event.fields, []string{"data: [DONE]"}); err != nil {
			return err
		}
		state.done = true
		return nil
	}

	pre, restored, changed, err := state.restoreChunk(ctx, []byte(data))
	if err != nil {
		return err
	}
	for _, payload := range pre {
		if err := writeRestoreSSEEvent(writer, flusher, nil, []string{"data: " + string(payload)}); err != nil {
			return err
		}
	}
	if !changed {
		return writeRestoreSSEEvent(writer, flusher, event.fields, event.rawData)
	}
	return writeRestoreSSEEvent(writer, flusher, event.fields, []string{"data: " + string(restored)})
}

// ---------------------------------------------------------------------------
// Streaming state
// ---------------------------------------------------------------------------

type restoreTokenBuffer struct {
	pending string
}

// feed appends text and returns the safe prefix. It holds back only a suffix
// that is an incomplete token prefix or an incomplete token; it never holds the
// full response text.
func (b *restoreTokenBuffer) feed(text string, mappings map[string]RestoreMapping) (ready string, changed bool) {
	hadPending := b.pending != ""
	b.pending += text
	ready, held, _ := restoreTokenText(b.pending, mappings, false, true)
	b.pending = held
	return ready, hadPending || ready != text
}

func (b *restoreTokenBuffer) take() string {
	pending := b.pending
	b.pending = ""
	return pending
}

type restoreToolState struct {
	id, typ, name              string
	idSent, typeSent, nameSent bool

	args    strings.Builder
	sawArgs bool
	emitted bool
}

func (t *restoreToolState) announced() bool {
	return t.idSent || t.typeSent || t.nameSent
}

type restoreChoiceState struct {
	text  map[string]*restoreTokenBuffer
	tools map[int]*restoreToolState
}

func newRestoreChoiceState() *restoreChoiceState {
	return &restoreChoiceState{
		text:  make(map[string]*restoreTokenBuffer),
		tools: make(map[int]*restoreToolState),
	}
}

func (c *restoreChoiceState) buffer(channel string) *restoreTokenBuffer {
	if buffer, ok := c.text[channel]; ok {
		return buffer
	}
	buffer := &restoreTokenBuffer{}
	c.text[channel] = buffer
	return buffer
}

func (c *restoreChoiceState) tool(index int) *restoreToolState {
	if tool, ok := c.tools[index]; ok {
		return tool
	}
	tool := &restoreToolState{}
	c.tools[index] = tool
	return tool
}

type restoreStreamState struct {
	mappings map[string]RestoreMapping
	choices  map[int]*restoreChoiceState
	base     map[string]json.RawMessage
	haveBase bool
	done     bool
}

func newRestoreStreamState(mappings map[string]RestoreMapping) *restoreStreamState {
	return &restoreStreamState{
		mappings: mappings,
		choices:  make(map[int]*restoreChoiceState),
	}
}

func (s *restoreStreamState) choice(index int) *restoreChoiceState {
	if choice, ok := s.choices[index]; ok {
		return choice
	}
	choice := newRestoreChoiceState()
	s.choices[index] = choice
	return choice
}

func restoreIsNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func restoreMarshal(value any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, restoreError("encoding failed")
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// restoreChunk restores one chat.completion.chunk. It returns synthetic events
// that must be written before the original event (text/tool suffix flushes),
// the rewritten event, and whether anything changed.
func (s *restoreStreamState) restoreChunk(ctx context.Context, data []byte) (pre [][]byte, out []byte, changed bool, err error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, false, restoreCancelled(err)
	}

	var top map[string]json.RawMessage
	if unmarshalErr := json.Unmarshal(data, &top); unmarshalErr != nil {
		return nil, nil, false, restoreError("malformed SSE JSON")
	}
	rawChoices, ok := top["choices"]
	if !ok || restoreIsNull(rawChoices) {
		return nil, data, false, nil
	}
	var choices []json.RawMessage
	if unmarshalErr := json.Unmarshal(rawChoices, &choices); unmarshalErr != nil {
		return nil, nil, false, restoreError("malformed SSE JSON")
	}
	if len(choices) == 0 {
		return nil, data, false, nil
	}
	if len(choices) > restoreMaxChoices {
		return nil, nil, false, restoreError("too many choices")
	}

	base := make(map[string]json.RawMessage, len(top))
	for key, value := range top {
		if key == "choices" || key == "usage" {
			continue
		}
		base[key] = value
	}
	s.base = base
	s.haveBase = true

	newChoices := make([]json.RawMessage, 0, len(choices))
	anyChange := false
	for _, rawChoice := range choices {
		if err := ctx.Err(); err != nil {
			return nil, nil, false, restoreCancelled(err)
		}
		var choice map[string]json.RawMessage
		if unmarshalErr := json.Unmarshal(rawChoice, &choice); unmarshalErr != nil {
			return nil, nil, false, restoreError("malformed SSE JSON")
		}
		index, indexErr := restoreChoiceIndex(choice, len(choices))
		if indexErr != nil {
			return nil, nil, false, indexErr
		}
		choiceState := s.choice(index)

		delta := make(map[string]json.RawMessage)
		if rawDelta, ok := choice["delta"]; ok && !restoreIsNull(rawDelta) {
			if unmarshalErr := json.Unmarshal(rawDelta, &delta); unmarshalErr != nil {
				return nil, nil, false, restoreError("malformed SSE JSON")
			}
		}

		choiceChanged := false
		for _, channel := range restoreTextChannels() {
			rawText, ok := delta[channel]
			if !ok {
				continue
			}
			var text *string
			if unmarshalErr := json.Unmarshal(rawText, &text); unmarshalErr != nil {
				return nil, nil, false, restoreError("malformed SSE JSON")
			}
			if text == nil {
				continue
			}
			ready, textChanged := choiceState.buffer(channel).feed(*text, s.mappings)
			if textChanged {
				encoded, encodeErr := json.Marshal(ready)
				if encodeErr != nil {
					return nil, nil, false, restoreError("encoding failed")
				}
				delta[channel] = encoded
				choiceChanged = true
			}
		}

		if rawTools, ok := delta["tool_calls"]; ok && !restoreIsNull(rawTools) {
			calls, toolsChanged, toolsErr := choiceState.consumeToolCalls(rawTools, s.mappings)
			if toolsErr != nil {
				return nil, nil, false, toolsErr
			}
			if toolsChanged {
				if len(calls) > 0 {
					encoded, encodeErr := json.Marshal(calls)
					if encodeErr != nil {
						return nil, nil, false, restoreError("encoding failed")
					}
					delta["tool_calls"] = encoded
				} else {
					delete(delta, "tool_calls")
				}
				choiceChanged = true
			}
		}

		finished, finishErr := restoreChoiceFinished(choice)
		if finishErr != nil {
			return nil, nil, false, finishErr
		}
		if finished {
			// If the finishing event introduces tool id/name/type for the first
			// time, those fields are still sitting in delta and the terminal
			// event will drop tool_calls. Emit the structural delta first so the
			// later arguments flush is not the first time the client sees the
			// call.
			if structural, ok := delta["tool_calls"]; ok && !restoreIsNull(structural) {
				var calls []json.RawMessage
				if unmarshalErr := json.Unmarshal(structural, &calls); unmarshalErr != nil {
					return nil, nil, false, restoreError("malformed tool call delta")
				}
				if len(calls) > 0 {
					event, eventErr := s.syntheticEvent(index, map[string]json.RawMessage{"tool_calls": structural})
					if eventErr != nil {
						return nil, nil, false, eventErr
					}
					pre = append(pre, event)
				}
				delete(delta, "tool_calls")
			}

			// The text that arrived on this same finishing event has already
			// been fed into the buffers. Flush it and the complete tool
			// arguments before the terminal finish_reason event.
			flushes, flushErr := s.flushChoiceEvents(choiceState, index, delta)
			if flushErr != nil {
				return nil, nil, false, flushErr
			}
			pre = append(pre, flushes...)
			for _, channel := range restoreTextChannels() {
				delete(delta, channel)
			}
			delete(delta, "tool_calls")
			choiceChanged = true
		}

		if choiceChanged {
			anyChange = true
			encodedDelta, encodeErr := json.Marshal(delta)
			if encodeErr != nil {
				return nil, nil, false, restoreError("encoding failed")
			}
			choice["delta"] = encodedDelta
			encodedChoice, encodeErr := restoreMarshal(choice)
			if encodeErr != nil {
				return nil, nil, false, encodeErr
			}
			newChoices = append(newChoices, encodedChoice)
			continue
		}
		newChoices = append(newChoices, rawChoice)
	}

	if !anyChange {
		return nil, data, false, nil
	}
	encodedChoices, encodeErr := json.Marshal(newChoices)
	if encodeErr != nil {
		return nil, nil, false, restoreError("encoding failed")
	}
	top["choices"] = encodedChoices
	encoded, encodeErr := restoreMarshal(top)
	if encodeErr != nil {
		return nil, nil, false, encodeErr
	}
	return pre, encoded, true, nil
}

func restoreChoiceIndex(choice map[string]json.RawMessage, total int) (int, error) {
	raw, ok := choice["index"]
	if !ok {
		if total == 1 {
			return 0, nil
		}
		return 0, restoreError("missing choice index")
	}
	var index int
	if err := json.Unmarshal(raw, &index); err != nil || index < 0 || index >= restoreMaxChoices {
		return 0, restoreError("invalid choice index")
	}
	return index, nil
}

func restoreChoiceFinished(choice map[string]json.RawMessage) (bool, error) {
	raw, ok := choice["finish_reason"]
	if !ok || restoreIsNull(raw) {
		return false, nil
	}
	var reason *string
	if err := json.Unmarshal(raw, &reason); err != nil {
		return false, restoreError("malformed SSE JSON")
	}
	return reason != nil && *reason != "", nil
}

func (s *restoreStreamState) flushChoiceEvents(choice *restoreChoiceState, index int, inFlight map[string]json.RawMessage) ([][]byte, error) {
	events := make([][]byte, 0, 2)
	textEvent, ok, err := s.textFlushEvent(choice, index, inFlight)
	if err != nil {
		return nil, err
	}
	if ok {
		events = append(events, textEvent)
	}
	if toolEvent, err := s.toolFlushEvent(choice, index); err != nil {
		return nil, err
	} else if toolEvent != nil {
		events = append(events, toolEvent)
	}
	return events, nil
}

func (s *restoreStreamState) flushAllEvents() ([][]byte, error) {
	if !s.haveBase {
		return nil, nil
	}
	indices := make([]int, 0, len(s.choices))
	for index := range s.choices {
		indices = append(indices, index)
	}
	sort.Ints(indices)

	var events [][]byte
	for _, index := range indices {
		flushed, err := s.flushChoiceEvents(s.choices[index], index, nil)
		if err != nil {
			return nil, err
		}
		events = append(events, flushed...)
	}
	return events, nil
}

func (s *restoreStreamState) textFlushEvent(choice *restoreChoiceState, index int, inFlight map[string]json.RawMessage) ([]byte, bool, error) {
	delta := make(map[string]json.RawMessage)
	for _, channel := range restoreTextChannels() {
		pending := ""
		if buffer, ok := choice.text[channel]; ok {
			pending = buffer.take()
		}
		ready := ""
		hasReady := false
		if raw, ok := inFlight[channel]; ok {
			var text *string
			if err := json.Unmarshal(raw, &text); err == nil && text != nil {
				ready = *text
				hasReady = true
			}
		}
		combined := ready + pending
		if combined == "" && !hasReady {
			continue
		}
		if combined == "" {
			continue
		}
		encoded, err := json.Marshal(combined)
		if err != nil {
			return nil, false, restoreError("encoding failed")
		}
		delta[channel] = encoded
	}
	if len(delta) == 0 {
		return nil, false, nil
	}
	event, err := s.syntheticEvent(index, delta)
	if err != nil {
		return nil, false, err
	}
	return event, true, nil
}

// toolFlushEvent restores complete arguments for one choice. Non-empty
// documents are parsed and validated before any event is returned, so a
// malformed or unmapped tool call never leaves a half-restored payload for
// execution. Empty or whitespace-only provider bytes are preserved exactly for
// a no-argument call.
func (s *restoreStreamState) toolFlushEvent(choice *restoreChoiceState, index int) ([]byte, error) {
	if len(choice.tools) == 0 {
		return nil, nil
	}
	toolIndices := make([]int, 0, len(choice.tools))
	for toolIndex := range choice.tools {
		toolIndices = append(toolIndices, toolIndex)
	}
	sort.Ints(toolIndices)

	type pendingTool struct {
		index int
		call  map[string]json.RawMessage
	}
	pending := make([]pendingTool, 0, len(toolIndices))
	for _, toolIndex := range toolIndices {
		tool := choice.tools[toolIndex]
		if tool.emitted || !tool.sawArgs {
			continue
		}
		rawArgs := tool.args.String()
		// Empty and whitespace-only arguments are the provider's exact
		// representation of a no-argument call. Preserve those bytes instead of
		// parsing them or dropping the call; a non-empty document must still be
		// valid JSON.
		restored := rawArgs
		if strings.TrimSpace(rawArgs) != "" {
			var err error
			restored, err = restoreToolArgumentsJSON(rawArgs, s.mappings)
			if err != nil {
				return nil, err
			}
		}
		call := make(map[string]json.RawMessage)
		call["index"] = json.RawMessage(strconv.Itoa(toolIndex))
		function := make(map[string]json.RawMessage)
		if !tool.announced() {
			if tool.id != "" {
				encoded, _ := json.Marshal(tool.id)
				call["id"] = encoded
			}
			if tool.typ != "" {
				encoded, _ := json.Marshal(tool.typ)
				call["type"] = encoded
			}
			if tool.name != "" {
				encoded, _ := json.Marshal(tool.name)
				function["name"] = encoded
			}
		}
		encodedArgs, err := json.Marshal(restored)
		if err != nil {
			return nil, restoreError("encoding failed")
		}
		function["arguments"] = encodedArgs
		encodedFunction, err := json.Marshal(function)
		if err != nil {
			return nil, restoreError("encoding failed")
		}
		call["function"] = encodedFunction
		pending = append(pending, pendingTool{index: toolIndex, call: call})
	}
	if len(pending) == 0 {
		return nil, nil
	}

	calls := make([]json.RawMessage, 0, len(pending))
	for _, item := range pending {
		encoded, err := json.Marshal(item.call)
		if err != nil {
			return nil, restoreError("encoding failed")
		}
		calls = append(calls, encoded)
	}
	encodedCalls, err := json.Marshal(calls)
	if err != nil {
		return nil, restoreError("encoding failed")
	}
	event, err := s.syntheticEvent(index, map[string]json.RawMessage{"tool_calls": encodedCalls})
	if err != nil {
		return nil, err
	}
	for _, item := range pending {
		choice.tools[item.index].emitted = true
	}
	return event, nil
}

func (s *restoreStreamState) syntheticEvent(index int, delta map[string]json.RawMessage) ([]byte, error) {
	top := make(map[string]json.RawMessage, len(s.base)+1)
	for key, value := range s.base {
		if key == "choices" || key == "usage" {
			continue
		}
		top[key] = value
	}
	encodedDelta, err := json.Marshal(delta)
	if err != nil {
		return nil, restoreError("encoding failed")
	}
	choice := map[string]json.RawMessage{
		"index":         json.RawMessage(strconv.Itoa(index)),
		"delta":         encodedDelta,
		"finish_reason": json.RawMessage("null"),
	}
	encodedChoice, err := json.Marshal(choice)
	if err != nil {
		return nil, restoreError("encoding failed")
	}
	encodedChoices, err := json.Marshal([]json.RawMessage{encodedChoice})
	if err != nil {
		return nil, restoreError("encoding failed")
	}
	top["choices"] = encodedChoices
	return restoreMarshal(top)
}

// consumeToolCalls strips arguments from the delta (they are accumulated and
// emitted only when complete), preserves id/name/type/index from their first
// occurrence, and returns the structural delta to forward.
func (c *restoreChoiceState) consumeToolCalls(raw json.RawMessage, mappings map[string]RestoreMapping) ([]json.RawMessage, bool, error) {
	var calls []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &calls); err != nil {
		return nil, false, restoreError("malformed tool call delta")
	}
	out := make([]json.RawMessage, 0, len(calls))
	changed := false
	for _, call := range calls {
		var index int
		if rawIndex, ok := call["index"]; ok && !restoreIsNull(rawIndex) {
			if err := json.Unmarshal(rawIndex, &index); err != nil || index < 0 || index >= restoreMaxToolsPerChoice {
				return nil, false, restoreError("invalid tool call index")
			}
		} else if len(calls) > 1 {
			return nil, false, restoreError("missing tool call index")
		}
		tool := c.tool(index)
		structural := make(map[string]json.RawMessage)
		structural["index"] = json.RawMessage(strconv.Itoa(index))

		if rawID, ok := call["id"]; ok && !restoreIsNull(rawID) {
			var id string
			if err := json.Unmarshal(rawID, &id); err != nil {
				return nil, false, restoreError("malformed tool call delta")
			}
			if id != "" && tool.id == "" {
				tool.id = id
			}
			if id != "" && !tool.idSent {
				structural["id"] = rawID
				tool.idSent = true
				changed = true
			}
		}
		if rawType, ok := call["type"]; ok && !restoreIsNull(rawType) {
			var typ string
			if err := json.Unmarshal(rawType, &typ); err != nil {
				return nil, false, restoreError("malformed tool call delta")
			}
			if typ != "" && tool.typ == "" {
				tool.typ = typ
			}
			if typ != "" && !tool.typeSent {
				structural["type"] = rawType
				tool.typeSent = true
				changed = true
			}
		}
		if rawFunction, ok := call["function"]; ok && !restoreIsNull(rawFunction) {
			var function map[string]json.RawMessage
			if err := json.Unmarshal(rawFunction, &function); err != nil {
				return nil, false, restoreError("malformed tool call delta")
			}
			outFunction := make(map[string]json.RawMessage)
			if rawName, ok := function["name"]; ok && !restoreIsNull(rawName) {
				var name string
				if err := json.Unmarshal(rawName, &name); err != nil {
					return nil, false, restoreError("malformed tool call delta")
				}
				if name != "" && tool.name == "" {
					tool.name = name
				}
				if name != "" && !tool.nameSent {
					outFunction["name"] = rawName
					tool.nameSent = true
					changed = true
				}
			}
			if rawArgs, ok := function["arguments"]; ok && !restoreIsNull(rawArgs) {
				var fragment string
				if err := json.Unmarshal(rawArgs, &fragment); err != nil {
					return nil, false, restoreError("malformed tool call delta")
				}
				if tool.args.Len()+len(fragment) > restoreMaxToolArgBytes {
					return nil, false, restoreError("tool arguments exceed size limit")
				}
				tool.args.WriteString(fragment)
				tool.sawArgs = true
				changed = true
			}
			for key, value := range function {
				if key != "name" && key != "arguments" {
					outFunction[key] = value
				}
			}
			if len(outFunction) > 0 {
				encoded, err := json.Marshal(outFunction)
				if err != nil {
					return nil, false, restoreError("encoding failed")
				}
				structural["function"] = encoded
			}
		}
		for key, value := range call {
			switch key {
			case "index", "id", "type", "function":
				continue
			}
			structural[key] = value
		}
		if len(structural) == 1 {
			// Only an index was supplied and the arguments are being withheld.
			continue
		}
		encoded, err := json.Marshal(structural)
		if err != nil {
			return nil, false, restoreError("encoding failed")
		}
		out = append(out, encoded)
	}
	return out, changed, nil
}

// ---------------------------------------------------------------------------
// Token scanning / restoration
// ---------------------------------------------------------------------------

func restoreIsHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// scanRestoreToken examines s[start:], which must begin with __PG_. It reports a
// complete token, or `partial` when the bytes run out before the token could be
// decided (so a caller may hold them for the next chunk).
func scanRestoreToken(s string, start int) (end int, token string, complete, partial bool) {
	pos := start + len(restoreTokenPrefix)
	for n := 0; n < restoreTokenHexChars; n++ {
		if pos >= len(s) {
			return 0, "", false, true
		}
		if !restoreIsHex(s[pos]) {
			return 0, "", false, false
		}
		pos++
	}
	if pos >= len(s) {
		return 0, "", false, true
	}
	if s[pos] != '_' {
		return 0, "", false, false
	}
	if pos+1 >= len(s) {
		return 0, "", false, true
	}
	if s[pos+1] != '_' {
		return 0, "", false, false
	}
	return pos + 2, s[start : pos+2], true, false
}

// splitPartialPrefix removes the longest suffix that is a proper prefix of the
// token marker, so a marker split across chunks is not emitted prematurely.
func splitPartialPrefix(s string) (ready, held string) {
	max := len(restoreTokenPrefix) - 1
	if max > len(s) {
		max = len(s)
	}
	for n := max; n > 0; n-- {
		if s[len(s)-n:] == restoreTokenPrefix[:n] {
			return s[:len(s)-n], s[len(s)-n:]
		}
	}
	return s, ""
}

// restoreTokenText is the single token scanner. holdPartial keeps a trailing
// incomplete marker/token for the next streaming chunk instead of emitting it;
// strict rejects an unknown complete token (tool arguments) instead of leaving
// it as ordinary text (content/reasoning). Replacement is one-shot: an original
// is written to the output and never rescanned.
func restoreTokenText(s string, mappings map[string]RestoreMapping, strict, holdPartial bool) (ready, held string, err error) {
	if !holdPartial && !strings.Contains(s, restoreTokenPrefix) {
		return s, "", nil
	}
	var out strings.Builder
	out.Grow(len(s))
	i := 0
	for i < len(s) {
		relative := strings.Index(s[i:], restoreTokenPrefix)
		if relative < 0 {
			if !holdPartial {
				out.WriteString(s[i:])
				return out.String(), "", nil
			}
			safe, hold := splitPartialPrefix(s[i:])
			out.WriteString(safe)
			return out.String(), hold, nil
		}
		start := i + relative
		out.WriteString(s[i:start])
		end, token, complete, partial := scanRestoreToken(s, start)
		if partial && holdPartial {
			return out.String(), s[start:], nil
		}
		if !complete {
			out.WriteString(restoreTokenPrefix)
			i = start + len(restoreTokenPrefix)
			continue
		}
		mapping, ok := mappings[token]
		if !ok {
			if strict {
				return "", "", restoreError("unmapped token in tool arguments")
			}
			out.WriteString(token)
		} else {
			out.WriteString(mapping.Original)
		}
		i = end
	}
	return out.String(), "", nil
}

// restoreTextTokens restores complete mapped tokens in a finished string.
func restoreTextTokens(s string, mappings map[string]RestoreMapping, strict bool) (string, error) {
	restored, _, err := restoreTokenText(s, mappings, strict, false)
	return restored, err
}

// restoreToolArgumentsJSON parses one complete tool argument document, restores
// string values recursively, and serializes it as valid JSON again.
func restoreToolArgumentsJSON(raw string, mappings map[string]RestoreMapping) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return raw, nil
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", restoreError("invalid tool arguments JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", restoreError("invalid tool arguments JSON")
	}
	restored, err := restoreToolValue(value, mappings, 0)
	if err != nil {
		return "", err
	}
	encoded, err := restoreMarshal(restored)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// restoreToolStringValue restores one string value in a parsed tool argument
// document. Only an exact whole-string token with a validated numeric mapping
// becomes a JSON number; everything else stays a string.
func restoreToolStringValue(value string, mappings map[string]RestoreMapping) (any, error) {
	if mapping, ok := mappings[value]; ok && mapping.OriginalType == "number" && restoreValidJSONNumber(mapping.Original) {
		return json.Number(mapping.Original), nil
	}
	return restoreTextTokens(value, mappings, true)
}

// restoreValidJSONNumber accepts exactly one JSON number literal and rejects
// surrounding whitespace, strings, keywords, and trailing data.
func restoreValidJSONNumber(value string) bool {
	if value == "" || !json.Valid([]byte(value)) {
		return false
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return false
	}
	number, ok := decoded.(json.Number)
	if !ok || number.String() != value {
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return false
	}
	return true
}

func restoreToolValue(value any, mappings map[string]RestoreMapping, depth int) (any, error) {
	if depth > restoreMaxToolDepth {
		return nil, restoreError("tool arguments nested too deeply")
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			restored, err := restoreToolValue(item, mappings, depth+1)
			if err != nil {
				return nil, err
			}
			typed[key] = restored
		}
		return typed, nil
	case []any:
		for index, item := range typed {
			restored, err := restoreToolValue(item, mappings, depth+1)
			if err != nil {
				return nil, err
			}
			typed[index] = restored
		}
		return typed, nil
	case string:
		return restoreToolStringValue(typed, mappings)
	default:
		return value, nil
	}
}

// ---------------------------------------------------------------------------
// Non-streaming JSON
// ---------------------------------------------------------------------------

func restoreJSONResponse(ctx context.Context, reader io.Reader, writer io.Writer, flusher interface{ Flush() }, mappings map[string]RestoreMapping) error {
	data, err := restoreReadAll(ctx, reader)
	if err != nil {
		return err
	}
	restored, err := restoreJSONBody(ctx, data, mappings)
	if err != nil {
		return err
	}
	if err := restoreWriteAll(writer, restored); err != nil {
		return err
	}
	restoreFlush(flusher)
	return nil
}

func restoreReadAll(ctx context.Context, reader io.Reader) ([]byte, error) {
	buffer := make([]byte, 32*1024)
	var out bytes.Buffer
	total := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, restoreCancelled(err)
		}
		n, err := reader.Read(buffer)
		if n > 0 {
			total += n
			if total > restoreMaxResponseBytes {
				return nil, restoreError("response exceeds size limit")
			}
			out.Write(buffer[:n])
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return out.Bytes(), nil
			}
			return nil, restoreError("read failed")
		}
	}
}

func restoreJSONBody(ctx context.Context, data []byte, mappings map[string]RestoreMapping) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, restoreCancelled(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, restoreError("malformed JSON response")
	}
	rawChoices, ok := top["choices"]
	if !ok || restoreIsNull(rawChoices) {
		return data, nil
	}
	var choices []json.RawMessage
	if err := json.Unmarshal(rawChoices, &choices); err != nil {
		return nil, restoreError("malformed JSON response")
	}
	if len(choices) == 0 {
		return data, nil
	}
	if len(choices) > restoreMaxChoices {
		return nil, restoreError("too many choices")
	}

	changedAny := false
	newChoices := make([]json.RawMessage, 0, len(choices))
	for _, rawChoice := range choices {
		if err := ctx.Err(); err != nil {
			return nil, restoreCancelled(err)
		}
		var choice map[string]json.RawMessage
		if err := json.Unmarshal(rawChoice, &choice); err != nil {
			return nil, restoreError("malformed JSON response")
		}
		choiceChanged := false
		if rawMessage, ok := choice["message"]; ok && !restoreIsNull(rawMessage) {
			var message map[string]json.RawMessage
			if err := json.Unmarshal(rawMessage, &message); err != nil {
				return nil, restoreError("malformed JSON response")
			}
			messageChanged := false
			for _, channel := range restoreTextChannels() {
				rawText, ok := message[channel]
				if !ok {
					continue
				}
				var text *string
				if err := json.Unmarshal(rawText, &text); err != nil {
					return nil, restoreError("malformed JSON response")
				}
				if text == nil {
					continue
				}
				restored, err := restoreTextTokens(*text, mappings, false)
				if err != nil {
					return nil, err
				}
				if restored != *text {
					encoded, err := json.Marshal(restored)
					if err != nil {
						return nil, restoreError("encoding failed")
					}
					message[channel] = encoded
					messageChanged = true
				}
			}
			if rawTools, ok := message["tool_calls"]; ok && !restoreIsNull(rawTools) {
				restoredTools, toolsChanged, err := restoreNonStreamToolCalls(rawTools, mappings)
				if err != nil {
					return nil, err
				}
				if toolsChanged {
					message["tool_calls"] = restoredTools
					messageChanged = true
				}
			}
			if messageChanged {
				encodedMessage, err := restoreMarshal(message)
				if err != nil {
					return nil, err
				}
				choice["message"] = encodedMessage
				choiceChanged = true
			}
		}
		if choiceChanged {
			encodedChoice, err := restoreMarshal(choice)
			if err != nil {
				return nil, err
			}
			newChoices = append(newChoices, encodedChoice)
			changedAny = true
		} else {
			newChoices = append(newChoices, rawChoice)
		}
	}
	if !changedAny {
		return data, nil
	}
	encodedChoices, err := json.Marshal(newChoices)
	if err != nil {
		return nil, restoreError("encoding failed")
	}
	top["choices"] = encodedChoices
	return restoreMarshal(top)
}

func restoreNonStreamToolCalls(raw json.RawMessage, mappings map[string]RestoreMapping) (json.RawMessage, bool, error) {
	var calls []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &calls); err != nil {
		return nil, false, restoreError("malformed JSON response")
	}
	changed := false
	for index, call := range calls {
		rawFunction, ok := call["function"]
		if !ok || restoreIsNull(rawFunction) {
			continue
		}
		var function map[string]json.RawMessage
		if err := json.Unmarshal(rawFunction, &function); err != nil {
			return nil, false, restoreError("malformed JSON response")
		}
		rawArgs, ok := function["arguments"]
		if !ok || restoreIsNull(rawArgs) {
			continue
		}
		var args string
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			continue // not a string: leave this call exactly as received
		}
		restored, err := restoreToolArgumentsJSON(args, mappings)
		if err != nil {
			return nil, false, err
		}
		if restored == args {
			continue
		}
		encoded, err := json.Marshal(restored)
		if err != nil {
			return nil, false, restoreError("encoding failed")
		}
		function["arguments"] = encoded
		encodedFunction, err := restoreMarshal(function)
		if err != nil {
			return nil, false, err
		}
		call["function"] = encodedFunction
		calls[index] = call
		changed = true
	}
	if !changed {
		return raw, false, nil
	}
	encoded, err := restoreMarshal(calls)
	if err != nil {
		return nil, false, err
	}
	return encoded, true, nil
}
