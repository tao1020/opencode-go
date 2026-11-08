/**
 * Outbound masking at the OpenCode Go adapter boundary.
 *
 * Guarantee: detected textual secrets are replaced in the model-provider
 * request. Arbitrary or encoded secrets, opaque provider state, and image
 * pixels can be missed. Local tools receive restored originals and can
 * transmit them; this module does not prevent that.
 *
 * Contract: POST /mask { version: 1, scope, payload } →
 * { version: 1, payload, mappings: [{ token: '__PG_<32hex>__', original,
 *   originalType?: 'number' }], uninspectedMedia: boolean }
 * @module llm-opencode-go/privacy
 */
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs'
import { createHmac, randomBytes } from 'node:crypto'
import { homedir } from 'node:os'
import { isAbsolute, join } from 'node:path'
import { LlmError, type StreamChunk } from '@deepseek-ai/dsh-llm'

/** Local daemon the operator runs; never a remote endpoint. */
export const DEFAULT_PRIVACY_ENDPOINT = 'http://127.0.0.1:8788'
/** Default credential location, derived from the current home directory. */
export const DEFAULT_PRIVACY_KEY_FILE = join(homedir(), '.local', 'state', 'privacy-guard', 'client-key')
/** Bound on one `/mask` call. */
export const DEFAULT_PRIVACY_TIMEOUT_MS = 15_000
/** Contract version this client speaks. */
export const PRIVACY_CONTRACT_VERSION = 1
/** Request and response envelope cap, including the JSON wrapper. */
const MAX_TRANSPORT_BYTES = 8 * 1024 * 1024

const TOKEN_LENGTH = 39
const TOKEN_PATTERN = /^__PG_[0-9a-f]{32}__$/
const NUMBER_LITERAL = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/
const TOKEN_SCAN = /__PG_[0-9a-f]{32}__/g
const TOKEN_ANY = /__PG_[0-9a-f]{32}__/
const RESPONSE_FIELDS = new Set(['version', 'payload', 'mappings', 'uninspectedMedia'])
const MAPPING_FIELDS = new Set(['token', 'original', 'originalType'])
const MAX_SCOPES = 1024
const MAX_KEY_BYTES = 4096

/**
 * Fixed, payload-free failure text. The code carries the diagnosis; the
 * message never interpolates request data, a token, a secret, or a daemon
 * string that an SDK might log.
 */
const FAILURE_TEXT = Object.freeze({
  PRIVACY_CONFIG: 'privacy configuration is invalid',
  PRIVACY_SERVICE_UNAVAILABLE: 'privacy is enabled but unavailable',
  PRIVACY_UNAVAILABLE: 'privacy daemon request failed',
  PRIVACY_REQUEST_TOO_LARGE: 'privacy request exceeds the transport limit',
  PRIVACY_INVALID_MAPPING: 'privacy mapping is invalid',
  PRIVACY_DUPLICATE_PUBLISH: 'privacy mappings were published twice',
  PRIVACY_MASK_NOT_PUBLISHED: 'privacy mappings were not published',
  PRIVACY_UNKNOWN_TOKEN: 'privacy token is not mapped for this request',
  PRIVACY_TOOL_ARGUMENTS_INVALID: 'privacy tool arguments are not valid JSON',
  PRIVACY_SCOPE_CAPACITY: 'privacy scope capacity is exhausted',
  PRIVACY_UNSUPPORTED_CHUNK: 'privacy received an unsupported stream chunk',
})

/** Throw one fixed-code failure. Never attach a cause or dynamic text. */
function fail(code: keyof typeof FAILURE_TEXT): never {
  throw new LlmError(FAILURE_TEXT[code], code)
}

/** One daemon mapping. `originalType: 'number'` restores an exact numeric JSON value. */
export interface PrivacyMapping {
  token: string
  original: string
  originalType?: 'number'
}

export interface PrivacyMaskMeta {
  provider: string
  model: string
  sessionId: string
}

export interface PrivacyMaskResult {
  payload: unknown
  mappings: readonly PrivacyMapping[]
  uninspectedMedia: boolean
}

/** What the adapter needs from a mask client. */
export interface PrivacyMaskClient {
  mask(payload: unknown, meta: PrivacyMaskMeta, signal?: AbortSignal): Promise<PrivacyMaskResult>
}

/** Per-call publication state. One instance per adapter stream call. */
export interface MaskState {
  readonly published: boolean
  readonly mappings: ReadonlyMap<string, PrivacyMapping>
  publish(mappings: readonly PrivacyMapping[]): void
}

/** Create the per-call mask state; mappings publish once, before the first chunk. */
export function createMaskState(): MaskState {
  let published = false
  let mappings: ReadonlyMap<string, PrivacyMapping> = new Map()
  return {
    get published() {
      return published
    },
    get mappings() {
      return mappings
    },
    publish(next) {
      if (published) fail('PRIVACY_DUPLICATE_PUBLISH')
      const map = new Map<string, PrivacyMapping>()
      for (const mapping of next) {
        if (!TOKEN_PATTERN.test(mapping.token) || map.has(mapping.token)) fail('PRIVACY_INVALID_MAPPING')
        map.set(mapping.token, mapping)
      }
      mappings = map
      published = true
    },
  }
}

/**
 * Session-scoped opaque namespaces, derived from the client key and session ID.
 * Recreating the registry with the same key preserves named scopes. A bounded LRU pins active scopes so one
 * is never replaced underneath a call; at capacity with every scope active it
 * refuses instead of silently re-keying.
 */
export function createScopeRegistry(maxScopes = MAX_SCOPES, secret: string | Buffer = randomBytes(32)): { acquire(sessionId: string): { readonly scope: string; release(): void } } {
  const entries = new Map<string, { scope: string; active: number }>()
  return {
    acquire(sessionId) {
      if (sessionId.length === 0) return { scope: randomBytes(16).toString('hex'), release() {} }
      let entry = entries.get(sessionId)
      if (entry !== undefined) {
        entries.delete(sessionId)
        entries.set(sessionId, entry)
      } else {
        if (entries.size >= maxScopes) {
          const victim = [...entries.entries()].find(([, value]) => value.active === 0)
          if (victim === undefined) fail('PRIVACY_SCOPE_CAPACITY')
          entries.delete(victim[0])
        }
        entry = { scope: createHmac('sha256', secret).update('privacy-guard-scope-v1\0').update(sessionId).digest('hex').slice(0, 32), active: 0 }
        entries.set(sessionId, entry)
      }
      entry.active += 1
      const record = entry
      let released = false
      return {
        scope: record.scope,
        release() {
          if (released) return
          released = true
          record.active -= 1
        },
      }
    },
  }
}

/**
 * Streaming replacement for text and reasoning deltas. A token can straddle two
 * deltas, so the rewriter keeps a tail of at most one token minus one character.
 * It never rescans text it emitted.
 */
export class TokenRewriter {
  private buffer = ''

  constructor(private readonly mappings: ReadonlyMap<string, PrivacyMapping>) {}

  push(text: string): string {
    if (this.mappings.size === 0) return text
    this.buffer += text
    let out = ''
    const prefix = '__PG_'
    while (this.buffer.length > 0) {
      const start = this.buffer.indexOf(prefix)
      if (start < 0) {
        let keep = Math.min(prefix.length - 1, this.buffer.length)
        while (keep > 0 && !prefix.startsWith(this.buffer.slice(-keep))) keep--
        out += this.buffer.slice(0, this.buffer.length - keep)
        this.buffer = this.buffer.slice(this.buffer.length - keep)
        break
      }
      out += this.buffer.slice(0, start)
      this.buffer = this.buffer.slice(start)
      if (this.buffer.length < TOKEN_LENGTH && /^__PG_(?:[0-9a-f]{0,32}|[0-9a-f]{32}_)$/.test(this.buffer)) break
      const token = this.buffer.slice(0, TOKEN_LENGTH)
      if (TOKEN_PATTERN.test(token)) {
        out += this.mappings.get(token)?.original ?? token
        this.buffer = this.buffer.slice(TOKEN_LENGTH)
      } else {
        out += this.buffer[0]
        this.buffer = this.buffer.slice(1)
      }
    }
    return out
  }

  flush(): string {
    const out = this.buffer
    this.buffer = ''
    return out
  }
}

/**
 * Replace tokens in free text in one pass over the masked input. Sequential
 * `replaceAll` would rescan an inserted original and could expand a token that
 * the original itself contains; this scanner never looks at text it emits.
 */
function restoreText(text: string, mappings: ReadonlyMap<string, PrivacyMapping>): string {
  const rewriter = new TokenRewriter(mappings)
  return rewriter.push(text) + rewriter.flush()
}

/**
 * Parse a numeric original without silently losing precision.
 *
 * `JSON.rawJSON` (Node 22.19+/24) lets `JSON.stringify` emit the exact literal,
 * including integers beyond MAX_SAFE_INTEGER, long fractions, `-0`, and
 * exponents. A strict JSON-number grammar runs first so nothing but a number
 * literal can be injected. Runtimes without `rawJSON` fall back to a canonical
 * round-trip only; a literal that would change is rejected.
 */
function numericOriginal(original: string, code: keyof typeof FAILURE_TEXT): unknown {
  if (!NUMBER_LITERAL.test(original)) fail(code)
  const factory = (JSON as unknown as { rawJSON?: (text: string) => unknown }).rawJSON
  if (typeof factory === 'function') {
    try {
      return factory(original)
    } catch {
      fail(code)
    }
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(original)
  } catch {
    fail(code)
  }
  if (typeof parsed !== 'number' || !Number.isFinite(parsed) || String(parsed) !== original) fail(code)
  return parsed
}

/**
 * Restore parsed tool arguments. An exact token string restores a number only
 * when the mapping is numeric; a token embedded in a larger string is always
 * replaced textually.
 */
function restoreJson(value: unknown, mappings: ReadonlyMap<string, PrivacyMapping>): unknown {
  if (typeof value === 'string') {
    const exact = mappings.get(value)
    if (exact !== undefined && exact.originalType === 'number') return numericOriginal(exact.original, 'PRIVACY_INVALID_MAPPING')
    return restoreText(value, mappings)
  }
  if (Array.isArray(value)) return value.map((entry) => restoreJson(entry, mappings))
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = Object.create(null)
    for (const [key, entry] of Object.entries(value)) {
      Object.defineProperty(out, key, { value: restoreJson(entry, mappings), enumerable: true, writable: true, configurable: true })
    }
    return out
  }
  return value
}

function restoreToolArguments(raw: string, mappings: ReadonlyMap<string, PrivacyMapping>): string {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    fail('PRIVACY_TOOL_ARGUMENTS_INVALID')
  }
  return JSON.stringify(restoreJson(parsed, mappings))
}

/**
 * A patterned token that this request did not map is refused before the tool
 * runs: it is either a dangling token from another context or model text that
 * must not be guessed at. Originals inserted by restoration are never rescanned.
 */
function assertKnownTokens(text: string, mappings: ReadonlyMap<string, PrivacyMapping>): void {
  for (const match of text.matchAll(TOKEN_SCAN)) {
    if (!mappings.has(match[0])) fail('PRIVACY_UNKNOWN_TOKEN')
  }
}

/**
 * Restore daemon tokens in the streamed chunks.
 *
 * Tool-call deltas are suppressed: the authoritative `block-end` block carries
 * the complete arguments, and `BlockAssembler` replaces the partial with that
 * block ("first close wins"), so the consumer receives restored arguments
 * exactly once. All tools are restored to their local semantic values; local
 * tools can still transmit a secret, which is outside this guarantee.
 */
export async function* restoreChunks(
  source: AsyncIterable<StreamChunk>,
  state: MaskState,
  failure?: () => unknown,
): AsyncGenerator<StreamChunk> {
  const text = new Map<number, TokenRewriter>()
  const reasoning = new Map<number, TokenRewriter>()
  let started = false
  let completed = false

  try {
  for await (const chunk of source) {
    if (!started) {
      started = true
      if (!state.published) {
        // A provider may turn an onPayload throw into a stream error event.
        // Surface the original fixed-code failure instead of a generic one.
        const pending = failure?.()
        if (pending instanceof Error) throw pending
        fail('PRIVACY_MASK_NOT_PUBLISHED')
      }
    }
    switch (chunk.type) {
      case 'block-start':
      case 'usage':
        yield chunk
        break
      case 'text-delta': {
        const rewriter = text.get(chunk.index) ?? new TokenRewriter(state.mappings)
        text.set(chunk.index, rewriter)
        yield { type: 'text-delta', index: chunk.index, text: rewriter.push(chunk.text) }
        break
      }
      case 'reasoning-delta': {
        const rewriter = reasoning.get(chunk.index) ?? new TokenRewriter(state.mappings)
        reasoning.set(chunk.index, rewriter)
        yield { type: 'reasoning-delta', index: chunk.index, text: rewriter.push(chunk.text) }
        break
      }
      case 'tool-call-delta':
        // Deliberately dropped; the block-end below is authoritative.
        break
      case 'block-end': {
        const block = chunk.block
        if (block.type === 'text' || block.type === 'reasoning') {
          const rewriters = block.type === 'text' ? text : reasoning
          const tail = rewriters.get(chunk.index)?.flush() ?? ''
          if (tail.length > 0) {
            yield { type: block.type === 'text' ? 'text-delta' : 'reasoning-delta', index: chunk.index, text: tail }
          }
          yield { type: 'block-end', index: chunk.index, block: { ...block, text: restoreText(block.text, state.mappings) } }
          break
        }
        if (block.type === 'tool-call') {
          assertKnownTokens(block.arguments, state.mappings)
          if (!TOKEN_ANY.test(block.arguments)) {
            yield chunk
            break
          }
          yield { type: 'block-end', index: chunk.index, block: { ...block, arguments: restoreToolArguments(block.arguments, state.mappings) } }
          break
        }
        yield chunk
        break
      }
      case 'finish': {
        // Release held text before the terminal chunk so an error or abort
        // finish never arrives ahead of the text it closes.
        for (const [index, rewriter] of text) {
          const tail = rewriter.flush()
          if (tail.length > 0) yield { type: 'text-delta', index, text: tail }
        }
        for (const [index, rewriter] of reasoning) {
          const tail = rewriter.flush()
          if (tail.length > 0) yield { type: 'reasoning-delta', index, text: tail }
        }
        text.clear()
        reasoning.clear()
        // replayState is provider-owned opaque state; never rewritten here.
        yield chunk
        break
      }
      default:
        fail('PRIVACY_UNSUPPORTED_CHUNK')
    }
  }
    completed = true
  } finally {
    // Consumer cancellation: drop held text; never yield from cleanup.
    if (!completed) {
      text.clear()
      reasoning.clear()
    }
  }

  for (const [index, rewriter] of text) {
    const tail = rewriter.flush()
    if (tail.length > 0) yield { type: 'text-delta', index, text: tail }
  }
  for (const [index, rewriter] of reasoning) {
    const tail = rewriter.flush()
    if (tail.length > 0) yield { type: 'reasoning-delta', index, text: tail }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function onlyFields(record: Record<string, unknown>, allowed: ReadonlySet<string>): void {
  for (const key of Object.keys(record)) if (!allowed.has(key)) fail('PRIVACY_UNAVAILABLE')
}

/**
 * Strict response validator. Unknown fields, a wrong version, a malformed or
 * duplicate token, an unsafe numeric original, or a non-boolean media flag
 * reject the whole response.
 */
export function parseMaskResponse(value: unknown): PrivacyMaskResult {
  if (!isRecord(value)) fail('PRIVACY_UNAVAILABLE')
  onlyFields(value, RESPONSE_FIELDS)
  if (value.version !== PRIVACY_CONTRACT_VERSION) fail('PRIVACY_UNAVAILABLE')
  if (!('payload' in value)) fail('PRIVACY_UNAVAILABLE')
  if (!Array.isArray(value.mappings)) fail('PRIVACY_UNAVAILABLE')
  if (typeof value.uninspectedMedia !== 'boolean') fail('PRIVACY_UNAVAILABLE')

  const seen = new Set<string>()
  const mappings: PrivacyMapping[] = []
  for (const entry of value.mappings) {
    if (!isRecord(entry)) fail('PRIVACY_UNAVAILABLE')
    onlyFields(entry, MAPPING_FIELDS)
    const { token, original, originalType } = entry
    if (typeof token !== 'string' || !TOKEN_PATTERN.test(token) || seen.has(token)) fail('PRIVACY_UNAVAILABLE')
    if (typeof original !== 'string') fail('PRIVACY_UNAVAILABLE')
    if (originalType !== undefined && originalType !== 'number') fail('PRIVACY_UNAVAILABLE')
    if (originalType === 'number') numericOriginal(original, 'PRIVACY_UNAVAILABLE')
    seen.add(token)
    mappings.push({ token, original, ...(originalType === undefined ? {} : { originalType }) })
  }
  return { payload: value.payload, mappings, uninspectedMedia: value.uninspectedMedia }
}

/** Accept only a loopback HTTP origin for the daemon. */
export function assertPrivacyEndpoint(raw: string): string {
  if (typeof raw !== 'string' || raw.length === 0) fail('PRIVACY_CONFIG')
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    fail('PRIVACY_CONFIG')
  }
  if (url.protocol !== 'http:') fail('PRIVACY_CONFIG')
  if (url.hostname !== '127.0.0.1' && url.hostname !== '[::1]') fail('PRIVACY_CONFIG')
  if (url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '') fail('PRIVACY_CONFIG')
  if (url.pathname !== '/' && url.pathname !== '') fail('PRIVACY_CONFIG')
  return url.origin
}

/**
 * Read the local daemon credential once.
 *
 * Refuses a symlink, requires an owner-only 0600 regular file owned by the
 * current user, and re-checks the opened descriptor so a swap between the path
 * check and the open cannot substitute another file.
 */
export function readPrivacyKey(file: string): string {
  if (typeof file !== 'string' || !isAbsolute(file)) fail('PRIVACY_CONFIG')
  let link
  try {
    link = lstatSync(file)
  } catch {
    fail('PRIVACY_CONFIG')
  }
  if (link.isSymbolicLink() || !link.isFile() || link.size > MAX_KEY_BYTES) fail('PRIVACY_CONFIG')

  let fd: number | undefined
  try {
    const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)
    fd = openSync(file, flags)
    const stat = fstatSync(fd)
    // Identity, size, owner, and mode come from the opened descriptor.
    if (!stat.isFile() || stat.dev !== link.dev || stat.ino !== link.ino || stat.size > MAX_KEY_BYTES) fail('PRIVACY_CONFIG')
    if ((stat.mode & 0o777) !== 0o600) fail('PRIVACY_CONFIG')
    const uid = typeof process.getuid === 'function' ? process.getuid() : undefined
    if (uid !== undefined && stat.uid !== uid) fail('PRIVACY_CONFIG')
    const buffer = Buffer.alloc(MAX_KEY_BYTES + 1)
    const bytes = readSync(fd, buffer, 0, buffer.length, 0)
    if (bytes > MAX_KEY_BYTES) fail('PRIVACY_CONFIG')
    const key = buffer.subarray(0, bytes).toString('utf8').trim()
    if (key.length === 0 || /\s/u.test(key)) fail('PRIVACY_CONFIG')
    return key
  } catch (error) {
    if (error instanceof LlmError) throw error
    return fail('PRIVACY_CONFIG')
  } finally {
    if (fd !== undefined) closeSync(fd)
  }
}

/**
 * Read a response body with a hard cap while it streams. The reader is cancelled
 * without awaiting on overflow, and the fused signal aborts a server that stalls
 * after headers. A read failure is sanitized: no local error text escapes.
 */
async function readBoundedBody(response: Response, fused: AbortSignal, caller: AbortSignal | undefined): Promise<string> {
  if (response.body === null) return ''
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  let detach = (): void => {}
  // One abort listener for the whole body; per-read listeners would accumulate.
  const aborted = new Promise<never>((_, reject) => {
    const abort = (): void => reject(fused.reason)
    if (fused.aborted) {
      abort()
      return
    }
    fused.addEventListener('abort', abort, { once: true })
    detach = () => fused.removeEventListener('abort', abort)
  })
  void aborted.catch(() => {})
  try {
    for (;;) {
      const { done, value } = await Promise.race([reader.read(), aborted])
      if (done) break
      total += value.byteLength
      if (total > MAX_TRANSPORT_BYTES) {
        void reader.cancel().catch(() => {})
        fail('PRIVACY_UNAVAILABLE')
      }
      chunks.push(value)
    }
  } catch (error) {
    if (caller?.aborted) throw caller.reason ?? error
    fail('PRIVACY_UNAVAILABLE')
  } finally {
    detach()
    try {
      reader.releaseLock()
    } catch {
      // A pending read keeps the lock; the request is already failing.
    }
  }
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString('utf8')
}

export interface PrivacyClientConfig {
  endpoint: string
  apiKeyFile: string
  timeoutMs: number
}

/**
 * Build the HTTP client. The scope registry is process-local and bounded; no
 * mapping or key is persisted anywhere.
 */
export function createHttpPrivacyClient(config: PrivacyClientConfig): PrivacyMaskClient {
  const endpoint = assertPrivacyEndpoint(config.endpoint)
  const apiKey = readPrivacyKey(config.apiKeyFile)
  if (!Number.isSafeInteger(config.timeoutMs) || config.timeoutMs < 1000 || config.timeoutMs > 60_000) fail('PRIVACY_CONFIG')
  const scopes = createScopeRegistry(MAX_SCOPES, apiKey)

  return {
    async mask(payload, meta, signal) {
      const lease = scopes.acquire(meta.sessionId)
      try {
        const body = JSON.stringify({ version: PRIVACY_CONTRACT_VERSION, scope: lease.scope, payload })
        if (Buffer.byteLength(body, 'utf8') > MAX_TRANSPORT_BYTES) fail('PRIVACY_REQUEST_TOO_LARGE')
        const timeout = AbortSignal.timeout(config.timeoutMs)
        const fused = signal === undefined ? timeout : AbortSignal.any([signal, timeout])
        let response: Response
        try {
          response = await fetch(`${endpoint}/mask`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` },
            body,
            signal: fused,
            redirect: 'error',
          })
        } catch (error) {
          if (signal?.aborted) throw signal.reason ?? error
          fail('PRIVACY_UNAVAILABLE')
        }
        if (!response.ok) {
          // Release the connection without draining a body that may never end.
          void response.body?.cancel().catch(() => {})
          fail('PRIVACY_UNAVAILABLE')
        }
        const text = await readBoundedBody(response, fused, signal)
        let parsed: unknown
        try {
          parsed = JSON.parse(text)
        } catch {
          fail('PRIVACY_UNAVAILABLE')
        }
        return parseMaskResponse(parsed)
      } finally {
        lease.release()
      }
    },
  }
}
