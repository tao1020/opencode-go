import { afterEach, describe, expect, it, vi } from 'vitest'
import { chmod, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createUserMessage, type StreamChunk } from '@deepseek-ai/dsh-llm'
import { OpencodeGoAdapter } from '../src/adapter.ts'
import { PlainConfig } from '../src/config.ts'
import { configOf, requestOf } from './support/host.ts'
import { fullLiveListing, listingBody, mockGateway, textEvents } from './support/gateway.ts'
import {
  createHttpPrivacyClient,
  createMaskState,
  createScopeRegistry,
  parseMaskResponse,
  readPrivacyKey,
  restoreChunks,
  TokenRewriter,
  type PrivacyMapping,
  type PrivacyMaskClient,
} from '../src/privacy.ts'

const posix = process.platform !== 'win32'
const TOKEN_A = `__PG_${'a'.repeat(32)}__`
const TOKEN_B = `__PG_${'b'.repeat(32)}__`
const TOKEN_C = `__PG_${'c'.repeat(32)}__`
const TOKEN_N = `__PG_${'1'.repeat(32)}__`

function mapping(token: string, original: string, originalType?: 'number'): PrivacyMapping {
  return { token, original, ...(originalType === undefined ? {} : { originalType }) }
}

function published(mappings: readonly PrivacyMapping[]) {
  const state = createMaskState()
  state.publish(mappings)
  return state
}

async function* source(...chunks: StreamChunk[]): AsyncIterable<StreamChunk> {
  for (const chunk of chunks) yield chunk
}

async function collect(stream: AsyncIterable<StreamChunk>): Promise<StreamChunk[]> {
  const out: StreamChunk[] = []
  for await (const chunk of stream) out.push(chunk)
  return out
}

function textOf(chunks: StreamChunk[], index: number): string {
  return chunks
    .filter((chunk): chunk is Extract<StreamChunk, { type: 'text-delta' }> => chunk.type === 'text-delta' && chunk.index === index)
    .map((chunk) => chunk.text)
    .join('')
}

function blockText(chunks: StreamChunk[]): string | undefined {
  const end = chunks.find((chunk) => chunk.type === 'block-end' && chunk.block.type === 'text')
  return end?.type === 'block-end' && end.block.type === 'text' ? end.block.text : undefined
}

function codeOf(fn: () => unknown): string | undefined {
  try {
    fn()
  } catch (error) {
    return (error as { code?: string }).code
  }
  return undefined
}

function tokenEvents(token: string): string[] {
  return [
    '{"choices":[{"delta":{"role":"assistant","content":""},"index":0,"finish_reason":null}]}',
    `{"choices":[{"delta":{"content":"${token}"},"index":0,"finish_reason":null}]}`,
    '{"choices":[{"delta":{},"index":0,"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1}}',
    '[DONE]',
  ]
}

afterEach(async () => {
  vi.unstubAllGlobals()
})

describe('token restoration', () => {
  it('restores a token split across two deltas', async () => {
    const state = published([mapping(TOKEN_A, 'secret')])
    const chunks = await collect(restoreChunks(source(
      { type: 'block-start', index: 0, blockType: 'text' },
      { type: 'text-delta', index: 0, text: `hello ${TOKEN_A.slice(0, 12)}` },
      { type: 'text-delta', index: 0, text: `${TOKEN_A.slice(12)} world` },
      { type: 'block-end', index: 0, block: { type: 'text', text: `hello ${TOKEN_A} world` } },
    ), state))
    expect(textOf(chunks, 0)).toBe('hello secret world')
    expect(blockText(chunks)).toBe('hello secret world')
  })

  it('does not rescan an original that itself contains another token', async () => {
    const state = published([mapping(TOKEN_A, TOKEN_B), mapping(TOKEN_B, 'deep')])
    const chunks = await collect(restoreChunks(source(
      { type: 'block-start', index: 0, blockType: 'text' },
      { type: 'block-end', index: 0, block: { type: 'text', text: TOKEN_A } },
    ), state))
    expect(blockText(chunks)).toBe(TOKEN_B)
  })

  it('leaves an unknown token in text untouched instead of guessing', async () => {
    const state = published([mapping(TOKEN_A, 'secret')])
    const chunks = await collect(restoreChunks(source(
      { type: 'block-start', index: 0, blockType: 'text' },
      { type: 'block-end', index: 0, block: { type: 'text', text: `a ${TOKEN_C} b` } },
    ), state))
    expect(blockText(chunks)).toBe(`a ${TOKEN_C} b`)
  })

  it('is single-pass inside the streaming rewriter', () => {
    const rewriter = new TokenRewriter(new Map([[TOKEN_A, mapping(TOKEN_A, TOKEN_B)], [TOKEN_B, mapping(TOKEN_B, 'deep')]]))
    expect(rewriter.push(TOKEN_A)).toBe(TOKEN_B)
    expect(rewriter.flush()).toBe('')
  })

  it('fails closed when mappings were never published', async () => {
    await expect(collect(restoreChunks(source({ type: 'block-start', index: 0, blockType: 'text' }), createMaskState())))
      .rejects.toMatchObject({ code: 'PRIVACY_MASK_NOT_PUBLISHED' })
  })

  it('rejects a duplicate publication', () => {
    const state = createMaskState()
    state.publish([])
    expect(() => state.publish([])).toThrow()
  })
})

describe('tool arguments', () => {
  const toolEnd = (name: string, args: unknown): StreamChunk => ({
    type: 'block-end',
    index: 1,
    block: { type: 'tool-call', id: 'call-1' as never, name, arguments: JSON.stringify(args) },
  })

  it('suppresses deltas and restores every tool, including bash', async () => {
    const state = published([mapping(TOKEN_A, 'secret')])
    const chunks = await collect(restoreChunks(source(
      { type: 'block-start', index: 1, blockType: 'tool-call' },
      { type: 'tool-call-delta', index: 1, id: 'call-1' as never, name: 'bash', argumentsDelta: '{"command":"echo ' },
      toolEnd('bash', { command: `echo ${TOKEN_A}` }),
    ), state))
    expect(chunks.some((chunk) => chunk.type === 'tool-call-delta')).toBe(false)
    const end = chunks.at(-1)
    if (end?.type !== 'block-end' || end.block.type !== 'tool-call') throw new Error('unreachable')
    expect(JSON.parse(end.block.arguments)).toEqual({ command: 'echo secret' })
  })

  it('fails a patterned token this request did not map', async () => {
    const state = published([mapping(TOKEN_A, 'secret')])
    await expect(collect(restoreChunks(source(toolEnd('bash', { command: `echo ${TOKEN_C}` })), state)))
      .rejects.toMatchObject({ code: 'PRIVACY_UNKNOWN_TOKEN' })
  })

  it('restores an exact numeric token as a number and an embedded one as text', async () => {
    const state = published([mapping(TOKEN_N, '123', 'number')])
    const chunks = await collect(restoreChunks(source(toolEnd('write', { count: TOKEN_N, label: `id-${TOKEN_N}` })), state))
    const end = chunks.at(-1)
    if (end?.type !== 'block-end' || end.block.type !== 'tool-call') throw new Error('unreachable')
    const args = JSON.parse(end.block.arguments) as { count: unknown; label: unknown }
    expect(args).toEqual({ count: 123, label: 'id-123' })
    expect(typeof args.count).toBe('number')
    expect(typeof args.label).toBe('string')
  })

  it('emits exact numeric literals without precision loss', async () => {
    const literals = ['9007199254740993', '0.123456789012345678901234567890', '-0', '1e3', '1E+3', '123.4500']
    for (const literal of literals) {
      const state = published([mapping(TOKEN_N, literal, 'number')])
      const chunks = await collect(restoreChunks(source(toolEnd('write', { n: TOKEN_N })), state))
      const end = chunks.at(-1)
      if (end?.type !== 'block-end' || end.block.type !== 'tool-call') throw new Error('unreachable')
      expect(end.block.arguments).toBe(`{"n":${literal}}`)
    }
  })

  it('accepts a numeric mapping beyond MAX_SAFE_INTEGER', () => {
    const parsed = parseMaskResponse({
      version: 1,
      payload: {},
      mappings: [{ token: TOKEN_N, original: '9007199254740993', originalType: 'number' }],
      uninspectedMedia: false,
    })
    expect(parsed.mappings).toHaveLength(1)
  })

  it('rejects a numeric original outside strict JSON number grammar', () => {
    for (const literal of ['01', '+1', '.5', '5.', 'NaN', 'Infinity', '1;2', '{"a":1}']) {
      expect(() => parseMaskResponse({
        version: 1,
        payload: {},
        mappings: [{ token: TOKEN_N, original: literal, originalType: 'number' }],
        uninspectedMedia: false,
      })).toThrow()
    }
  })

  it('fails closed on unparseable arguments carrying a token', async () => {
    const state = published([mapping(TOKEN_A, 'secret')])
    const bad: StreamChunk = { type: 'block-end', index: 1, block: { type: 'tool-call', id: 'call-1' as never, name: 'write', arguments: `not json ${TOKEN_A}` } }
    await expect(collect(restoreChunks(source(bad), state))).rejects.toMatchObject({ code: 'PRIVACY_TOOL_ARGUMENTS_INVALID' })
  })

  it('never rewrites finish.replayState', async () => {
    const state = published([mapping(TOKEN_A, 'secret')])
    const finish: StreamChunk = { type: 'finish', reason: { kind: 'stop' }, replayState: { response: TOKEN_A } }
    expect(await collect(restoreChunks(source(finish), state))).toEqual([finish])
  })
})

describe('scope registry', () => {
  it('keeps one scope per session and separates sessions', () => {
    const registry = createScopeRegistry(8)
    const first = registry.acquire('session-a')
    const again = registry.acquire('session-a')
    expect(again.scope).toBe(first.scope)
    first.release()
    again.release()
    const other = registry.acquire('session-b')
    expect(other.scope).not.toBe(first.scope)
    other.release()
  })

  it('isolates an empty session id per request', () => {
    const registry = createScopeRegistry(8)
    const first = registry.acquire('')
    const second = registry.acquire('')
    expect(first.scope).not.toBe(second.scope)
    expect(first.scope).toMatch(/^[0-9a-f]{32}$/)
  })

  it('never evicts an active scope and fails typed at capacity', () => {
    const registry = createScopeRegistry(1)
    const active = registry.acquire('session-a')
    expect(codeOf(() => registry.acquire('session-b'))).toBe('PRIVACY_SCOPE_CAPACITY')
    active.release()
    const next = registry.acquire('session-b')
    expect(next.scope).not.toBe(active.scope)
    next.release()
  })
})

describe('strict daemon contract', () => {
  const valid = { version: 1, payload: { ok: true }, mappings: [{ token: TOKEN_A, original: 'secret' }], uninspectedMedia: false }

  it('accepts the versioned envelope', () => {
    expect(parseMaskResponse(valid)).toEqual({ payload: { ok: true }, mappings: [{ token: TOKEN_A, original: 'secret' }], uninspectedMedia: false })
  })

  it('rejects unknown fields, versions, tokens, duplicates, and a missing media flag', () => {
    expect(() => parseMaskResponse({ ...valid, extra: 1 })).toThrow()
    expect(() => parseMaskResponse({ ...valid, version: 2 })).toThrow()
    expect(() => parseMaskResponse({ ...valid, mappings: [{ token: 'bad', original: 'x' }] })).toThrow()
    expect(() => parseMaskResponse({ ...valid, mappings: [{ token: TOKEN_A, original: 'x' }, { token: TOKEN_A, original: 'y' }] })).toThrow()
    expect(() => parseMaskResponse({ ...valid, uninspectedMedia: 'no' })).toThrow()
    expect(() => parseMaskResponse({ ...valid, mappings: [{ token: TOKEN_A, original: 'x', kind: 'number' }] })).toThrow()
  })
})

describe.skipIf(!posix)('http client', () => {
  it('posts the versioned scope envelope, keeps the scope, and authenticates', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'privacy-client-'))
    const keyFile = join(dir, 'client-key')
    await writeFile(keyFile, 'local-key\n', { mode: 0o600 })
    await chmod(keyFile, 0o600)
    const bodies: Array<Record<string, unknown>> = []
    const headers: Array<Record<string, string>> = []
    vi.stubGlobal('fetch', vi.fn(async (_input: unknown, init?: RequestInit) => {
      bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>)
      headers.push(init?.headers as Record<string, string>)
      return new Response(JSON.stringify({ version: 1, payload: { masked: true }, mappings: [], uninspectedMedia: false }), { status: 200 })
    }))
    try {
      const client = createHttpPrivacyClient({ endpoint: 'http://127.0.0.1:8788', apiKeyFile: keyFile, timeoutMs: 1000 })
      const first = await client.mask({ a: 1 }, { provider: 'p', model: 'm', sessionId: 'session-a' })
      const second = await client.mask({ a: 2 }, { provider: 'p', model: 'm', sessionId: 'session-a' })
      expect(first).toEqual({ payload: { masked: true }, mappings: [], uninspectedMedia: false })
      expect(bodies[0]).toMatchObject({ version: 1, payload: { a: 1 } })
      expect(String(bodies[0]?.scope)).toMatch(/^[0-9a-f]{32}$/)
      expect(bodies[1]?.scope).toBe(bodies[0]?.scope)
      expect(headers[0]?.authorization).toBe('Bearer local-key')
      expect(second.payload).toEqual({ masked: true })
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('refuses a missing key file before any request', () => {
    expect(codeOf(() => createHttpPrivacyClient({ endpoint: 'http://127.0.0.1:8788', apiKeyFile: '/definitely/missing', timeoutMs: 1000 })))
      .toBe('PRIVACY_CONFIG')
  })
})

describe('configuration', () => {
  it('ships disabled with loopback defaults and no credential', () => {
    const config = PlainConfig({})
    expect(config.privacyEnabled).toBe(false)
    expect(config.privacyEndpoint).toBe('http://127.0.0.1:8788')
    expect(config.privacyKeyFile).toBe('')
    expect(config.privacyTimeoutMs).toBe(15_000)
  })
})

describe('adapter wiring', () => {
  it('refuses to stream when privacy is enabled without a client', async () => {
    const gateway = await mockGateway({ status: 200, body: listingBody(fullLiveListing()) })
    const adapter = new OpencodeGoAdapter({
      config: () => configOf(gateway.url, { privacyEnabled: true }),
      resolveApiKey: () => Promise.resolve('test-key'),
    })
    await expect(collect(adapter.stream(requestOf()))).rejects.toMatchObject({ code: 'PRIVACY_SERVICE_UNAVAILABLE' })
    expect(gateway.paths).not.toContain('/chat/completions')
  })

  it('masks the wire body, restores the block end, and leaves the request untouched', async () => {
    const gateway = await mockGateway({ status: 200, body: listingBody(fullLiveListing()) })
    gateway.pushCompletions({ events: tokenEvents(TOKEN_A) })
    const calls: string[] = []
    const client: PrivacyMaskClient = {
      async mask(payload, meta) {
        calls.push(meta.sessionId)
        const wire = JSON.stringify(payload).replaceAll('hunter2', TOKEN_A)
        return { payload: JSON.parse(wire), mappings: [mapping(TOKEN_A, 'hunter2')], uninspectedMedia: false }
      },
    }
    const adapter = new OpencodeGoAdapter({
      config: () => configOf(gateway.url, { privacyEnabled: true }),
      resolveApiKey: () => Promise.resolve('test-key'),
      privacy: client,
    })
    const options = requestOf({
      sessionId: 'session-a' as never,
      messages: [createUserMessage({ content: [{ type: 'text', text: 'say hunter2' }], source: { kind: 'plugin', plugin: 'test' } })],
    })
    const before = JSON.stringify(options)
    const chunks = await collect(adapter.stream(options))

    expect(calls).toEqual(['session-a'])
    const wire = JSON.stringify(gateway.bodies.at(-1))
    expect(wire).toContain(TOKEN_A)
    expect(wire).not.toContain('hunter2')
    expect(blockText(chunks)).toBe('hunter2')
    expect(JSON.stringify(options)).toBe(before)
  })

  it('keeps two sessions on their own mappings', async () => {
    const gateway = await mockGateway({ status: 200, body: listingBody(fullLiveListing()) })
    gateway.pushCompletions({ events: tokenEvents(TOKEN_A) })
    gateway.pushCompletions({ events: tokenEvents(TOKEN_B) })
    const client: PrivacyMaskClient = {
      async mask(payload, meta) {
        const [token, original] = meta.sessionId === 'session-a' ? [TOKEN_A, 'secret-a'] : [TOKEN_B, 'secret-b']
        return { payload, mappings: [mapping(token, original)], uninspectedMedia: false }
      },
    }
    const adapter = new OpencodeGoAdapter({
      config: () => configOf(gateway.url, { privacyEnabled: true }),
      resolveApiKey: () => Promise.resolve('test-key'),
      privacy: client,
    })
    const first = await collect(adapter.stream(requestOf({ sessionId: 'session-a' as never })))
    const second = await collect(adapter.stream(requestOf({ sessionId: 'session-b' as never })))
    expect(blockText(first)).toBe('secret-a')
    expect(blockText(second)).toBe('secret-b')
  })
})

describe.skipIf(!posix)('credential file', () => {
  it('reads an owner-only 0600 regular file', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'privacy-key-'))
    const file = join(dir, 'client-key')
    await writeFile(file, 'token\n', { mode: 0o600 })
    await chmod(file, 0o600)
    try {
      expect(readPrivacyKey(file)).toBe('token')
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('refuses a symlink, a group-readable file, and a missing file', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'privacy-key-'))
    const real = join(dir, 'real-key')
    const link = join(dir, 'link-key')
    await writeFile(real, 'token\n', { mode: 0o600 })
    await chmod(real, 0o600)
    await symlink(real, link)
    try {
      expect(codeOf(() => readPrivacyKey(link))).toBe('PRIVACY_CONFIG')
      await chmod(real, 0o644)
      expect(codeOf(() => readPrivacyKey(real))).toBe('PRIVACY_CONFIG')
      expect(codeOf(() => readPrivacyKey(join(dir, 'missing')))).toBe('PRIVACY_CONFIG')
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})

describe('route scope', () => {
  it('leaves the free route unchanged when privacy is enabled', async () => {
    const gateway = await mockGateway({ status: 200, body: listingBody(['beam-free']) })
    gateway.pushCompletions({ events: textEvents })
    const client: PrivacyMaskClient = {
      async mask() {
        throw new Error('the free route must never call the privacy client')
      },
    }
    const adapter = new OpencodeGoAdapter({
      source: 'free',
      config: () => configOf(gateway.url, { privacyEnabled: true, freeBaseURL: gateway.url }),
      resolveApiKey: () => Promise.resolve('public'),
      privacy: client,
    })
    const chunks = await collect(adapter.stream(requestOf({ provider: 'dsh-opencode-free' as never, model: 'beam-free' })))
    expect(chunks.at(-1)).toMatchObject({ type: 'finish', reason: { kind: 'stop' } })
  })
})
