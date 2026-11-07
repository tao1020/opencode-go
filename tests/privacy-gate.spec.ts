import { afterEach, describe, expect, it, vi } from 'vitest'
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { StreamChunk } from '@deepseek-ai/dsh-llm'
import { OpencodeGoAdapter } from '../src/adapter.ts'
import { validateGoConfig } from '../src/config.ts'
import { createHttpPrivacyClient, createMaskState, restoreChunks, type PrivacyMaskClient } from '../src/privacy.ts'
import { configOf, requestOf } from './support/host.ts'
import { modelsDocument, modelEntry, protocolEntry } from './support/data.ts'
import { fullLiveListing, listingBody, mockGateway, textEvents } from './support/gateway.ts'

const TOKEN_A = `__PG_${'a'.repeat(32)}__`
const posix = process.platform !== 'win32'

async function collect(stream: AsyncIterable<StreamChunk>): Promise<StreamChunk[]> {
  const chunks: StreamChunk[] = []
  for await (const chunk of stream) chunks.push(chunk)
  return chunks
}

async function* source(...chunks: StreamChunk[]): AsyncIterable<StreamChunk> {
  for (const chunk of chunks) yield chunk
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('Flash-only gate', () => {
  it('honors a live disable without invoking the client', async () => {
    const gateway = await mockGateway({ status: 200, body: listingBody(fullLiveListing()) })
    gateway.pushCompletions({ events: textEvents })
    let calls = 0
    const client: PrivacyMaskClient = {
      async mask() {
        calls += 1
        return { payload: {}, mappings: [], uninspectedMedia: false }
      },
    }
    const adapter = new OpencodeGoAdapter({
      config: () => configOf(gateway.url, { privacyEnabled: false }),
      resolveApiKey: () => Promise.resolve('test-key'),
      privacy: client,
    })
    await collect(adapter.stream(requestOf()))
    expect(calls).toBe(0)
  })

  it('leaves a paid non-Flash model unprotected', async () => {
    const gateway = await mockGateway({ status: 200, body: listingBody(fullLiveListing()) })
    gateway.pushCompletions({ events: textEvents })
    let calls = 0
    const client: PrivacyMaskClient = {
      async mask() {
        calls += 1
        throw new Error('non-Flash models must not be masked')
      },
    }
    const adapter = new OpencodeGoAdapter({
      config: () => configOf(gateway.url, { privacyEnabled: true }),
      resolveApiKey: () => Promise.resolve('test-key'),
      privacy: client,
    })
    const chunks = await collect(adapter.stream(requestOf({ model: 'deepseek-v4-pro' })))
    expect(chunks.at(-1)).toMatchObject({ type: 'finish', reason: { kind: 'stop' } })
    expect(calls).toBe(0)
  })

  it('fails a paid Flash model whose catalog protocol is unsupported', async () => {
    const gateway = await mockGateway({
      status: 200,
      body: modelsDocument({
        'deepseek-v4.1-flash': modelEntry({ name: 'DeepSeek V4.1 Flash', family: 'deepseek', api: protocolEntry('messages') }),
      }),
    })
    const adapter = new OpencodeGoAdapter({
      config: () => configOf(gateway.url, { privacyEnabled: true }),
      resolveApiKey: () => Promise.resolve('test-key'),
      privacy: {
        async mask() {
          throw new Error('the client must not run for an unsupported protocol')
        },
      },
    })
    await expect(collect(adapter.stream(requestOf()))).rejects.toMatchObject({ code: 'PRIVACY_UNSUPPORTED_PROTOCOL' })
    expect(gateway.bodies.length).toBe(0)
  })

  it('validates the privacy endpoint only when enabled', () => {
    expect(() => validateGoConfig(configOf('http://127.0.0.1:1', { privacyEnabled: true, privacyEndpoint: 'http://example.com:8788' }))).toThrow()
    expect(() => validateGoConfig(configOf('http://127.0.0.1:1', { privacyEnabled: true, privacyEndpoint: 'http://127.0.0.1:8788' }))).not.toThrow()
    expect(() => validateGoConfig(configOf('http://127.0.0.1:1', { privacyEnabled: false, privacyEndpoint: 'http://example.com:8788' }))).not.toThrow()
  })
})

describe('restore ordering', () => {
  it('flushes held text before the finish chunk', async () => {
    const state = createMaskState()
    state.publish([{ token: TOKEN_A, original: 'secret' }])
    const chunks = await collect(restoreChunks(source(
      { type: 'block-start', index: 0, blockType: 'text' },
      { type: 'text-delta', index: 0, text: `hello ${TOKEN_A.slice(0, 10)}` },
      { type: 'finish', reason: { kind: 'stop' } },
    ), state))
    const finish = chunks.findIndex((chunk) => chunk.type === 'finish')
    expect(finish).toBe(chunks.length - 1)
    const text = chunks.slice(0, finish).filter((chunk) => chunk.type === 'text-delta').map((chunk) => chunk.text).join('')
    expect(text).toBe(`hello ${TOKEN_A.slice(0, 10)}`)
  })

  it('drops held text when the consumer cancels without yielding from cleanup', async () => {
    const state = createMaskState()
    state.publish([{ token: TOKEN_A, original: 'secret' }])
    const seen: StreamChunk[] = []
    for await (const chunk of restoreChunks(source(
      { type: 'block-start', index: 0, blockType: 'text' },
      { type: 'text-delta', index: 0, text: `hello ${TOKEN_A.slice(0, 10)}` },
      { type: 'finish', reason: { kind: 'stop' } },
    ), state)) {
      seen.push(chunk)
      if (chunk.type === 'text-delta') break
    }
    expect(seen.some((chunk) => chunk.type === 'finish')).toBe(false)
  })
})

describe('transport chunking', () => {
  it.skipIf(!posix)('reads a many-chunk response with one abort listener', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'privacy-gate-'))
    const file = join(dir, 'client-key')
    await writeFile(file, 'key\n', { mode: 0o600 })
    await chmod(file, 0o600)
    const body = JSON.stringify({ version: 1, payload: { ok: true }, mappings: [], uninspectedMedia: false })
    const parts = (body.match(/[\s\S]{1,4}/g) ?? []).map((part) => new TextEncoder().encode(part))
    vi.stubGlobal('fetch', async () => new Response(new ReadableStream<Uint8Array>({
      start(controller) {
        for (const part of parts) controller.enqueue(part)
        controller.close()
      },
    }), { status: 200 }))
    try {
      const client = createHttpPrivacyClient({ endpoint: 'http://127.0.0.1:8788', apiKeyFile: file, timeoutMs: 15_000 })
      await expect(client.mask({ a: 1 }, { provider: 'p', model: 'm', sessionId: 's' })).resolves.toMatchObject({ payload: { ok: true } })
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})
