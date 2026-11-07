import { afterEach, describe, expect, it, vi } from 'vitest'
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHttpPrivacyClient, readPrivacyKey } from '../src/privacy.ts'

const posix = process.platform !== 'win32'
const KEY = 'local-key'

async function keyFile(): Promise<{ dir: string; file: string }> {
  const dir = await mkdtemp(join(tmpdir(), 'privacy-transport-'))
  const file = join(dir, 'client-key')
  await writeFile(file, `${KEY}\n`, { mode: 0o600 })
  await chmod(file, 0o600)
  return { dir, file }
}

function clientFor(file: string, timeoutMs = 15_000) {
  return createHttpPrivacyClient({ endpoint: 'http://127.0.0.1:8788', apiKeyFile: file, timeoutMs })
}

function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
  return promise.then(() => undefined, (error: { code?: string }) => error.code)
}

function codeOfSync(fn: () => unknown): string | undefined {
  try {
    fn()
  } catch (error) {
    return (error as { code?: string }).code
  }
  return undefined
}

function streamBody(chunks: Uint8Array[], options: { stall?: boolean; close?: boolean; cancel?: () => void } = {}): Response {
  return new Response(new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk)
      if (options.stall !== true && options.close !== false) controller.close()
    },
    cancel() {
      options.cancel?.()
    },
  }), { status: 200 })
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe.skipIf(!posix)('bounded transport', () => {
  it('cancels an oversized chunked response instead of buffering it', async () => {
    const { dir, file } = await keyFile()
    let cancelled = false
    const chunk = new Uint8Array(1024 * 1024)
    vi.stubGlobal('fetch', async () => streamBody(Array.from({ length: 9 }, () => chunk), { close: false, cancel: () => { cancelled = true } }))
    try {
      await expect(codeOf(clientFor(file).mask({ a: 1 }, { provider: 'p', model: 'm', sessionId: 's' })))
        .resolves.toBe('PRIVACY_UNAVAILABLE')
      await new Promise((resolve) => setTimeout(resolve, 0))
      expect(cancelled).toBe(true)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('aborts a server that stalls after headers', async () => {
    const { dir, file } = await keyFile()
    vi.stubGlobal('fetch', async () => streamBody([], { stall: true }))
    try {
      await expect(codeOf(clientFor(file, 1000).mask({ a: 1 }, { provider: 'p', model: 'm', sessionId: 's' })))
        .resolves.toBe('PRIVACY_UNAVAILABLE')
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('propagates a caller cancellation without turning it into a verdict', async () => {
    const { dir, file } = await keyFile()
    vi.stubGlobal('fetch', async () => streamBody([], { stall: true }))
    const controller = new AbortController()
    try {
      const pending = clientFor(file).mask({ a: 1 }, { provider: 'p', model: 'm', sessionId: 's' }, controller.signal)
      setTimeout(() => controller.abort(new Error('cancelled by test')), 50)
      await expect(pending).rejects.toThrow(/cancelled by test/)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('cancels a non-2xx body without draining it', async () => {
    const { dir, file } = await keyFile()
    let cancelled = false
    vi.stubGlobal('fetch', async () => new Response(new ReadableStream<Uint8Array>({
      start() {},
      cancel() { cancelled = true },
    }), { status: 500 }))
    try {
      await expect(codeOf(clientFor(file).mask({ a: 1 }, { provider: 'p', model: 'm', sessionId: 's' })))
        .resolves.toBe('PRIVACY_UNAVAILABLE')
      await new Promise((resolve) => setTimeout(resolve, 0))
      expect(cancelled).toBe(true)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('does not surface a raw local fetch error', async () => {
    const { dir, file } = await keyFile()
    vi.stubGlobal('fetch', async () => {
      throw new Error('socket failed for SuperSecret123!')
    })
    try {
      const error = await clientFor(file).mask({ a: 1 }, { provider: 'p', model: 'm', sessionId: 's' }).then(
        () => undefined,
        (reason: Error) => reason,
      )
      expect(error).toMatchObject({ code: 'PRIVACY_UNAVAILABLE' })
      expect(error?.message).not.toContain('SuperSecret123!')
      expect(error?.message).toBe('privacy daemon request failed')
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})

describe.skipIf(!posix)('key file bounds', () => {
  it('refuses a key file larger than 4 KiB before reading it', async () => {
    const { dir, file } = await keyFile()
    await writeFile(file, 'x'.repeat(5000), { mode: 0o600 })
    await chmod(file, 0o600)
    try {
      expect(codeOfSync(() => readPrivacyKey(file))).toBe('PRIVACY_CONFIG')
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})
