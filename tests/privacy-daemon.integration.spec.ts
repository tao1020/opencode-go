import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { spawn, type ChildProcess } from 'node:child_process'
import { once } from 'node:events'
import { existsSync } from 'node:fs'
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { OpencodeGoAdapter } from '../src/adapter.ts'
import { createHttpPrivacyClient } from '../src/privacy.ts'
import { configOf, requestOf } from './support/host.ts'
import { fullLiveListing, listingBody, mockGateway, textEvents } from './support/gateway.ts'

/**
 * Manual integration against the compiled Go daemon.
 *
 * Set `PRIVACY_GUARD_TEST_BINARY` to an absolute binary path. Without it the
 * suite is skipped, so CI unit runs are unaffected. Windows is skipped: the
 * daemon's key-file contract is POSIX (0600, owner, non-symlink).
 */
const binary = process.env.PRIVACY_GUARD_TEST_BINARY
const enabled = binary !== undefined && existsSync(binary) && process.platform !== 'win32'
const describeIntegration = enabled ? describe : describe.skip

const SECRET = 'SuperSecret123!'
const TOKEN = /__PG_[0-9a-f]{32}__/

async function collect(stream: AsyncIterable<import('@deepseek-ai/dsh-llm').StreamChunk>) {
  const chunks: import('@deepseek-ai/dsh-llm').StreamChunk[] = []
  for await (const chunk of stream) chunks.push(chunk)
  return chunks
}

async function freePort(): Promise<number> {
  return await new Promise((resolve, reject) => {
    const server = createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      if (address === null || typeof address === 'string') {
        server.close()
        reject(new Error('no port'))
        return
      }
      const { port } = address
      server.close(() => resolve(port))
    })
  })
}

async function waitHealthy(endpoint: string): Promise<void> {
  const signal = AbortSignal.timeout(10_000)
  for (;;) {
    signal.throwIfAborted()
    try {
      const response = await fetch(`${endpoint}/healthz`, { signal })
      if (response.ok) return
    } catch {
      // Retry until the timeout.
    }
    await new Promise((resolve) => setTimeout(resolve, 50))
  }
}

function toolEvents(args: string, cut1: number, cut2: number): string[] {
  const fragments = [args.slice(0, cut1), args.slice(cut1, cut2), args.slice(cut2)]
  return [
    JSON.stringify({ choices: [{ delta: { role: 'assistant', tool_calls: [{ index: 0, id: 'call_1', type: 'function', function: { name: 'edit', arguments: fragments[0] } }] }, index: 0, finish_reason: null }] }),
    ...fragments.slice(1).map((fragment) => JSON.stringify({ choices: [{ delta: { tool_calls: [{ index: 0, function: { arguments: fragment } }] }, index: 0, finish_reason: null }] })),
    JSON.stringify({ choices: [{ delta: {}, index: 0, finish_reason: 'tool_calls' }], usage: { prompt_tokens: 3, completion_tokens: 1 } }),
    '[DONE]',
  ]
}

describeIntegration('privacy daemon integration (manual)', () => {
  let child: ChildProcess | undefined
  let dir = ''
  let endpoint = ''

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'privacy-daemon-'))
    const keyFile = join(dir, 'client-key')
    await writeFile(keyFile, `${randomBytes(16).toString('hex')}\n`, { mode: 0o600 })
    await chmod(keyFile, 0o600)
    const port = await freePort()
    endpoint = `http://127.0.0.1:${port}`
    child = spawn(binary as string, [], {
      env: { ...process.env, GUARD_LISTEN: `127.0.0.1:${port}`, CLIENT_API_KEY_FILE: keyFile },
      stdio: ['ignore', 'ignore', 'pipe'],
    })
    let stderr = ''
    child.stderr?.on('data', (chunk) => { stderr += String(chunk) })
    const exited = once(child, 'exit').then(() => {
      throw new Error(`privacy daemon exited before health: ${stderr.slice(-500)}`)
    })
    await Promise.race([waitHealthy(endpoint), exited])
  }, 30_000)

  afterAll(async () => {
    if (child !== undefined && child.exitCode === null) {
      child.kill('SIGTERM')
      await Promise.race([once(child, 'exit'), new Promise((resolve) => setTimeout(resolve, 2000))])
      if (child.exitCode === null) child.kill('SIGKILL')
    }
    if (dir.length > 0) await rm(dir, { recursive: true, force: true })
  })

  it('masks outbound, restores an echoed token split across frames, and stays stable per session', async () => {
    const gateway = await mockGateway({ status: 200, body: listingBody(fullLiveListing()) })
    gateway.pushCompletions({ events: textEvents })
    const client = createHttpPrivacyClient({ endpoint, apiKeyFile: join(dir, 'client-key'), timeoutMs: 15_000 })
    const adapter = new OpencodeGoAdapter({
      config: () => configOf(gateway.url, { privacyEnabled: true }),
      resolveApiKey: () => Promise.resolve('test-key'),
      privacy: client,
    })
    const options = requestOf({
      sessionId: 'session-a' as never,
      messages: [createUserMessage({ content: [{ type: 'text', text: `database password="${SECRET}"` }], source: { kind: 'plugin', plugin: 'test' } })],
    })
    const before = JSON.stringify(options)

    await collect(adapter.stream(options))
    expect(JSON.stringify(options)).toBe(before)
    const first = JSON.stringify(gateway.bodies[0])
    expect(first).not.toContain(SECRET)
    const token = TOKEN.exec(first)?.[0]
    expect(token).toBeDefined()

    const args = JSON.stringify({ old: `password="${token}"`, new: `password="${token}"\n# rotated` })
    const cut = args.indexOf(token as string)
    gateway.pushCompletions({ events: toolEvents(args, cut + 8, cut + 20) })
    const chunks = await collect(adapter.stream(options))
    const second = JSON.stringify(gateway.bodies[1])
    expect(second).not.toContain(SECRET)
    expect(TOKEN.exec(second)?.[0]).toBe(token)

    const end = chunks.find((chunk) => chunk.type === 'block-end' && chunk.block.type === 'tool-call')
    if (end?.type !== 'block-end' || end.block.type !== 'tool-call') throw new Error('no tool block')
    const restored = JSON.parse(end.block.arguments) as { old: string; new: string }
    expect(restored.old).toBe(`password="${SECRET}"`)
    expect(restored.new).toBe(`password="${SECRET}"\n# rotated`)

    gateway.pushCompletions({ events: textEvents })
    await collect(adapter.stream({ ...options, sessionId: 'session-b' as never }))
    expect(TOKEN.exec(JSON.stringify(gateway.bodies[2]))?.[0]).not.toBe(token)

    // Simulate history from a previous plugin process. The new adapter has a
    // fresh scope and must return the old literal exactly once to the tool.
    const stale = token as string
    const restarted = new OpencodeGoAdapter({
      config: () => configOf(gateway.url, { privacyEnabled: true }),
      resolveApiKey: () => Promise.resolve('test-key'),
      privacy: createHttpPrivacyClient({ endpoint, apiKeyFile: join(dir, 'client-key'), timeoutMs: 15_000 }),
    })
    const replay = {
      ...options,
      messages: [createUserMessage({ content: [{ type: 'text', text: `historical ${stale}` }], source: { kind: 'plugin', plugin: 'test' } })],
    }
    gateway.pushCompletions({ events: textEvents })
    await collect(restarted.stream(replay))
    const remasked = TOKEN.exec(JSON.stringify(gateway.bodies.at(-1)))?.[0]
    expect(remasked).toBeDefined()
    expect(remasked).not.toBe(stale)
    const replayArgs = JSON.stringify({ value: remasked })
    gateway.pushCompletions({ events: toolEvents(replayArgs, 15, 25) })
    const replayChunks = await collect(restarted.stream(replay))
    const replayEnd = replayChunks.find((chunk) => chunk.type === 'block-end' && chunk.block.type === 'tool-call')
    if (replayEnd?.type !== 'block-end' || replayEnd.block.type !== 'tool-call') throw new Error('no replay tool block')
    expect(JSON.parse(replayEnd.block.arguments)).toEqual({ value: stale })

    child?.kill('SIGKILL')
    await once(child as ChildProcess, 'exit')
    const beforeFailure = gateway.bodies.length
    await expect(collect(adapter.stream({ ...options, sessionId: 'session-c' as never }))).rejects.toMatchObject({ code: 'PRIVACY_UNAVAILABLE' })
    expect(gateway.bodies.length).toBe(beforeFailure)
  }, 30_000)
})
