import { describe, expect, it, vi } from 'vitest'
import {
  QUOTA_FRESH_MS,
  QUOTA_REFRESH_MS,
  QuotaLedger,
  planAccountOrder,
  quotaReading,
  type QuotaReading,
} from '../src/quota-plan.ts'
import type { GoUsage } from '../src/contracts.ts'

const NOW = Date.parse('2026-11-26T12:00:00.000Z')
const DAY = 24 * 60 * 60_000

const usageOf = (monthlyPercent: number, resetsInMs: number, now = NOW): GoUsage => ({
  rolling: { status: 'ok', percent: 0, resetsAt: new Date(now + 60 * 60_000).toISOString() },
  weekly: { status: 'ok', percent: 0, resetsAt: new Date(now + 3 * DAY).toISOString() },
  monthly: { status: 'ok', percent: monthlyPercent, resetsAt: new Date(now + resetsInMs).toISOString() },
})

const readingOf = (monthlyPercent: number, resetsInMs: number, at = NOW): QuotaReading =>
  quotaReading(usageOf(monthlyPercent, resetsInMs, at), at)

describe('quota reading', () => {
  it('turns the used percentage into the remaining share and keeps the refill time', () => {
    expect(readingOf(80, 10 * DAY)).toEqual({ remaining: 0.2, resetsAt: NOW + 10 * DAY, at: NOW })
  })

  it('treats a rate-limited or fully spent month as empty', () => {
    const limited: GoUsage = { ...usageOf(10, 10 * DAY), monthly: { status: 'rate-limited', percent: 10,
      resetsAt: new Date(NOW + DAY).toISOString() } }
    expect(quotaReading(limited, NOW).remaining).toBe(0)
    expect(readingOf(100, DAY).remaining).toBe(0)
  })
})

describe('quota-aware rotation', () => {
  const plan = (refs: string[], quota: Map<string, QuotaReading>) => planAccountOrder({ refs, quota, nowMs: NOW })

  it('keeps the rotation while an account has no reading', () => {
    expect(plan(['A', 'B'], new Map([['A', readingOf(20, 20 * DAY)]]))).toEqual(['A', 'B'])
  })

  it('keeps the rotation when readings are stale', () => {
    const stale = new Map<string, QuotaReading>([
      ['A', readingOf(20, 20 * DAY, NOW - QUOTA_FRESH_MS - 1)],
      ['B', readingOf(60, 20 * DAY, NOW - QUOTA_FRESH_MS - 1)],
    ])
    expect(plan(['A', 'B'], stale)).toEqual(['A', 'B'])
  })

  it('starts on the account that still holds more of its month', () => {
    const quota = new Map<string, QuotaReading>([['A', readingOf(80, 20 * DAY)], ['B', readingOf(40, 20 * DAY)]])
    expect(plan(['A', 'B'], quota)).toEqual(['B', 'A'])
  })

  it('leaves nearly equal accounts to the rotation', () => {
    const quota = new Map<string, QuotaReading>([['A', readingOf(40, 20 * DAY)], ['B', readingOf(50, 20 * DAY)]])
    expect(plan(['A', 'B'], quota)).toEqual(['A', 'B'])
  })

  it('spends allowance that refills soon before allowance that lasts', () => {
    const quota = new Map<string, QuotaReading>([['A', readingOf(80, 2 * DAY)], ['B', readingOf(40, 25 * DAY)]])
    expect(plan(['A', 'B'], quota)).toEqual(['A', 'B'])
    expect(plan(['B', 'A'], quota)).toEqual(['A', 'B'])
  })

  it('promotes a healthy remainder when its refill is within a week', () => {
    const quota = new Map<string, QuotaReading>([['A', readingOf(80, 6 * DAY)], ['B', readingOf(40, 25 * DAY)]])
    expect(plan(['A', 'B'], quota)).toEqual(['A', 'B'])
  })

  it('waits for the three-day window before spending a small remainder', () => {
    const quota = new Map<string, QuotaReading>([['A', readingOf(90, 5 * DAY)], ['B', readingOf(80, 25 * DAY)]])
    expect(plan(['A', 'B'], quota)).toEqual(['A', 'B'])
  })

  it('still spends a small remainder once its refill is within three days', () => {
    const quota = new Map<string, QuotaReading>([['A', readingOf(90, 2 * DAY)], ['B', readingOf(80, 25 * DAY)]])
    // The rotation picks B and B leads by only 10 points, so without the
    // three-day rule the start would stay on B.
    expect(plan(['B', 'A'], quota)).toEqual(['A', 'B'])
  })

  it('holds back an account that is nearly empty', () => {
    const quota = new Map<string, QuotaReading>([['A', readingOf(98, 20 * DAY)], ['B', readingOf(99, 20 * DAY)],
      ['C', readingOf(50, 20 * DAY)]])
    expect(plan(['A', 'B', 'C'], quota)).toEqual(['C', 'A', 'B'])
  })

  it('keeps the rotation when every account is nearly empty', () => {
    const quota = new Map<string, QuotaReading>([['A', readingOf(99, 20 * DAY)], ['B', readingOf(98, 20 * DAY)]])
    expect(plan(['A', 'B'], quota)).toEqual(['A', 'B'])
  })

  it('keeps the rotation when it already starts on the fullest account', () => {
    const quota = new Map<string, QuotaReading>([['A', readingOf(20, 20 * DAY)], ['B', readingOf(90, 20 * DAY)]])
    expect(plan(['A', 'B'], quota)).toEqual(['A', 'B'])
  })

  it('does nothing for a single account', () => {
    expect(plan(['A'], new Map([['A', readingOf(20, 20 * DAY)]]))).toEqual(['A'])
  })
})

describe('quota ledger', () => {
  const settle = async (): Promise<void> => { await new Promise(resolve => setImmediate(resolve)) }

  it('records readings and refreshes stale accounts in the background', async () => {
    let now = NOW
    const read = vi.fn(async (ref: string) => usageOf(ref === 'A' ? 20 : 60, 20 * DAY, now))
    const ledger = new QuotaLedger(read, () => now)
    ledger.record('A', usageOf(80, 20 * DAY, now))
    expect(ledger.snapshot().get('A')?.remaining).toBeCloseTo(0.2)
    ledger.refresh(['A', 'B'])
    // A is fresh, so only B is fetched; routing never waits for the result.
    expect(read).toHaveBeenCalledTimes(1)
    expect(read).toHaveBeenCalledWith('B')
    await settle()
    expect(ledger.snapshot().get('B')?.remaining).toBeCloseTo(0.4)
    now += QUOTA_REFRESH_MS
    ledger.refresh(['A', 'B'])
    // Both readings aged past the refresh interval, so both are read again.
    expect(read).toHaveBeenCalledTimes(3)
    expect(read).toHaveBeenLastCalledWith('B')
    await settle()
  })

  it('retries a failed read only after the refresh interval', async () => {
    let now = NOW
    const read = vi.fn(async () => { throw new Error('offline') })
    const ledger = new QuotaLedger(read, () => now)
    ledger.refresh(['A'])
    await settle()
    ledger.refresh(['A'])
    expect(read).toHaveBeenCalledTimes(1)
    now += QUOTA_REFRESH_MS
    ledger.refresh(['A'])
    expect(read).toHaveBeenCalledTimes(2)
    await settle()
    expect(ledger.snapshot().size).toBe(0)
  })
})
