/** Quota-aware rotation: spend allowance that expires soon, then the fullest account. */
import { type GoUsage } from './contracts.ts'

/** A reading older than this is not trusted for routing. */
export const QUOTA_FRESH_MS = 15 * 60_000
/** Refresh a reading at most this often; routing never waits for a refresh. */
export const QUOTA_REFRESH_MS = 5 * 60_000
/** Allowance that refills within a week is spent first when this much still remains. */
export const QUOTA_EXPIRING_WEEK_MS = 7 * 24 * 60 * 60_000
export const QUOTA_EXPIRING_WEEK_SHARE = 0.15
/** Closer to the refill, a smaller remainder still justifies spending it first. */
export const QUOTA_EXPIRING_SOON_MS = 3 * 24 * 60 * 60_000
export const QUOTA_EXPIRING_SOON_SHARE = 0.10
/** An account this empty is held back for conversations that are already on it. */
export const QUOTA_LOW = 0.05
/** Only override the rotation when the fuller account leads by this share. */
export const QUOTA_MARGIN = 0.30

export interface QuotaReading {
  /** Spendable share of the monthly allowance, `0..1`. */
  remaining: number
  /** When the monthly allowance refills, in epoch milliseconds. */
  resetsAt: number
  /** When this reading was taken, in epoch milliseconds. */
  at: number
}

/** Reduce an official usage response to the one number routing compares. */
export function quotaReading(usage: GoUsage, at: number): QuotaReading {
  const monthly = usage.monthly
  const limited = monthly.status === 'rate-limited' || monthly.percent >= 100
  const resetsAt = Date.parse(monthly.resetsAt)
  return {
    remaining: limited ? 0 : Math.max(0, 100 - monthly.percent) / 100,
    resetsAt: Number.isFinite(resetsAt) ? resetsAt : at,
    at,
  }
}

/**
 * Order the accounts a new conversation may start on:
 *
 * 1. Allowance that refills within a week while more than
 *    `QUOTA_EXPIRING_WEEK_SHARE` remains, or within three days while at least
 *    `QUOTA_EXPIRING_SOON_SHARE` remains, goes first — soonest refill first,
 *    because unused allowance is lost when the window ends.
 * 2. The rest follow by remaining allowance, fullest first.
 * 3. Accounts below `QUOTA_LOW` sink to the end.
 *
 * The rotation order only changes when the leading account also leads the
 * account the rotation picked by `QUOTA_MARGIN`, so near-equal accounts keep
 * alternating and a conversation does not jump for noise. Fewer than two fresh
 * readings for the whole set keeps the rotation untouched.
 */
export function planAccountOrder(input: {
  refs: readonly string[]
  quota: ReadonlyMap<string, QuotaReading>
  nowMs?: number
}): string[] {
  const { refs, quota, nowMs = Date.now() } = input
  const order = [...refs]
  if (order.length < 2) return order
  const fresh = (ref: string): QuotaReading | undefined => {
    const reading = quota.get(ref)
    return reading !== undefined && nowMs - reading.at <= QUOTA_FRESH_MS ? reading : undefined
  }
  // Partial data would silently favor the accounts that answered: rank only
  // when every account has a recent reading.
  const readings = order.map(ref => fresh(ref))
  if (readings.some(reading => reading === undefined)) return order
  const low = (reading: QuotaReading): boolean => reading.remaining < QUOTA_LOW
  const expiring = (reading: QuotaReading): boolean => {
    const until = reading.resetsAt - nowMs
    if (until <= QUOTA_EXPIRING_SOON_MS) return reading.remaining >= QUOTA_EXPIRING_SOON_SHARE
    return until <= QUOTA_EXPIRING_WEEK_MS && reading.remaining > QUOTA_EXPIRING_WEEK_SHARE
  }
  const ranked = order
    .filter((_, index) => !low(readings[index]!))
    .sort((left, right) => {
      const a = fresh(left)!
      const b = fresh(right)!
      if (expiring(a) !== expiring(b)) return expiring(a) ? -1 : 1
      if (expiring(a) && a.resetsAt !== b.resetsAt) return a.resetsAt - b.resetsAt
      return b.remaining - a.remaining
    })
  if (ranked.length === 0) return order
  const best = ranked[0]!
  if (best === order[0]) return order
  // Keep the rotation's pick unless the fuller account leads it clearly, or the
  // fuller account is about to lose the allowance it still holds.
  if (!expiring(fresh(best)!) && fresh(best)!.remaining - fresh(order[0]!)!.remaining < QUOTA_MARGIN) return order
  for (const ref of order) if (!ranked.includes(ref)) ranked.push(ref)
  return ranked
}

/** Latest official reading per account, fed by every usage fetch the Host makes. */
export class QuotaLedger {
  private readonly readings = new Map<string, QuotaReading>()
  private readonly attempts = new Map<string, number>()

  constructor(private readonly read: (ref: string) => Promise<GoUsage>, private readonly now: () => number = Date.now) {}

  record(ref: string, usage: GoUsage): void {
    this.readings.set(ref, quotaReading(usage, this.now()))
  }

  snapshot(): ReadonlyMap<string, QuotaReading> { return this.readings }

  /** Refresh stale readings in the background; a failing account retries after the interval. */
  refresh(refs: readonly string[]): void {
    const now = this.now()
    for (const ref of refs) {
      const reading = this.readings.get(ref)
      if (reading !== undefined && now - reading.at < QUOTA_REFRESH_MS) continue
      const attempt = this.attempts.get(ref)
      if (attempt !== undefined && now - attempt < QUOTA_REFRESH_MS) continue
      this.attempts.set(ref, now)
      void this.read(ref).then(usage => this.record(ref, usage), () => { /* the next request tries again */ })
    }
  }
}
