/** Quota-aware rotation: spend allowance that expires soon, then the fullest account. */
import { type GoUsage } from './contracts.ts';
/** A reading older than this is not trusted for routing. */
export declare const QUOTA_FRESH_MS: number;
/** Refresh a reading at most this often; routing never waits for a refresh. */
export declare const QUOTA_REFRESH_MS: number;
/** Allowance that refills within a week is spent first when this much still remains. */
export declare const QUOTA_EXPIRING_WEEK_MS: number;
export declare const QUOTA_EXPIRING_WEEK_SHARE = 0.15;
/** Closer to the refill, a smaller remainder still justifies spending it first. */
export declare const QUOTA_EXPIRING_SOON_MS: number;
export declare const QUOTA_EXPIRING_SOON_SHARE = 0.1;
/** An account this empty is held back for conversations that are already on it. */
export declare const QUOTA_LOW = 0.05;
/** Only override the rotation when the fuller account leads by this share. */
export declare const QUOTA_MARGIN = 0.3;
export interface QuotaReading {
    /** Spendable share of the monthly allowance, `0..1`. */
    remaining: number;
    /** When the monthly allowance refills, in epoch milliseconds. */
    resetsAt: number;
    /** When this reading was taken, in epoch milliseconds. */
    at: number;
}
/** Reduce an official usage response to the one number routing compares. */
export declare function quotaReading(usage: GoUsage, at: number): QuotaReading;
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
export declare function planAccountOrder(input: {
    refs: readonly string[];
    quota: ReadonlyMap<string, QuotaReading>;
    nowMs?: number;
}): string[];
/** Latest official reading per account, fed by every usage fetch the Host makes. */
export declare class QuotaLedger {
    private readonly read;
    private readonly now;
    private readonly readings;
    private readonly attempts;
    constructor(read: (ref: string) => Promise<GoUsage>, now?: () => number);
    record(ref: string, usage: GoUsage): void;
    snapshot(): ReadonlyMap<string, QuotaReading>;
    /** Refresh stale readings in the background; a failing account retries after the interval. */
    refresh(refs: readonly string[]): void;
}
