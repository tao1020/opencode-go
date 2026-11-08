import { type StreamChunk } from '@deepseek-ai/dsh-llm';
/** Local daemon the operator runs; never a remote endpoint. */
export declare const DEFAULT_PRIVACY_ENDPOINT = "http://127.0.0.1:8788";
/** Default credential location, derived from the current home directory. */
export declare const DEFAULT_PRIVACY_KEY_FILE: string;
/** Bound on one `/mask` call. */
export declare const DEFAULT_PRIVACY_TIMEOUT_MS = 15000;
/** Contract version this client speaks. */
export declare const PRIVACY_CONTRACT_VERSION = 1;
/** One daemon mapping. `originalType: 'number'` restores an exact numeric JSON value. */
export interface PrivacyMapping {
    token: string;
    original: string;
    originalType?: 'number';
}
export interface PrivacyMaskMeta {
    provider: string;
    model: string;
    sessionId: string;
}
export interface PrivacyMaskResult {
    payload: unknown;
    mappings: readonly PrivacyMapping[];
    uninspectedMedia: boolean;
}
/** What the adapter needs from a mask client. */
export interface PrivacyMaskClient {
    mask(payload: unknown, meta: PrivacyMaskMeta, signal?: AbortSignal): Promise<PrivacyMaskResult>;
}
/** Per-call publication state. One instance per adapter stream call. */
export interface MaskState {
    readonly published: boolean;
    readonly mappings: ReadonlyMap<string, PrivacyMapping>;
    publish(mappings: readonly PrivacyMapping[]): void;
}
/** Create the per-call mask state; mappings publish once, before the first chunk. */
export declare function createMaskState(): MaskState;
/**
 * Session-scoped opaque namespaces, derived from the client key and session ID.
 * Recreating the registry with the same key preserves named scopes. A bounded LRU pins active scopes so one
 * is never replaced underneath a call; at capacity with every scope active it
 * refuses instead of silently re-keying.
 */
export declare function createScopeRegistry(maxScopes?: number, secret?: string | Buffer): {
    acquire(sessionId: string): {
        readonly scope: string;
        release(): void;
    };
};
/**
 * Streaming replacement for text and reasoning deltas. A token can straddle two
 * deltas, so the rewriter keeps a tail of at most one token minus one character.
 * It never rescans text it emitted.
 */
export declare class TokenRewriter {
    private readonly mappings;
    private buffer;
    constructor(mappings: ReadonlyMap<string, PrivacyMapping>);
    push(text: string): string;
    flush(): string;
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
export declare function restoreChunks(source: AsyncIterable<StreamChunk>, state: MaskState, failure?: () => unknown): AsyncGenerator<StreamChunk>;
/**
 * Strict response validator. Unknown fields, a wrong version, a malformed or
 * duplicate token, an unsafe numeric original, or a non-boolean media flag
 * reject the whole response.
 */
export declare function parseMaskResponse(value: unknown): PrivacyMaskResult;
/** Accept only a loopback HTTP origin for the daemon. */
export declare function assertPrivacyEndpoint(raw: string): string;
/**
 * Read the local daemon credential once.
 *
 * Refuses a symlink, requires an owner-only 0600 regular file owned by the
 * current user, and re-checks the opened descriptor so a swap between the path
 * check and the open cannot substitute another file.
 */
export declare function readPrivacyKey(file: string): string;
export interface PrivacyClientConfig {
    endpoint: string;
    apiKeyFile: string;
    timeoutMs: number;
}
/**
 * Build the HTTP client. The scope registry is process-local and bounded; no
 * mapping or key is persisted anywhere.
 */
export declare function createHttpPrivacyClient(config: PrivacyClientConfig): PrivacyMaskClient;
