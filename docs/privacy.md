# Privacy transport (OpenCode Go)

Outbound masking for OpenCode Go model requests. Disabled by default.

## Scope: paid Go, Flash, chat-completions only

Masking applies only when all three hold: the paid Go provider, model id
`deepseek-v4.1-flash`, and protocol `openai-completions`. Every other Go model
and the entire free route stay unprotected, even when `privacyEnabled` is true;
there is no automatic switch. The gate uses the resolved provider id, model id,
and protocol, not a name match.

## Enabling and disabling

`privacyEnabled: false` takes effect on the next request: the client is not
invoked and nothing is masked. Enabling privacy, or changing the endpoint, key
path, or timeout, requires a plugin reload. Enabling at runtime without a
reloaded client fails closed with `PRIVACY_SERVICE_UNAVAILABLE` rather than
sending unprotected traffic.

The key-file contract (regular file, no symlink, 0600, owner) is POSIX. Linux
and macOS are supported; Windows tests are skipped explicitly.

## What this protects

Only **detected textual secrets** in the **model-provider request body**.
Before pi-ai sends a request, the adapter posts the serialized body to a local
daemon and sends the daemon's masked payload instead. Detected textual secrets
are replaced; arbitrary or encoded secrets, secrets in opaque provider state,
and image pixels can be missed.

That is the entire guarantee. Do not describe it as a general secret firewall.

## What this does not protect

- **Local tools can still transmit secrets.** Tool arguments are restored to
  their original values so tools behave normally. A restored command can send a
  secret to `gh`, the network, an MCP server, or anywhere else. This module does
  not prevent that and must not be described as preventing it.
- **Images are not scanned.** `uninspectedMedia` is advisory; the request still
  runs. Image pixels are never inspected.
- **Opaque replay state is not readable.** `finish.replayState` is passed
  through untouched, and the next request re-sends it. The daemon cannot read
  encrypted reasoning state, so tokens inside it are not detectable.
- **Semantic correctness.** The model cannot compute over a value it never
  sees (length, hash, substring, comparison), so secret-dependent tasks may
  produce wrong results.
- **Short values and references.** Detected values shorter than four characters
  propagate only to equal whole strings, not substrings inside other text.
  Standard uppercase `$TOKEN` / `${TOKEN}` references are preserved; unusual
  language expressions can be misclassified. Review generated edits as usual.
- **History already sent.** Enabling cannot undo earlier transmission.
  Start a new session if earlier history may contain secrets.
- **Upgrades.** This feature belongs to this fork. Replacing it with an upstream
  build without the feature removes protection; re-verify after upgrades.

## Configuration

| Field | Default | Meaning |
|---|---|---|
| `privacyEnabled` | `false` | Turns the transport on. |
| `privacyEndpoint` | `http://127.0.0.1:8788` | Loopback HTTP origin only. |
| `privacyKeyFile` | `''` | Absolute key-file path; empty uses `~/.local/state/privacy-guard/client-key`. The file must be a regular file, not a symlink, mode 0600, owned by the current user; the opened descriptor is re-checked. |
| `privacyTimeoutMs` | `15000` | Bound on one `/mask` call (1000–60000). |

No credential is stored in configuration. Enabling privacy without a usable key
file fails at plugin load; enabling it without a client fails the request with
`PRIVACY_SERVICE_UNAVAILABLE` rather than sending the original payload.

## Daemon contract

```
POST /mask
{ "version": 1, "scope": "<opaque 32..128>", "payload": <JSON> }

200 { "version": 1,
      "payload": <masked JSON>,
      "mappings": [{ "token": "__PG_<32 hex>__", "original": "...", "originalType": "number"? }],
      "uninspectedMedia": false }
```

- `scope` is a per-session keyed 16-byte hex namespace derived from the local client key and session ID.
  It is never the raw session ID. An empty session ID gets a fresh scope per
  request. A new client with the same key preserves a named session scope.
  Credential mode also derives stable tokens, so original history can rebuild
  the same masked prefix after a daemon restart. Unknown token literals are
  re-masked as opaque values.
- Tokens match `^__PG_[0-9a-f]{32}__$`.
- `originalType: "number"` restores an exact numeric JSON value. On Node
  22.19+/24 the client emits the original literal through `JSON.rawJSON`, so
  integers beyond `MAX_SAFE_INTEGER`, long fractions, `-0`, and exponents keep
  their exact spelling. The literal must match strict JSON number grammar, so
  nothing but a number can be injected. On a runtime without `JSON.rawJSON`,
  only a canonical round-trip is accepted; a literal that would change is
  rejected, never silently rounded.
- The client caps the request and response envelope at 8 MiB including the
  JSON wrapper. Any non-2xx, timeout, oversize body, malformed body, or unknown
  field fails the request closed.
- Failures throw fixed codes with fixed messages only; no payload, token,
  secret, or daemon string is interpolated into an error that an SDK might log.

## Restoration

- Text and reasoning deltas are restored in one pass with a tail buffer, so a
  token split across deltas still resolves. An original that itself contains a
  token is never rescanned.
- Tool-call deltas are suppressed; the authoritative `block-end` carries the
  full arguments and is restored once. `BlockAssembler` replaces the partial
  with that block.
- A patterned token that this request did not map fails with
  `PRIVACY_UNKNOWN_TOKEN` before any tool runs, rather than corrupting a
  command. The daemon's outbound pass makes this a residual invariant: a
  token-shaped string this scope does not own (another scope, an earlier
  process after a restart, or a literal that only looks like a token) is
  masked as an opaque value and restored to its original literal, never to
  another scope's secret. The model therefore never sees a token it cannot
  restore.
- The client still leaves unknown tokens untouched in free text; it never
  guesses them from another session.

## Failure codes

| Code | Meaning |
|---|---|
| `PRIVACY_SERVICE_UNAVAILABLE` | Enabled but no client, or the daemon is unreachable. |
| `PRIVACY_UNAVAILABLE` | Non-2xx, timeout, oversize, or an invalid contract response. |
| `PRIVACY_MASK_NOT_PUBLISHED` | The first chunk arrived before mappings. |
| `PRIVACY_UNKNOWN_TOKEN` | A patterned token not in this request's mappings reached a tool. |
| `PRIVACY_TOOL_ARGUMENTS_INVALID` | Tool arguments carrying a token were not valid JSON. |
| `PRIVACY_INVALID_MAPPING` | Malformed or unsafe mapping data. |
| `PRIVACY_SCOPE_CAPACITY` | Every scope is active; refusing to re-key a session. |

## Manual daemon integration test

The unit suite uses a fake client. The real daemon test is opt-in and skipped
without the environment variable:

```sh
cd privacy-guard && go build -o /tmp/privacy-guard-mac-review .
PRIVACY_GUARD_TEST_BINARY=/tmp/privacy-guard-mac-review npx vitest run tests/privacy-daemon.integration.spec.ts
```

It starts the daemon on a free loopback port with a temporary 0600 key, uses
the real `createHttpPrivacyClient` and a mock gateway, and checks masking,
token stability per session, restoration of an echoed token split across
frames, old-token replay through a fresh client scope, and fail-closed behavior after the daemon is killed. Windows is
skipped because the key-file contract is POSIX.


The Harness headless smoke can also exercise outbound masking and returned text
restoration with a running local daemon and synthetic credentials. Install the
matching Harness CLI locally before running it. The upstream gateway is simulated.

```sh
PRIVACY_SMOKE_ENDPOINT=http://127.0.0.1:8788 \
PRIVACY_SMOKE_KEY_FILE="$HOME/.local/state/privacy-guard/client-key" \
npm run verify:headless
```

A complete token owned by the current scope keeps its mapping even inside a
sensitive field such as `password`. It is never wrapped in a second token.

Detection is heuristic. Passive status prose such as `a token is left untouched` is preserved.
Explicit assignments such as `password="left"`, quoted values, and `token is left`
remain masked. Other ambiguous natural-language statements can still produce
false positives. Old tokens whose vault has been lost restore to their literal
text only. Recovering the original secret requires the original local data.


## Lightweight credential detector

Run the daemon with `GUARD_DETECTOR=credentials` to select the credential-only
regex detector and bounded detection-position cache. The default remains the
legacy Gitleaks detector. The deployment templates select credential mode.
See `privacy-guard/README.md` for Mac/Linux setup and both client routes.

Credential mode covers explicit AK/SK, password and username fields, common
credential formats, authentication headers and URL credentials. It does not
claim general personal-data detection. Every request still applies its current
secret set throughout the payload. The cache never stores masked prefixes.

Text restoration emits ordinary text immediately and buffers only a possible
partial placeholder. Tool arguments are still validated and restored before
execution. No source from the surveyed third-party proxy projects was copied.
