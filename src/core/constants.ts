/**
 * P3′ payfetch — FROZEN constants (SPEC §15) + guarded asset registry (§3.2).
 *
 * Purpose: the single home for every tunable/frozen value the payer, policy
 * engine, budget ledger, guards, and transport use. Transcribed verbatim from
 * SPEC §15's table — a coder faces zero design decisions here.
 *
 * Invariants:
 *  - Every number/threshold/label the codebase uses is a named constant HERE.
 *    No magic numbers anywhere else (0/1, array indices, and obvious arithmetic
 *    excepted). SPEC §15: "no magic numbers outside constants.ts".
 *  - `CLIENT_VERSION` / `POLICY_VERSION` are stamped onto every receipt (§8.3).
 *    Changing ANY value in this file requires a version bump AND a RESULTS.md
 *    entry (SPEC §15 house rule) — never a silent edit.
 *  - Guarded blocks (KNOWN_ASSETS, P1/P2 base URLs) cite their source; `-- VERIFY`
 *    markers name what must be re-checked at integration before that code path
 *    goes live. Guarded values are LITERALS (P1 KNOWN_HUBS discipline) so a
 *    supply-chain swap is auditable in the diff.
 *  - Exported objects/arrays are `Object.freeze`d / `as const` — a mutated frozen
 *    constant is a silent policy drift.
 *
 * A handful of constants below are NOT in the SPEC §15 policy table but are
 * required, no-magic-number, protocol/plumbing values; each is flagged inline
 * with its provenance (e.g. the wire header names from the pinned
 * @x402/core@2.17.0 client/http modules).
 *
 * WIRE-PARITY WAVE (2026-07-02): re-pinned x402@1.2.0 → @x402/core@2.17.0. The
 * x402 protocol version is now ECHOED from each challenge (§3.1a rule 2) — there
 * is no hardcoded version payload constant; only SUPPORTED_X402_VERSIONS (the
 * accept-set) and NETWORK_ALIASES (CAIP-2 → canonical) are frozen here (§15).
 */

// ---------------------------------------------------------------------------
// Version stamps (SPEC §15 header, §8.3 receipt schema)
// ---------------------------------------------------------------------------

/** Client version stamped on every receipt (`clientVersion`). SPEC §8.3/§15. */
export const CLIENT_VERSION = "p3f-1.0.0";
/** Policy defaults version stamped on every receipt (`policyVersion`). SPEC §8.3/§15.
 *  1.0.0 → 1.1.0 (2026-07-03): the frozen `GUARD_TIMEOUT_MS = 2000` was superseded
 *  by the mode-scoped guard screen budgets below (measured cold-latency fix).
 *  1.1.0 → 1.2.0 (2026-07-03): `GUARD_SCREEN_BUDGET_MS` 8000 → 13000 after the P1
 *  RugCheck-cap follow-up remeasured the capped cold p99 at ~12.7s.
 *  1.2.0 → 1.3.0 (2026-07-03): `GUARD_SCREEN_BUDGET_MS` 13000 → 10000 after the P1
 *  RugCheck double-fetch dedupe dropped the re-measured cold p99 to ~7.0s. See
 *  RESULTS.md 2026-07-03 "P3 guard timeout". §15 house rule: a constants change
 *  carries a version bump + a RESULTS.md entry.
 *  1.3.0 → 1.4.0 (2026-07-03): P3 product review fixes — (a) the non-elicitation
 *  approval path (`approval.preApprovedUpToUsd` / `approval.preApprovedHosts`,
 *  `APPROVAL_PREAPPROVED_UP_TO_DEFAULT_USD`) so a client that cannot elicit can still
 *  transact above threshold via EXPLICIT operator config; (b) the split
 *  `guards.safety.onDegraded` axis (`SAFETY_ON_DEGRADED_DEFAULT`) decoupling the
 *  degrade fail-close from `onUnavailable`. Defaults leave every existing behavior
 *  unchanged (pre-approval OFF: null/[]; onDegraded "block" == prior degrade→
 *  unavailable→block). See RESULTS.md 2026-07-03 "P3 product review".
 *  1.4.0 → 1.5.0 (2026-07-03): `GUARD_SCREEN_BUDGET_MS` 10000 → 13000 — a P1 re-measure
 *  put the v1.3.x-escalated cold p99 back at ~10.7s (quiet Helius), so 10000ms was
 *  cutting real cold escalated screens; 13000ms covers it and the slow-Helius tail
 *  (~29s) fail-closes safely until the P1 S3 registry removes the escalation fan-out.
 *  See RESULTS.md 2026-07-03 "P3 guard budget (v1.3.1)". */
export const POLICY_VERSION = "p3f-policy-1.5.0";

// ---------------------------------------------------------------------------
// Budget caps — defaults (SPEC §15)
// ---------------------------------------------------------------------------

/** Default per-payment ceiling (USD). SPEC §15 `PER_CALL_CAP_DEFAULT_USD`. */
export const PER_CALL_CAP_DEFAULT_USD = 1.0;
/** Default per-UTC-day ceiling (USD) — worst silent day ≤ $2. SPEC §15. */
export const DAILY_CAP_DEFAULT_USD = 2.0;
/** Default per-host-per-day ceiling (USD). SPEC §15. */
export const PER_HOST_DAILY_CAP_DEFAULT_USD = 1.0;
/** Lifetime cap — unset by default (null). SPEC §15 `TOTAL_CAP_DEFAULT_USD`. */
export const TOTAL_CAP_DEFAULT_USD: number | null = null;

// ---------------------------------------------------------------------------
// Approval (SPEC §6, §15)
// ---------------------------------------------------------------------------

/** Above this quote amount (USD, strict) → human approval. SPEC §15. */
export const APPROVAL_THRESHOLD_DEFAULT_USD = 0.1;
/**
 * Non-elicitation pre-approval ceiling (USD) — the P3 review "de-risk the approval
 * UX for non-eliciting clients" fix. `null` (default) ⇒ OFF: no config pre-approval,
 * so an above-threshold payment on a client that cannot elicit is fail-closed exactly
 * as before. When an operator sets it > 0, an above-threshold payment whose amount is
 * ≤ this ceiling is approved via CONFIG (not an impossible in-session dialog) — still
 * bounded by every cap (D7 per-call + D11 reserve) and by the guards (D8, which run
 * BEFORE approval), and NEVER an agent self-approval (config.json is operator-owned;
 * no tool mutates it — the M6 prohibition is untouched). SPEC §6/§15. */
export const APPROVAL_PREAPPROVED_UP_TO_DEFAULT_USD: number | null = null;
/** Elicit wait before `approval_timeout` (seconds). SPEC §15. */
export const APPROVAL_ELICIT_TIMEOUT_S = 120;
/** Queue-mode grant lifetime (seconds). SPEC §15. */
export const APPROVAL_QUEUE_TTL_S = 3_600;

// ---------------------------------------------------------------------------
// Payment execution / EIP-3009 windows (SPEC §2, §5.3, §15)
// ---------------------------------------------------------------------------

/** Frozen: at most one payment attempt per logical request — no retry loop can
 *  drain a wallet. SPEC §5.3/§15 `MAX_PAYMENT_ATTEMPTS_PER_REQUEST`. */
export const MAX_PAYMENT_ATTEMPTS_PER_REQUEST = 1;
/** EIP-3009 `validAfter` backdating (seconds). SPEC §2/§15 `CLOCK_SKEW_S`. */
export const CLOCK_SKEW_S = 600;
/** `validBefore` window when terms advertise no timeout (seconds). SPEC §2/§15. */
export const PAYMENT_VALIDITY_DEFAULT_S = 300;
/** `validBefore` hard ceiling (seconds) — clamps advertised maxTimeoutSeconds. SPEC §2/§15. */
export const PAYMENT_VALIDITY_MAX_S = 600;
/** Hold release grace past validBefore (seconds). SPEC §5.2/§15. */
export const HOLD_RELEASE_MARGIN_S = 60;

// ---------------------------------------------------------------------------
// Per-host auto-deny circuit breaker (SPEC §5.4, §15)
// ---------------------------------------------------------------------------

/** Strikes to auto-deny a host (≥1 must be confirmed-class). SPEC §5.4/§15. */
export const AUTO_DENY_STRIKES = 2;
/** Soft-strike-only (unknown_settlement) auto-deny threshold. SPEC §5.4/§15. */
export const AUTO_DENY_UNKNOWN_ONLY_STRIKES = 4;
/** Strike accumulation window (days). SPEC §15 `AUTO_DENY_WINDOW_DAYS`. */
export const AUTO_DENY_WINDOW_DAYS = 7;
/** Auto-deny duration absent an operator clear (days). SPEC §15 `AUTO_DENY_TTL_DAYS`. */
export const AUTO_DENY_TTL_DAYS = 7;

// ---------------------------------------------------------------------------
// Guards (SPEC §7, §15)
// ---------------------------------------------------------------------------

/**
 * Guard screen budget — the OVERALL time-box a guard's `check()` (upstream screen
 * fetch + parse) may take before the pipeline abandons it as "unavailable". SPEC
 * §7.1/§15 (supersedes the frozen `GUARD_TIMEOUT_MS = 2000`, retired 2026-07-03).
 *
 * Two mode-scoped budgets, because the two guards have opposite latency needs:
 *
 *  - ENFORCE (`GUARD_SCREEN_BUDGET_MS`): the SAFETY guard's primary, confirmed-
 *    blocker case is a cache-cold, FIRST-TOUCH token screen — the exact input on
 *    which a 2000ms box always timed out (fail-closed block-everything, never a
 *    true `danger` detection). Sized to the MEASURED cold P1 screen latency, which
 *    has moved with P1 latency work: n=107 pre-escalation read p99 5.8s (→ 8000ms);
 *    the recall fix (deployer escalation) + RugCheck 4.5s cap remeasured a capped
 *    cold p99 of ~12.7s (→ 13000ms; uncapped it was 26.4s); the P1 RugCheck
 *    DOUBLE-FETCH dedupe then dropped a quiet-Helius cold p99 to ~7.0s (briefly →
 *    10000ms). The v1.3.x recall escalation (S1 create-filter + ALGO-1 aged-cursor
 *    walk + S2 curve batch) fans out more cold Helius work on the escalation class,
 *    and a RE-MEASURE put the escalated cold p99 back at ~10.7s on quiet Helius —
 *    10000ms was cutting real cold escalated screens. 13000ms covers the ~10.7s p99
 *    with margin; the day-variable slow-Helius tail (~29s) fail-closes safely (a SAFE
 *    block, never a wrong verdict) — reinforced by the dim5-MED degraded-screen
 *    fail-close (a capped/absent danger-relevant upstream on an inconclusive verdict
 *    also fails closed). Still < P1's 29s Lambda ceiling and < P3's per-leg
 *    `FETCH_TIMEOUT_MS` (30000). UX TRADEOFF (opt-in gate, flagged in RESULTS.md): a
 *    cold novel escalated screen puts up to ~13s in the payment hot path. Acceptable
 *    for an OPT-IN safety gate; the durable fix that lowers this budget again is the
 *    P1 S3 create-registry (serves the creator/history from precompute and removes
 *    the per-screen escalation fan-out), plus provisioned concurrency.
 *
 *  - ADVISORY (`GUARD_ADVISORY_BUDGET_MS`): a proceed-fast budget, UNCHANGED at
 *    2000ms. An advisory guard (e.g. the default-ON trust guard) downgrades
 *    "unavailable" to a PROCEED — it only ever notes, never blocks — so holding
 *    the payment hot-path for the full enforce budget on every first-touch token,
 *    only to proceed anyway, is a pure default-latency regression with zero safety
 *    benefit. 2000ms keeps the pre-fix default latency; a cold/slow/dead advisory
 *    screen degrades to "unavailable" in ≤2s and the pipeline proceeds. This short
 *    budget IS the "fast no-progress abort" for the default-ON path.
 *
 * A genuinely dead host (connection refused / DNS / reset / network error) is
 * surfaced as "unavailable" the instant `guardFetch` rejects — it NEVER waits out
 * the budget, in either mode (see `guards/internal.ts`). The residual case a
 * short abort cannot help is a BLACKHOLE enforce host (accepts the connection then
 * never answers): on the current all-at-once P1 upstream (API-Gateway/Lambda emits
 * response bytes only AFTER the screen computes) it is indistinguishable from a
 * legitimately-slow cold screen until it answers, so it is bounded by the enforce
 * budget rather than a sub-second abort. A shorter enforce abort would cut real
 * cold screens (the re-measured escalated cold p99 is ~10.7s) and RE-OPEN this blocker; a
 * true short connect/no-progress timeout lands with the P1 latency follow-up
 * (provisioned concurrency + streamed early headers / socket connectTimeout),
 * which will let this budget drop again.
 */
export const GUARD_SCREEN_BUDGET_MS = 13_000;

/** Advisory (proceed-fast) guard budget (ms) — see `GUARD_SCREEN_BUDGET_MS`. SPEC §7.1/§15. */
export const GUARD_ADVISORY_BUDGET_MS = 2_000;

/**
 * The effective overall guard budget for a guard's mode (SPEC §7.1). Enforce gets
 * the generous cold-screen budget so it can actually detect `danger`; advisory
 * proceeds fast. The pipeline (`runGuard`) and the guards' `guardFetchWithTimeout`
 * MUST size their time-box from this single helper so the two layers never drift.
 */
export function guardBudgetMs(mode: "advisory" | "enforce"): number {
  return mode === "enforce" ? GUARD_SCREEN_BUDGET_MS : GUARD_ADVISORY_BUDGET_MS;
}
/** Guard fetches never trigger guards (recursion depth). SPEC §7.2/§15. */
export const GUARD_RECURSION_DEPTH = 0;
/** Guards are free-tier-only by default (USD). SPEC §15 `GUARD_DAILY_BUDGET_DEFAULT_USD`. */
export const GUARD_DAILY_BUDGET_DEFAULT_USD = 0;
/** Strip query strings from guard target URLs (THESIS §9). SPEC §15 `GUARD_SEND_QUERY`. */
export const GUARD_SEND_QUERY = false;
/** P2 trust verdicts that block/warn by default. SPEC §7.2/§15. */
export const TRUST_BLOCK_VERDICTS_DEFAULT: readonly string[] = Object.freeze(["unreliable"]);
/** P1 safety verdicts that block/warn by default. SPEC §7.3/§15. */
export const SAFETY_BLOCK_VERDICTS_DEFAULT: readonly string[] = Object.freeze(["danger"]);
/** P1 deployer verdicts that block/warn (deep tier only). SPEC §7.3/§15. */
export const SAFETY_BLOCK_DEPLOYER_VERDICTS_DEFAULT: readonly string[] = Object.freeze([
  "serial_rugger",
]);
/** Default safety-guard depth — `deep` is always-paid on P1 (review #7). SPEC §15. */
export const SAFETY_GUARD_DEPTH_DEFAULT = "basic" as const;
/**
 * Enforce-mode-only: what the PIPELINE does when the safety guard reports a
 * DEGRADED screen (a danger-relevant upstream capped/absent → an inconclusive
 * verdict that may UNDER-call danger). SPEC §7.3/§15 default `"block"` (fail
 * closed — identical to the prior behavior, where a degrade collapsed into
 * `unavailable` and `onUnavailable: "block"` fired). Split from `onUnavailable`
 * (P3 review §4b) so an operator can soften degrade-block NOISE (`"warn"`/
 * `"proceed"`) WITHOUT also softening a genuinely dead P1 (which stays governed by
 * `onUnavailable`). Only the safety guard emits `degraded` (a P1 basic-screen
 * field); the trust guard has no such axis. */
export const SAFETY_ON_DEGRADED_DEFAULT = "block" as const;

// ---------------------------------------------------------------------------
// Rail / scheme / network support (SPEC §3.2, §15)
// ---------------------------------------------------------------------------

/** Enabled payment rails — MPP is a detection stub. SPEC §2/§15 `RAILS_ENABLED`. */
export const RAILS_ENABLED: readonly ["x402"] = Object.freeze(["x402"]);
/** Supported x402 schemes — `upto` is denied + tallied. SPEC §3.2/§15. */
export const SUPPORTED_SCHEMES: readonly ["exact"] = Object.freeze(["exact"]);
/** Supported networks — `base-sepolia` only in test mode (enforced by pipeline). SPEC §15. */
export const SUPPORTED_NETWORKS: readonly ["base", "base-sepolia"] = Object.freeze([
  "base",
  "base-sepolia",
]);

/** A network we can settle on. SPEC §2 PaymentQuote.network. */
export type SupportedNetwork = (typeof SUPPORTED_NETWORKS)[number];

// ---------------------------------------------------------------------------
// x402 protocol version & network dialect (SPEC §3.1a, §15) — WIRE-PARITY WAVE
// ---------------------------------------------------------------------------

/**
 * x402 wire protocol versions this client accepts. The version is ECHOED from
 * each challenge's `x402Version` into the payment payload — NEVER hardcoded
 * (§3.1a rule 2). A challenge whose version ∉ this set is quote-filter rejected
 * and tallied `unsupported_x402_version`. SPEC §15 `SUPPORTED_X402_VERSIONS`.
 * The pinned @x402/core@2.17.0 emits v2 (`require("@x402/core").x402Version`).
 */
export const SUPPORTED_X402_VERSIONS: readonly number[] = Object.freeze([1, 2]);

/** Is `v` an x402 version we can transact (§3.1a rule 2 filter). */
export function isSupportedX402Version(v: number | null | undefined): boolean {
  return v != null && SUPPORTED_X402_VERSIONS.includes(v);
}

/**
 * CAIP-2 network id → canonical name (§3.1a rule 3 / SPEC §15 `NETWORK_ALIASES`).
 * v2 sellers declare networks as CAIP-2 (`eip155:84532`); v1 sellers use the
 * canonical names directly. We normalize to canonical for ALL policy/asset logic
 * (`PaymentQuote.network`) and for `termsHash` (so v1/v2 dialects of the same
 * terms hash identically), while the payment payload echoes the RAW declared
 * string (`PaymentQuote.networkAsDeclared`) — the seller hears its own dialect.
 * The CAIP-2 chain-ids match CHAIN_ID_BY_CANONICAL below.
 */
export const NETWORK_ALIASES: Readonly<Record<string, SupportedNetwork>> = Object.freeze({
  "eip155:8453": "base",
  "eip155:84532": "base-sepolia",
});

/**
 * Canonical EVM chain id per supported network — the EIP-712 domain `chainId`
 * (SPEC §2, §3.1a rule 6). Source-cited: @x402/core@2.17.0 sibling
 * @x402/evm@2.17.0 `dist/cjs/exact/client/index.js` `EVM_NETWORK_CHAIN_ID_MAP`
 * (`"base-sepolia": 84532`, `base: 8453`); identical to the CAIP-2 ids in
 * NETWORK_ALIASES (`eip155:8453` / `eip155:84532`). We derive chainId from the
 * CANONICAL name so v1 and v2 dialects of the same network sign an identical
 * domain (byte-identical wire).
 */
const CHAIN_ID_BY_CANONICAL: Readonly<Record<SupportedNetwork, number>> = Object.freeze({
  base: 8453,
  "base-sepolia": 84532,
});

/**
 * Normalize a challenge's declared network string to a canonical name (§3.1a
 * rule 3). A CAIP-2 alias maps via NETWORK_ALIASES; an already-canonical name
 * passes through; an unknown string is returned unchanged (and is then rejected
 * as `unsupported_network` by the §3.2 filter — fail closed). Never throws.
 */
export function canonicalNetwork(declared: string | null | undefined): string | null {
  if (declared == null) return null;
  return NETWORK_ALIASES[declared] ?? declared;
}

/**
 * EVM chain id for a CANONICAL network name (`base`/`base-sepolia`), else null.
 * Replaces the pinned package's `getNetworkId` for the EIP-712 domain (§3.1a
 * rule 6); callers pass the normalized `PaymentQuote.network`.
 */
export function chainIdForNetwork(canonical: string | null | undefined): number | null {
  if (canonical == null) return null;
  return CHAIN_ID_BY_CANONICAL[canonical as SupportedNetwork] ?? null;
}

// ---------------------------------------------------------------------------
// Transport (SPEC §11, §15)
// ---------------------------------------------------------------------------

/** Per-request-leg timeout (ms). SPEC §11/§15 `FETCH_TIMEOUT_MS`. */
export const FETCH_TIMEOUT_MS = 30_000;
/** Max redirects followed, each hop re-guarded. SPEC §11/§15 `MAX_REDIRECTS`. */
export const MAX_REDIRECTS = 2;
/** Hard body-read cap (bytes) = 10 MiB. SPEC §11/§15 `RESPONSE_MAX_BYTES`. */
export const RESPONSE_MAX_BYTES = 10_485_760;
/** Inline-mode return cap (bytes) = 100 KiB. SPEC §11/§15 `RESPONSE_INLINE_MAX_BYTES`. */
export const RESPONSE_INLINE_MAX_BYTES = 102_400;

// ---------------------------------------------------------------------------
// Ledger lock (SPEC §8.1, §15)
// ---------------------------------------------------------------------------

/** Lockfile takeover threshold (seconds). SPEC §8.1/§15 `LOCK_STALE_S`. */
export const LOCK_STALE_S = 300;

// ---------------------------------------------------------------------------
// GUARDED CONSTANTS — guard target base URLs (SPEC §15, cross-product fix 3)
// ---------------------------------------------------------------------------
/**
 * ONE live base URL for BOTH guards (SPEC §15 `SCAFFOLD_BASE_URL`): P1 and P2
 * are products on the same scaffold deploy, so the guard targets share a single
 * origin — a stable-domain swap later is this one line. Routes appended by the
 * guards: `/v1/trust/score` (trust, §7.2) and `/v1/safety/screen[/deep]`
 * (safety, §7.3). Operators override per-guard via `opts.guardBaseUrls`
 * (src/index.ts); an override of `null` degrades that guard to `unavailable`
 * (fail-closed per §7.2/§7.3), never a silent proceed.
 *
 * SOURCE (guarded literal, P1 KNOWN_HUBS discipline): the deployed scaffold
 * API-Gateway origin recorded in RESULTS.md (live-eval #1 target
 * `POST {SCAFFOLD_BASE_URL}/v1/hello`).
 */
export const SCAFFOLD_BASE_URL = "https://api.forum-labs.com";

/** P2 trust-guard base (SPEC §7.2) — derived from `SCAFFOLD_BASE_URL`. */
export const P2_TRUST_BASE_URL: string = SCAFFOLD_BASE_URL;
/** P1 safety-guard base (SPEC §7.3) — derived from `SCAFFOLD_BASE_URL`. */
export const P1_SAFETY_BASE_URL: string = SCAFFOLD_BASE_URL;

/**
 * Integration header sent on guard calls (THESIS §7 instrument; one header name
 * scaffold-wide, shared with P1 calls). SPEC §15 `INTEGRATION_HEADER`.
 * Value format (THESIS §7): `payfetch/1;i={installId8}[;via={viaSlug}]`.
 */
export const INTEGRATION_HEADER = "X-P2-Integration";

// ---------------------------------------------------------------------------
// Protocol / plumbing constants — NOT in the SPEC §15 policy table, but named
// here to satisfy the no-magic-number rule. Each cites its provenance.
// ---------------------------------------------------------------------------

/** EIP-3009 authorization nonce length (bytes). deps.random() must return this. SPEC §2. */
export const NONCE_BYTES = 32;

/**
 * x402 wire header names (§3.1a; RESULTS.md wire-parity wave). Source-cited to the
 * pinned @x402/core@2.17.0 (the header literals live inline in
 * `dist/cjs/{client,http,server}/index.js`; the package does not export them as
 * named constants). Used for the PaymentProof header (§2), the challenge/settlement
 * channels (§3.1a rules 1 & 5), and reserved-header hygiene (§11).
 *
 *  - `X_PAYMENT_HEADER` — outgoing header for an x402 v1 payload (v1 HTTP spec).
 *  - `PAYMENT_SIGNATURE_HEADER` — outgoing header for an x402 v2 payload.
 *    `@x402/core` `encodePaymentSignatureHeader` uses this split. The current
 *    resource server reads `PAYMENT-SIGNATURE` only, so a v2 payload in
 *    `X-PAYMENT` never reaches verification.
 *  - `PAYMENT_REQUIRED_HEADER` — the v2-canonical challenge channel (§3.1a rule 1):
 *    a 402's base64 PAYMENT-REQUIRED header IS the challenge; the body is fallback.
 *  - `PAYMENT_RESPONSE_HEADER` / `X_PAYMENT_RESPONSE_HEADER` — the settlement
 *    channel (§3.1a rule 5): parse PAYMENT-RESPONSE first, else the legacy
 *    X-PAYMENT-RESPONSE. Both are base64 JSON.
 */
export const X_PAYMENT_HEADER = "X-PAYMENT";
export const PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE";
export const PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED";
export const PAYMENT_RESPONSE_HEADER = "PAYMENT-RESPONSE";
export const X_PAYMENT_RESPONSE_HEADER = "X-PAYMENT-RESPONSE";

/** Header name for one outgoing payment payload. v1 stays `X-PAYMENT`; v2 uses `PAYMENT-SIGNATURE`. */
export function outgoingPaymentHeader(x402Version: number): string {
  return x402Version === 1 ? X_PAYMENT_HEADER : PAYMENT_SIGNATURE_HEADER;
}

/**
 * Default CDP EVM account name when `PAYFETCH_CDP_ACCOUNT_NAME` is unset (SPEC
 * §12: the env var is optional). A STABLE name is required so the same buyer
 * wallet is resolved across restarts (an unnamed `createAccount` would mint a
 * fresh address each run).
 */
export const DEFAULT_CDP_ACCOUNT_NAME = "payfetch";

// ---------------------------------------------------------------------------
// GUARDED BLOCK — KNOWN_ASSETS (SPEC §3.2, §15)
// ---------------------------------------------------------------------------
/**
 * Payable ERC-20 assets. Membership gates payment (SPEC §3.2: "Paying in unknown
 * assets is refused, always" — amountUsd must be derivable or budgets are
 * unenforceable) and drives `amountUsd = atomic / 10^decimals`.
 *
 * VALUE-IDENTITY REQUIREMENT (SPEC §1): this set MUST stay value-identical to P2
 * `KNOWN_USDC_ASSETS` until the shared parse402/X402Terms module is lifted to the
 * scaffold. P2 source of record: products/p2_trust/prober/src/constants.ts
 * (KNOWN_USDC_ASSETS) — same two addresses, same order.
 *
 * SOURCES (public, source-cited per P1 KNOWN_HUBS discipline):
 *  - Base mainnet USDC (Circle):  0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
 *    (SPEC §3.2 pins this literal; 6 decimals.)
 *  - Base Sepolia testnet USDC:   0x036CbD53842c5426634e7929541eC2318f3dCF7e
 *    RESOLVED from the installed x402 package's asset config (SPEC §15 asked to
 *    resolve this at integration): x402@1.2.0 →
 *    node_modules/x402/dist/cjs/shared/evm/index.js `config["84532"].usdcAddress`
 *    (also exposed as `require("x402/types").evm.config["84532"].usdcAddress`).
 *    Matches Circle's published Base Sepolia USDC and P2's KNOWN_USDC_ASSETS.
 *
 * -- VERIFY at integration: confirm both addresses against Circle's published
 *    USDC list and a live Bazaar 402 `asset` field before real money moves.
 *    Mislabeling here only ever DENIES (fail-closed): a non-matching asset yields
 *    amountUsd null and is rejected as `unknown_asset`, never overpaid.
 *
 * All v1 assets are USDC with 6 decimals; USDC ≡ $1.00 (limitation SPEC §16.1).
 */
export const USDC_DECIMALS = 6;

/** One payable asset's guarded record (checksummed address as source-cited). */
export type KnownAsset = {
  readonly address: string; // checksummed, as source-cited
  readonly decimals: number;
  readonly network: SupportedNetwork;
  readonly label: string;
};

export const KNOWN_ASSETS: readonly KnownAsset[] = Object.freeze([
  Object.freeze({
    address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // Base mainnet USDC   -- VERIFY
    decimals: USDC_DECIMALS,
    network: "base" as const,
    label: "USDC (Base)",
  }),
  Object.freeze({
    address: "0x036CbD53842c5426634e7929541eC2318f3dCF7e", // Base Sepolia USDC   -- VERIFY
    decimals: USDC_DECIMALS,
    network: "base-sepolia" as const,
    label: "USDC (Base Sepolia)",
  }),
]);

/** address(lowercased) → decimals, for O(1) case-insensitive membership + derivation. */
const KNOWN_ASSET_DECIMALS_BY_LOWER: ReadonlyMap<string, number> = new Map(
  KNOWN_ASSETS.map((a) => [a.address.toLowerCase(), a.decimals]),
);

/** address(lowercased) → its canonical network, for the asset⇄network coherence check (SPEC §3.2, fix L4). */
const KNOWN_ASSET_NETWORK_BY_LOWER: ReadonlyMap<string, SupportedNetwork> = new Map(
  KNOWN_ASSETS.map((a) => [a.address.toLowerCase(), a.network]),
);

/**
 * Case-insensitive membership test for KNOWN_ASSETS. SPEC §3.2 quote filter.
 * This stays a PURE membership test: the asset and network checks remain
 * independent set-membership conjuncts, so this does NOT itself require
 * asset⇄network pairing. The SEPARATE coherence check — a KNOWN asset must
 * settle on the network it was advertised with — is layered on top in
 * `rejectReason` (x402.ts) via `knownAssetNetwork` (SPEC §3.2 hardening, fix L4).
 */
export function isKnownAsset(asset: string | null | undefined): boolean {
  return asset != null && KNOWN_ASSET_DECIMALS_BY_LOWER.has(asset.toLowerCase());
}

/** Decimals for a known asset, else null. */
export function knownAssetDecimals(asset: string | null | undefined): number | null {
  if (asset == null) return null;
  return KNOWN_ASSET_DECIMALS_BY_LOWER.get(asset.toLowerCase()) ?? null;
}

/** The canonical network a KNOWN asset settles on, else null (SPEC §3.2, fix L4). */
export function knownAssetNetwork(asset: string | null | undefined): SupportedNetwork | null {
  if (asset == null) return null;
  return KNOWN_ASSET_NETWORK_BY_LOWER.get(asset.toLowerCase()) ?? null;
}

/**
 * Derive USD from an atomic amount for a KNOWN asset (SPEC §2/§3.2). Returns null
 * unless the asset is known AND the amount is a non-negative integer string
 * (never parses a float; `amountAtomic` is preserved as an as-advertised string).
 */
export function deriveAmountUsd(
  amountAtomic: string | null | undefined,
  asset: string | null | undefined,
): number | null {
  if (amountAtomic == null || !/^\d+$/.test(amountAtomic)) return null;
  const decimals = knownAssetDecimals(asset);
  if (decimals == null) return null;
  return Number(amountAtomic) / 10 ** decimals;
}
