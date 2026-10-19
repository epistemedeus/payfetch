/**
 * P3′ payfetch — payer seam types (SPEC §1, §2, §3.1).
 *
 * Purpose: the rail-agnostic contracts through which the core library and policy
 * engine handle payment WITHOUT knowing rail specifics — mirrors the scaffold's
 * seller-side `PaymentVerifier` (SPEC §2). Plus `PayfetchDeps` (SPEC §1), the
 * dependency-injection bundle the core threads everywhere (no globals, env, raw
 * fetch, or clock touched directly — P1 §1 discipline).
 *
 * Invariants:
 *  - `WalletSigner.address()` returns a LOWERCASED EVM address (SPEC §2).
 *  - `PaymentQuote.amountAtomic` is the advertised atomic STRING, never parsed to
 *    a float; `payTo`/`asset` are lowercased; `amountUsd` is derived only for
 *    KNOWN_ASSETS (SPEC §2/§3.2).
 *  - `PaymentProof.headers` carries one wire header: `X-PAYMENT` for v1 or
 *    `PAYMENT-SIGNATURE` for v2. `validBeforeTs` is epoch SECONDS (drives
 *    hold expiry, §5.2); `nonce` is hex (receipt provenance).
 *  - `PayfetchDeps.log` NEVER receives key material (SPEC §1/§12); `random()`
 *    returns 32 bytes (nonce + ids), seeded in tests.
 *  - Portability (SPEC §1 scaffold-lift): this directory imports NOTHING outside
 *    `src/payer/` and `src/core/` — the guards/pipeline may depend on it, never
 *    the reverse.
 */

import type { SupportedNetwork } from "../core/constants.js";

// ---------------------------------------------------------------------------
// Rail seam (SPEC §2)
// ---------------------------------------------------------------------------

/** A settlement rail. SPEC §2 (`RAILS_ENABLED = ["x402"]`; `mpp` is a stub). */
export type Rail = "x402" | "mpp";

// ---------------------------------------------------------------------------
// EIP-712 typed data (argument to WalletSigner.signTypedData)
// ---------------------------------------------------------------------------

/**
 * EIP-712 typed-data payload. Structural shape accepted by BOTH viem
 * `LocalAccount.signTypedData` and the CDP server-wallet account's
 * viem-compatible `signTypedData` (RESULTS.md `-- VERIFY cdp-signer`, RESOLVED).
 * The x402 exact-EVM scheme signs `TransferWithAuthorization` over this shape
 * (see payer/x402.ts, mirrored from the pinned package).
 */
export type Eip712TypedData = {
  domain: {
    name?: string;
    version?: string;
    chainId?: number;
    verifyingContract?: `0x${string}`;
    salt?: `0x${string}`;
  };
  types: Record<string, ReadonlyArray<{ name: string; type: string }>>;
  primaryType: string;
  message: Record<string, unknown>;
};

// ---------------------------------------------------------------------------
// WalletSigner (SPEC §2) — the injected signing seam
// ---------------------------------------------------------------------------

export interface WalletSigner {
  kind: "local_key" | "cdp_server_wallet";
  /** EVM address, lowercased. SPEC §2. */
  address(): Promise<string>;
  signTypedData(td: Eip712TypedData): Promise<`0x${string}`>;
}

// ---------------------------------------------------------------------------
// X402Terms (SPEC §3.1 — "EXACT same normalization as P2 PROBER_SPEC §3.3")
// ---------------------------------------------------------------------------

/**
 * One normalized `accepts` entry. The first ten fields are byte-for-byte the P2
 * PROBER_SPEC §3.3 `X402Terms` (source of record:
 * products/p2_trust/prober/src/probe/parse402.ts) so `termsHash` is value-
 * identical across buyer and seller (SPEC §1 unification target).
 *
 * AMBIGUITY / conservative reading (flagged): SPEC §3.1 gives `terms:
 * X402Terms[]` but the frozen `PaymentQuote` (§2) additionally needs `resource`
 * and `rawAccepts` (the latter is the ONLY carrier of the accepts entry's
 * `extra: {name, version}` — the EIP-712 domain data required to sign, which is
 * NOT among P2's hashed fields). Since `ParsedChallenge` is frozen to
 * `{rail, x402Version, terms, termsHash, malformed}`, the only spec-faithful
 * place to surface those is on each term. They are therefore appended here as
 * P3-side plumbing. This does NOT affect `termsHash`: `hashTerms` uses ONLY the
 * eight P2 fields (scheme, network, asset, amountAtomic, payTo,
 * maxTimeoutSeconds, mimeType, outputSchemaSha256) — `resource`, `rawAccepts`,
 * and `networkAsDeclared` are excluded, exactly as P2 excludes
 * `resource`/`description`.
 *
 * NETWORK DIALECT (§3.1a rule 3, WIRE-PARITY WAVE): `network` is the CANONICAL
 * name (`base`/`base-sepolia`) — a CAIP-2 declaration (`eip155:84532`) is
 * normalized via `NETWORK_ALIASES` at parse time so the hashed 8-tuple is
 * dialect-invariant. `networkAsDeclared` preserves the RAW declared string for
 * the payment payload's echoed network field (`PaymentQuote.networkAsDeclared`).
 */
export type X402Terms = {
  // --- P2 PROBER_SPEC §3.3 fields (identical shape + semantics) ---
  scheme: string;
  network: string; // CANONICAL (§3.1a rule 3); the hashed 8-tuple's network slot
  asset: string | null;
  amountAtomic: string | null; // as advertised (string; never parsed to float)
  amountUsd: number | null; // derived iff asset ∈ KNOWN_ASSETS, else null
  payTo: string | null; // lowercased
  maxTimeoutSeconds: number | null;
  mimeType: string | null;
  hasOutputSchema: boolean;
  outputSchemaSha256: string | null;
  // --- P3 plumbing (excluded from termsHash) ---
  networkAsDeclared: string; // the RAW declared network string (§3.1a rule 3 echo)
  resource: string | null; // advertised resource URL (PaymentQuote.resource)
  rawAccepts: unknown; // the original accepts entry (payload construction input)
};

// ---------------------------------------------------------------------------
// ParsedChallenge (SPEC §3.1)
// ---------------------------------------------------------------------------

export type ParsedChallenge = {
  rail: Rail | null; // x402 iff body parses as JSON with x402Version + accepts[]
  x402Version: number | null;
  terms: X402Terms[]; // EXACT same normalization as P2 PROBER_SPEC §3.3
  termsHash: string | null; // same algorithm/fields as P2 §3.3 (16 hex)
  malformed: boolean; // body unusable as any known rail's challenge
};

// ---------------------------------------------------------------------------
// PaymentQuote / PaymentProof (SPEC §2)
// ---------------------------------------------------------------------------

export type PaymentQuote = {
  rail: Rail;
  scheme: "exact"; // v1: only "exact" survives quote filtering
  network: SupportedNetwork; // "base" | "base-sepolia"
  asset: string; // ERC-20 address, lowercased; ∈ KNOWN_ASSETS
  amountAtomic: string; // as advertised (string; never parsed to float)
  amountUsd: number; // derived: atomic ÷ 10^decimals, KNOWN_ASSETS only
  payTo: string; // lowercased
  maxTimeoutSeconds: number | null;
  resource: string | null;
  mimeType: string | null;
  outputSchemaSha256: string | null;
  rawAccepts: unknown; // original accepts entry — payload construction input
  x402Version: number; // ECHOED from the challenge (§3.1a rule 2 — never hardcoded)
  networkAsDeclared: string; // the challenge's raw network string (§3.1a rule 3 echo)
};

export type PaymentProof = {
  headers: Record<string, string>; // one header: X-PAYMENT (v1) or PAYMENT-SIGNATURE (v2)
  validBeforeTs: number; // epoch SECONDS — drives hold expiry (§5.2)
  nonce: string; // hex; receipt provenance
};

// ---------------------------------------------------------------------------
// PaymentPayer (SPEC §2) — the dual-rail seam
// ---------------------------------------------------------------------------

export interface PaymentPayer {
  rail: Rail;
  detects(challenge: ParsedChallenge): boolean; // rail detection (§3.1)
  quotes(challenge: ParsedChallenge): PaymentQuote[]; // ONLY supported entries (filter §3.2)
  buildPayment(
    quote: PaymentQuote,
    signer: WalletSigner,
    deps: PayfetchDeps,
  ): Promise<PaymentProof>;
}

// ---------------------------------------------------------------------------
// Elicitation bridge (SPEC §1 `ElicitFn`, §6)
// ---------------------------------------------------------------------------
/**
 * MCP elicitation bridge (SPEC §1: `elicit: ElicitFn | null`; null = client
 * without elicitation support, §6). FORWARD-DECLARED for stage 1: the approval
 * flow (§6) and MCP server (§9) are later stages that own the final contract.
 * The request fields transcribe §6's enumerated prompt contents; the response is
 * the §6 approve-once / deny choice (no "always allow" in v1). Flagged so the
 * approval stage refines rather than reinvents.
 */
export type ElicitRequest = {
  host: string;
  resource: string | null;
  amountUsd: number;
  networkLabel: string;
  assetLabel: string;
  guards: unknown[]; // GuardResult[] at approval time (§6); typed loosely pre-guards
  remainingBudgets: unknown; // today's remaining budgets (§6)
};
/**
 * The outcome of an elicitation attempt (SPEC §6).
 *  - `approved: true`                    → the human approved THIS one payment.
 *  - `approved: false, cancelled: false` → a GENUINE human denial (declined / unchecked).
 *  - `cancelled: true`                   → the client could NOT service the prompt (it
 *    dismissed/cancelled without rendering a decision — e.g. Claude Desktop, which
 *    advertises `elicitation` but returns `cancel` immediately). This is NOT a denial:
 *    the engine treats it exactly like an absent elicitation channel (config
 *    pre-approval → `approval.elicitFallback`), and — critically — never mistakes an
 *    un-renderable dialog for a human saying "no" (P3 review, desktop-fallback fix).
 * `cancelled` is optional (defaults false) so an approve/deny bridge stays terse.
 */
export type ElicitDecision = { approved: boolean; cancelled?: boolean };
export type ElicitFn = (request: ElicitRequest) => Promise<ElicitDecision>;

// ---------------------------------------------------------------------------
// PayfetchDeps (SPEC §1) — dependency injection bundle
// ---------------------------------------------------------------------------

export type PayfetchDeps = {
  fetch: typeof fetch; // undici in prod; FakeFetch in tests
  signer: WalletSigner;
  now: () => number; // epoch ms
  random: () => Uint8Array; // 32 bytes; nonce + ids (seeded in tests)
  dataDir: string; // ledger/state/config root
  /** Structured log sink. NEVER receives key material (SPEC §1/§12). */
  log: (msg: string, fields?: Record<string, unknown>) => void;
  elicit: ElicitFn | null; // MCP elicitation bridge; null = unsupported (§6)
};

// ---------------------------------------------------------------------------
// Errors (SPEC §2 — MppPayer throws UnsupportedRailError)
// ---------------------------------------------------------------------------

/**
 * Thrown by a rail payer whose implementation is a stub / not yet built (SPEC §2:
 * `MppPayer` methods throw this). A programmer error, not a policy result — the
 * pipeline routes challenges only to a payer whose `detects()` returned true, so
 * this should never surface for `RAILS_ENABLED` rails.
 */
export class UnsupportedRailError extends Error {
  readonly rail: Rail;
  readonly method: string;
  constructor(rail: Rail, method: string) {
    super(`Rail "${rail}" does not support ${method}() in v1 (SPEC §2 stub).`);
    this.name = "UnsupportedRailError";
    this.rail = rail;
    this.method = method;
  }
}
