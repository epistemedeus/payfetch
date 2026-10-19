/**
 * P3′ payfetch — X402Payer: the x402 `exact`-EVM rail (SPEC §2, §3.2, §3.3).
 *
 * Purpose: detect x402 challenges, filter+select quotes deterministically, and
 * build a signed EIP-3009 `TransferWithAuthorization` payment payload using an
 * INJECTED `WalletSigner`. We OWN the HTTP loop, guards, budgets, and receipts;
 * we BUILD ON the pinned `@x402/core@2.17.0` package for the wire format (SPEC §0
 * `-- VERIFY x402-wire`, RE-OPENED → §3.1a; WIRE-PARITY WAVE 2026-07-02).
 *
 * Bounded-authority invariant (SPEC §2): the signature authorizes movement of
 * THAT asset, THAT amount, THAT recipient, THAT time window — nothing else. This
 * is why BYO keys are tolerable (THESIS §2).
 *
 * REUSE vs MIRROR (the §3.1a rule-6 split; re-verified against @x402/core@2.17.0):
 *  - REUSED verbatim from the pinned package (wire format stays byte-identical):
 *      • `@x402/core/utils` → `safeBase64Encode` / `safeBase64Decode` (the base64
 *        wire codec; `dist/cjs/utils/index.js`).
 *      • `@x402/core/http`  → `decodePaymentResponseHeader` (PAYMENT-RESPONSE /
 *        X-PAYMENT-RESPONSE base64-JSON → SettleResponse; `dist/cjs/http/index.js`).
 *  - MIRRORED (re-implemented following the package source EXACTLY, cited below):
 *      • The EIP-712 `TransferWithAuthorization` type set + primary type are NOT
 *        in `@x402/core` (which is protocol-core only). They live in the sibling
 *        `@x402/evm` — a heavy, permit2/batch-settlement-laden package that
 *        `@x402/core` does NOT require. Rather than pull it in for one fixed
 *        EIP-3009 constant, we MIRROR it (unchanged since v1; it is the EIP-3009
 *        standard). Source: `@x402/evm@2.17.0` `dist/cjs/index.js:81`
 *        (`authorizationTypes`) and `dist/cjs/exact/client/index.js:187`
 *        (`primaryType: "TransferWithAuthorization"`). See `AUTHORIZATION_TYPES`.
 *      • The package's client scheme (`ExactEvmScheme.createPaymentPayload` →
 *        `createEIP3009Payload`, `@x402/evm dist/cjs/exact/client/index.js:139`)
 *        bakes in `globalThis.crypto` for the nonce and `Date.now()` with NO
 *        SPEC §2 clamp, and its signer type rejects our async `WalletSigner`. So
 *        we build the unsigned authorization ourselves with the injected
 *        nonce/clock and sign via `deps.signer.signTypedData`.
 *      • network → chainId: mirrored as `chainIdForNetwork` (constants.ts),
 *        replacing the package's `getEvmChainId(eip155:N)` /
 *        `getEvmChainIdV1(name)` (`@x402/evm .../exact/client/index.js:113,626`).
 *
 * WIRE ENVELOPE (VERIFIED against @x402/core@2.17.0 PaymentPayload{V1,V2}Schema,
 * `dist/cjs/schemas/index.d.ts`, and the v2 client assembly `@x402/core
 * dist/cjs/client/index.js:296` — round-trip smoke-tested):
 *   v1: { x402Version:1, scheme, network, payload:{signature, authorization} }
 *   v2: { x402Version:2, accepted:<raw requirements entry>, payload:{…} }
 *       (v2 drops top-level scheme/network; `accepted` carries the selected entry
 *        with its `amount` field + RAW CAIP-2 network; the facilitator reads
 *        `paymentPayload.accepted` and throws if it is missing — client L825.)
 * The version is ECHOED from the quote (§3.1a rule 2); the network is echoed RAW
 * via `quote.networkAsDeclared` / `quote.rawAccepts` (§3.1a rule 3).
 *
 * Invariants:
 *  - `buildPayment` calls `signer.signTypedData` EXACTLY once (SPEC §5.3,
 *    count-asserted) and consumes EXACTLY the 32 bytes from `deps.random()` as
 *    the nonce (byte-asserted).
 *  - Quote filter (§3.2 + §3.1a rule 2) is deterministic/order-free; failing
 *    entries are tallied per-reason into `rejected` (local demand telemetry).
 *    Selection (§3.3): min `amountUsd`, tie → first listed.
 */

import { decodePaymentResponseHeader } from "@x402/core/http";
import { safeBase64Encode } from "@x402/core/utils";
import { getAddress, toHex } from "viem";

import {
  CLOCK_SKEW_S,
  NONCE_BYTES,
  PAYMENT_VALIDITY_DEFAULT_S,
  PAYMENT_VALIDITY_MAX_S,
  RAILS_ENABLED,
  SUPPORTED_NETWORKS,
  SUPPORTED_SCHEMES,
  outgoingPaymentHeader,
  chainIdForNetwork,
  deriveAmountUsd,
  isKnownAsset,
  isSupportedX402Version,
  knownAssetNetwork,
  type SupportedNetwork,
} from "../core/constants.js";
import type {
  Eip712TypedData,
  ParsedChallenge,
  PayfetchDeps,
  PaymentPayer,
  PaymentProof,
  PaymentQuote,
  WalletSigner,
  X402Terms,
} from "./types.js";

// ---------------------------------------------------------------------------
// MIRRORED EIP-712 material (§3.1a rule 6) — the EIP-3009 TransferWithAuthorization
// type set + primary type. NOT in @x402/core; transcribed verbatim from the sibling
// @x402/evm@2.17.0 `dist/cjs/index.js:81` (`authorizationTypes`) and
// `dist/cjs/exact/client/index.js:187` (`primaryType`). This is the fixed EIP-3009
// standard (unchanged across x402 v1/v2); mirrored to avoid depending on the heavy
// @x402/evm package for one constant. Exported so signer tests share one source.
// ---------------------------------------------------------------------------

/** EIP-712 type set for EIP-3009 `TransferWithAuthorization` (mirror; see above). */
export const AUTHORIZATION_TYPES: Eip712TypedData["types"] = Object.freeze({
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
});

/** EIP-712 primary type for the exact-EVM scheme (mirror; see above). */
export const AUTHORIZATION_PRIMARY_TYPE = "TransferWithAuthorization";

// ---------------------------------------------------------------------------
// Quote filtering (§3.2) + per-reason rejection tally
// ---------------------------------------------------------------------------

/** Filter tally: reason → count of accepts entries rejected for that reason (§3.2). */
export type QuoteRejections = Record<string, number>;

/**
 * First filter condition an entry fails, in fixed precedence, or null if it
 * qualifies. Precedence (version → rail → scheme → network → asset →
 * asset/network coherence → payTo → amount) makes the tally deterministic: an
 * `upto` entry with an otherwise-fine body tallies `unsupported_scheme_upto`.
 * Reason spellings follow SPEC §3.2/§13 examples (`unsupported_scheme_upto`,
 * `unknown_asset`, `unsupported_network`) plus `unsupported_x402_version`
 * (§3.1a rule 2) and `asset_network_mismatch` (§3.2 hardening, fix L4).
 *
 * `x402Version` is a CHALLENGE-level property (not per-term); it is threaded in so
 * an entire challenge of an unaccepted version rejects EVERY entry — before any
 * other reason (a version we don't speak is unpayable regardless of terms).
 */
function rejectReason(term: X402Terms, x402Version: number | null): string | null {
  if (!isSupportedX402Version(x402Version)) return "unsupported_x402_version";
  if (!(RAILS_ENABLED as readonly string[]).includes("x402")) return "unsupported_rail_x402";
  if (!(SUPPORTED_SCHEMES as readonly string[]).includes(term.scheme)) {
    return `unsupported_scheme_${term.scheme}`;
  }
  if (!(SUPPORTED_NETWORKS as readonly string[]).includes(term.network)) return "unsupported_network";
  if (!isKnownAsset(term.asset)) return "unknown_asset";
  // L4 (SPEC §3.2): the asset must settle on the network it was advertised with —
  // a KNOWN asset carries its canonical network; a mismatch (e.g. Base-mainnet
  // USDC declared on base-sepolia) would sign an unspendable EIP-712 domain
  // (chainId from network, verifyingContract from asset). Reject rather than sign.
  // By this point isKnownAsset passed AND term.network is canonical (parse402), so
  // this is a direct canonical-vs-canonical comparison; the `!== null` guard keeps
  // it defensive/typed (assetNetwork is non-null here).
  const assetNetwork = knownAssetNetwork(term.asset);
  if (assetNetwork !== null && assetNetwork !== term.network) return "asset_network_mismatch";
  if (term.payTo == null || term.payTo.length === 0) return "missing_pay_to";
  if (term.amountAtomic == null || !/^\d+$/.test(term.amountAtomic)) return "non_integer_amount";
  return null;
}

/**
 * Build a PaymentQuote from a filter-passing term (all fields provably present).
 * `x402Version` is ECHOED from the challenge (§3.1a rule 2); `networkAsDeclared`
 * carries the RAW declared network for the payload's echoed field (§3.1a rule 3)
 * while `network` is the CANONICAL name for policy/asset/budget logic.
 */
function toQuote(term: X402Terms, x402Version: number): PaymentQuote {
  // Filter guarantees: asset ∈ KNOWN_ASSETS, network ∈ SUPPORTED_NETWORKS,
  // scheme === "exact", payTo present, amount a non-negative integer string.
  const asset = (term.asset as string).toLowerCase();
  const amountAtomic = term.amountAtomic as string;
  const amountUsd = term.amountUsd ?? deriveAmountUsd(amountAtomic, asset) ?? 0;
  return {
    rail: "x402",
    scheme: "exact",
    network: term.network as SupportedNetwork,
    asset,
    amountAtomic,
    amountUsd,
    payTo: term.payTo as string,
    maxTimeoutSeconds: term.maxTimeoutSeconds,
    resource: term.resource,
    mimeType: term.mimeType,
    outputSchemaSha256: term.outputSchemaSha256,
    rawAccepts: term.rawAccepts,
    x402Version,
    networkAsDeclared: term.networkAsDeclared,
  };
}

/**
 * Apply the §3.2 filter to a parsed challenge, returning both surviving quotes
 * and the per-reason rejection tally (SPEC §3.2 telemetry). Order-free and
 * deterministic. A malformed challenge (no terms) yields empty results.
 */
export function quoteWithRejections(challenge: ParsedChallenge): {
  quotes: PaymentQuote[];
  rejected: QuoteRejections;
} {
  const quotes: PaymentQuote[] = [];
  const rejected: QuoteRejections = {};
  for (const term of challenge.terms) {
    const reason = rejectReason(term, challenge.x402Version);
    if (reason !== null) {
      rejected[reason] = (rejected[reason] ?? 0) + 1;
      continue;
    }
    quotes.push(toQuote(term, challenge.x402Version as number));
  }
  return { quotes, rejected };
}

/**
 * Selection (§3.3): choose the min-`amountUsd` quote; tie → first listed in
 * `accepts`. Deterministic + auditable. Returns null when there are no quotes.
 */
export function selectQuote(quotes: readonly PaymentQuote[]): PaymentQuote | null {
  let best: PaymentQuote | null = null;
  for (const q of quotes) {
    // Strict `<` keeps the FIRST minimum on ties (accepts order preserved).
    if (best === null || q.amountUsd < best.amountUsd) best = q;
  }
  return best;
}

// ---------------------------------------------------------------------------
// buildPayment (SPEC §2 normative) — the one signature
// ---------------------------------------------------------------------------

/** EIP-712 domain data (`extra: {name, version}`) read defensively from the raw entry. */
function extractExtra(rawAccepts: unknown): { name?: string; version?: string } {
  if (rawAccepts == null || typeof rawAccepts !== "object") return {};
  const extra = (rawAccepts as Record<string, unknown>).extra;
  if (extra == null || typeof extra !== "object") return {};
  const e = extra as Record<string, unknown>;
  return {
    name: typeof e.name === "string" ? e.name : undefined,
    version: typeof e.version === "string" ? e.version : undefined,
  };
}

/**
 * Build a signed payment proof for `quote` (SPEC §2 normative paragraph).
 * The header name follows the echoed version: `X-PAYMENT` for v1 and
 * `PAYMENT-SIGNATURE` for v2, matching `@x402/core` `encodePaymentSignatureHeader`.
 * validAfter = floor(now/1000) − CLOCK_SKEW_S;
 * validBefore = floor(now/1000) + min(maxTimeoutSeconds ?? DEFAULT, MAX);
 * nonce = the 32 bytes from deps.random().
 *
 * The EIP-3009 authorization + signature are IDENTICAL across x402 v1/v2; only the
 * outer payload ENVELOPE differs (§3.1a rule 2, VERIFIED against @x402/core@2.17.0
 * PaymentPayload{V1,V2}Schema): v1 carries top-level `scheme`/`network`, v2 carries
 * the selected requirements entry as `accepted` (with its raw CAIP-2 network +
 * `amount` field) and drops top-level scheme/network. We ECHO `quote.x402Version`
 * and echo the RAW network dialect (`quote.networkAsDeclared` / `quote.rawAccepts`).
 */
export async function buildX402Payment(
  quote: PaymentQuote,
  signer: WalletSigner,
  deps: PayfetchDeps,
): Promise<PaymentProof> {
  // --- Time window (SPEC §2) ---
  const nowSec = Math.floor(deps.now() / 1000);
  const validAfter = nowSec - CLOCK_SKEW_S;
  const timeoutS = Math.min(
    quote.maxTimeoutSeconds ?? PAYMENT_VALIDITY_DEFAULT_S,
    PAYMENT_VALIDITY_MAX_S,
  );
  const validBefore = nowSec + timeoutS;

  // --- Nonce: EXACTLY the 32 bytes from deps.random() (SPEC §2) ---
  const nonceBytes = deps.random();
  if (nonceBytes.length !== NONCE_BYTES) {
    // Programmer/dep error, not a policy result — deps.random() contract is 32 bytes.
    throw new Error(
      `deps.random() must return ${NONCE_BYTES} bytes for the EIP-3009 nonce; got ${nonceBytes.length}`,
    );
  }
  const nonceHex = toHex(nonceBytes);

  // --- Addresses (checksummed for the signed struct + encoded payload) ---
  const from = getAddress(await signer.address());
  const to = getAddress(quote.payTo);
  const verifyingContract = getAddress(quote.asset);

  const { name, version } = extractExtra(quote.rawAccepts);
  // chainId from the CANONICAL network (§3.1a rule 6) — dialect-invariant domain.
  const chainId = chainIdForNetwork(quote.network);
  if (chainId === null) {
    // The §3.2 filter guarantees a SUPPORTED_NETWORKS quote, so this is a
    // programmer/dep error (a quote reached buildPayment with an unmapped network).
    throw new Error(`no EVM chainId for network "${quote.network}"`);
  }

  // Authorization values are strings in the wire payload (EIP-3009; @x402/evm
  // createEIP3009Payload uses the same field set — dist/cjs/exact/client/index.js:139).
  const authorization = {
    from,
    to,
    value: quote.amountAtomic,
    validAfter: String(validAfter),
    validBefore: String(validBefore),
    nonce: nonceHex,
  };

  // Typed data mirrors signEIP3009Authorization (@x402/evm .../exact/client:161).
  const typedData: Eip712TypedData = {
    types: AUTHORIZATION_TYPES,
    domain: { name, version, chainId, verifyingContract },
    primaryType: AUTHORIZATION_PRIMARY_TYPE,
    message: { ...authorization },
  };

  // EXACTLY one signature per buildPayment (SPEC §5.3).
  const signature = await signer.signTypedData(typedData);

  // Version-branched envelope (§3.1a rule 2; VERIFIED against @x402/core@2.17.0
  // client L296 / PaymentPayload{V1,V2}Schema). base64 via the pinned safeBase64Encode.
  const payment =
    quote.x402Version === 1
      ? {
          x402Version: 1,
          scheme: quote.scheme,
          network: quote.networkAsDeclared, // echo the RAW declared dialect (§3.1a rule 3)
          payload: { signature, authorization },
        }
      : {
          x402Version: quote.x402Version, // ECHOED (v2+) — never hardcoded (§3.1a rule 2)
          // `accepted` is the selected requirements entry the facilitator verifies
          // against (client L825); echo the raw entry so it carries the seller's own
          // dialect (CAIP-2 network + `amount` field) byte-for-byte (§3.1a rule 3).
          accepted: quote.rawAccepts,
          payload: { signature, authorization },
        };
  const header = safeBase64Encode(JSON.stringify(payment));

  return {
    headers: { [outgoingPaymentHeader(quote.x402Version)]: header },
    validBeforeTs: validBefore, // epoch SECONDS (SPEC §2 / §5.2)
    nonce: nonceHex,
  };
}

// ---------------------------------------------------------------------------
// Settlement response parsing (PAYMENT-RESPONSE / X-PAYMENT-RESPONSE, SPEC §5.3 / §3.1a rule 5)
// ---------------------------------------------------------------------------

/** Facilitator settlement facts (base64 JSON). SPEC §5.3 (subset of @x402/core SettleResponse). */
export type SettlementResponse = {
  success: boolean;
  transaction?: string;
  network?: string;
  payer?: string;
};

/**
 * Parse a settlement header value via the pinned package's
 * `decodePaymentResponseHeader` (@x402/core/http; base64 JSON → SettleResponse —
 * the v2-canonical decoder, runtime-lenient about optional network/payer). Header
 * SELECTION (PAYMENT-RESPONSE first, else X-PAYMENT-RESPONSE) is the pipeline's
 * job (§3.1a rule 5); this decodes whichever value it is handed. DEFENSIVE:
 * returns null on any decode failure or non-object result — never throws (SPEC
 * §5.3; degrade toward over-counting, §13).
 */
export function parseSettlementResponse(headerValue: string): SettlementResponse | null {
  try {
    const decoded = decodePaymentResponseHeader(headerValue) as unknown;
    if (decoded == null || typeof decoded !== "object") return null;
    return decoded as SettlementResponse;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// X402Payer (SPEC §2 PaymentPayer)
// ---------------------------------------------------------------------------

export class X402Payer implements PaymentPayer {
  readonly rail = "x402" as const;

  /** Rail detection (§3.1): x402Version + accepts present ⇒ ParsedChallenge.rail === "x402". */
  detects(challenge: ParsedChallenge): boolean {
    return challenge.rail === "x402";
  }

  /** Surviving quotes after the §3.2 filter (rejection tally via quoteWithRejections). */
  quotes(challenge: ParsedChallenge): PaymentQuote[] {
    return quoteWithRejections(challenge).quotes;
  }

  buildPayment(
    quote: PaymentQuote,
    signer: WalletSigner,
    deps: PayfetchDeps,
  ): Promise<PaymentProof> {
    return buildX402Payment(quote, signer, deps);
  }
}
