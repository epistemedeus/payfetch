/**
 * P3′ payfetch — X402Payer tests (SPEC §14 "Parsing" selection/tally + "Payer").
 *
 * Hermetic. Covers: §3.2 filter tallies (upto / unknown asset / unsupported
 * network / non-integer amount / empty), §3.3 selection (min amount, tie→first),
 * §2 buildPayment window math + clamp, nonce == deps.random bytes, exactly one
 * signature per buildPayment, the version-correct payment header, and the X-PAYMENT-RESPONSE
 * round-trip / defensive-null.
 */

import { getAddress, toHex } from "viem";
import { safeBase64Decode, safeBase64Encode } from "@x402/core/utils";
import { describe, expect, it } from "vitest";

import {
  CLOCK_SKEW_S,
  PAYMENT_VALIDITY_DEFAULT_S,
  PAYMENT_VALIDITY_MAX_S,
  PAYMENT_SIGNATURE_HEADER,
  X_PAYMENT_HEADER,
} from "../src/core/constants.js";
import { parseChallenge } from "../src/payer/parse402.js";
import type { PaymentQuote } from "../src/payer/types.js";
import {
  X402Payer,
  buildX402Payment,
  parseSettlementResponse,
  quoteWithRejections,
  selectQuote,
} from "../src/payer/x402.js";
import {
  FakeSigner,
  acceptsEntry,
  acceptsEntryV2,
  challenge402,
  challenge402V2,
  fakeDeps,
  fixedRandom,
} from "./fakes.js";

// Realistic clock so EIP-3009 windows stay positive (2023-11-14T22:13:20Z).
const NOW_MS = 1_700_000_000_000;
const NOW_SEC = Math.floor(NOW_MS / 1000);

function quoteFrom(over: Record<string, unknown> = {}): PaymentQuote {
  const c = parseChallenge(challenge402({ accepts: [acceptsEntry(over)] }));
  const { quotes } = quoteWithRejections(c);
  expect(quotes).toHaveLength(1);
  return quotes[0];
}

describe("quoteWithRejections — §3.2 filter + per-reason tally", () => {
  it("upto-only challenge → zero quotes, tally { unsupported_scheme_upto: 1 }", () => {
    const c = parseChallenge(challenge402({ accepts: [acceptsEntry({ scheme: "upto" })] }));
    const { quotes, rejected } = quoteWithRejections(c);
    expect(quotes).toEqual([]);
    expect(rejected).toEqual({ unsupported_scheme_upto: 1 });
  });

  it("unknown asset → zero quotes, tally { unknown_asset: 1 }", () => {
    const c = parseChallenge(
      challenge402({ accepts: [acceptsEntry({ asset: "0x1111111111111111111111111111111111111111" })] }),
    );
    const { quotes, rejected } = quoteWithRejections(c);
    expect(quotes).toEqual([]);
    expect(rejected).toEqual({ unknown_asset: 1 });
  });

  it("unsupported network → zero quotes, tally { unsupported_network: 1 }", () => {
    const c = parseChallenge(
      challenge402({ accepts: [acceptsEntry({ network: "ethereum" })] }),
    );
    const { quotes, rejected } = quoteWithRejections(c);
    expect(quotes).toEqual([]);
    expect(rejected).toEqual({ unsupported_network: 1 });
  });

  it("non-integer amount string → zero quotes, tally { non_integer_amount: 1 }", () => {
    const c = parseChallenge(
      challenge402({ accepts: [acceptsEntry({ maxAmountRequired: "1.5" })] }),
    );
    const { quotes, rejected } = quoteWithRejections(c);
    expect(quotes).toEqual([]);
    expect(rejected).toEqual({ non_integer_amount: 1 });
  });

  it("empty accepts (malformed) → zero quotes, empty tally", () => {
    const c = parseChallenge(challenge402({ accepts: [] }));
    const { quotes, rejected } = quoteWithRejections(c);
    expect(quotes).toEqual([]);
    expect(rejected).toEqual({});
  });

  it("scheme precedence over other failures (upto + unknown asset → tally upto)", () => {
    const c = parseChallenge(
      challenge402({
        accepts: [acceptsEntry({ scheme: "upto", asset: "0x2222222222222222222222222222222222222222" })],
      }),
    );
    const { rejected } = quoteWithRejections(c);
    expect(rejected).toEqual({ unsupported_scheme_upto: 1 });
  });

  it("mixed multi-accepts: one payable + one upto → 1 quote, tally counts the reject", () => {
    const c = parseChallenge(
      challenge402({
        accepts: [acceptsEntry({ maxAmountRequired: "10000" }), acceptsEntry({ scheme: "upto" })],
      }),
    );
    const { quotes, rejected } = quoteWithRejections(c);
    expect(quotes).toHaveLength(1);
    expect(rejected).toEqual({ unsupported_scheme_upto: 1 });
  });
});

describe("quoteWithRejections — §3.2 fix L4 asset⇄network coherence", () => {
  // The two KNOWN assets carry a canonical network (constants.ts KNOWN_ASSETS):
  // Base-mainnet USDC settles on `base`; Base-Sepolia USDC on `base-sepolia`.
  const BASE_MAINNET_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
  const BASE_SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

  it("Base-mainnet USDC advertised on base-sepolia (canonical) → asset_network_mismatch, no quote", () => {
    // acceptsEntry defaults to Base-mainnet USDC; override only the network.
    const c = parseChallenge(challenge402({ accepts: [acceptsEntry({ network: "base-sepolia" })] }));
    const { quotes, rejected } = quoteWithRejections(c);
    expect(quotes).toEqual([]);
    expect(rejected).toEqual({ asset_network_mismatch: 1 });
  });

  it("Base-mainnet USDC advertised on base-sepolia via CAIP-2 (eip155:84532) → asset_network_mismatch", () => {
    // The declared network is canonicalized (eip155:84532 → base-sepolia) BEFORE
    // the coherence check runs, so the CAIP-2 dialect mismatches identically.
    const c = parseChallenge(challenge402({ accepts: [acceptsEntry({ network: "eip155:84532" })] }));
    const { quotes, rejected } = quoteWithRejections(c);
    expect(quotes).toEqual([]);
    expect(rejected).toEqual({ asset_network_mismatch: 1 });
  });

  it("mirror: Base-Sepolia USDC advertised on base via CAIP-2 (eip155:8453) → asset_network_mismatch", () => {
    const c = parseChallenge(
      challenge402({ accepts: [acceptsEntry({ asset: BASE_SEPOLIA_USDC, network: "eip155:8453" })] }),
    );
    const { quotes, rejected } = quoteWithRejections(c);
    expect(quotes).toEqual([]);
    expect(rejected).toEqual({ asset_network_mismatch: 1 });
  });

  it("REGRESSION: coherent pairs still qualify (mainnet USDC/base + sepolia USDC/base-sepolia)", () => {
    // Do NOT over-reject the happy path: each asset advertised on its own network.
    const c = parseChallenge(
      challenge402({
        accepts: [
          acceptsEntry({ asset: BASE_MAINNET_USDC, network: "base" }),
          acceptsEntry({ asset: BASE_SEPOLIA_USDC, network: "base-sepolia" }),
        ],
      }),
    );
    const { quotes, rejected } = quoteWithRejections(c);
    expect(quotes).toHaveLength(2);
    expect(rejected).toEqual({});
    expect(quotes.map((q) => q.network)).toEqual(["base", "base-sepolia"]);
  });
});

describe("selectQuote — §3.3 min amount, tie → first listed", () => {
  it("picks the minimum-amountUsd survivor", () => {
    const c = parseChallenge(
      challenge402({
        accepts: [
          acceptsEntry({ maxAmountRequired: "30000" }),
          acceptsEntry({ maxAmountRequired: "10000" }),
          acceptsEntry({ maxAmountRequired: "20000" }),
        ],
      }),
    );
    const { quotes } = quoteWithRejections(c);
    const selected = selectQuote(quotes);
    expect(selected?.amountAtomic).toBe("10000");
  });

  it("on a tie, keeps the FIRST listed", () => {
    const first = "0x000000000000000000000000000000000000AAAA";
    const second = "0x000000000000000000000000000000000000BBBB";
    const c = parseChallenge(
      challenge402({
        accepts: [
          acceptsEntry({ maxAmountRequired: "10000", payTo: first }),
          acceptsEntry({ maxAmountRequired: "10000", payTo: second }),
        ],
      }),
    );
    const { quotes } = quoteWithRejections(c);
    const selected = selectQuote(quotes);
    expect(selected?.payTo).toBe(first.toLowerCase());
  });

  it("returns null when there are no quotes", () => {
    expect(selectQuote([])).toBeNull();
  });
});

describe("X402Payer.detects — §3.1", () => {
  const payer = new X402Payer();
  it("true for an x402 challenge (x402Version + accepts)", () => {
    expect(payer.detects(parseChallenge(challenge402()))).toBe(true);
  });
  it("false for a non-JSON body", () => {
    expect(payer.detects(parseChallenge("not json"))).toBe(false);
  });
});

describe("buildX402Payment — §2 EIP-3009 window math + nonce + one signature", () => {
  it("validAfter/validBefore: maxTimeoutSeconds ABSENT → default window", async () => {
    const quote = quoteFrom({ maxTimeoutSeconds: undefined });
    const signer = new FakeSigner();
    const rng = fixedRandom(new Uint8Array(32).fill(7));
    const proof = await buildX402Payment(
      quote,
      signer,
      fakeDeps({ now: () => NOW_MS, random: rng.random, signer }),
    );
    expect(proof.validBeforeTs).toBe(NOW_SEC + PAYMENT_VALIDITY_DEFAULT_S);

    const payload = decodePaymentHeader(proof.headers[X_PAYMENT_HEADER]);
    expect(payload.payload.authorization.validAfter).toBe(String(NOW_SEC - CLOCK_SKEW_S));
    expect(payload.payload.authorization.validBefore).toBe(
      String(NOW_SEC + PAYMENT_VALIDITY_DEFAULT_S),
    );
  });

  it("validBefore: maxTimeoutSeconds BELOW cap → used as-is", async () => {
    const quote = quoteFrom({ maxTimeoutSeconds: 120 });
    const signer = new FakeSigner();
    const proof = await buildX402Payment(
      quote,
      signer,
      fakeDeps({ now: () => NOW_MS, random: fixedRandom(new Uint8Array(32).fill(3)).random, signer }),
    );
    expect(proof.validBeforeTs).toBe(NOW_SEC + 120);
  });

  it("validBefore: maxTimeoutSeconds ABOVE cap → clamped to PAYMENT_VALIDITY_MAX_S", async () => {
    const quote = quoteFrom({ maxTimeoutSeconds: 9999 });
    const signer = new FakeSigner();
    const proof = await buildX402Payment(
      quote,
      signer,
      fakeDeps({ now: () => NOW_MS, random: fixedRandom(new Uint8Array(32).fill(9)).random, signer }),
    );
    expect(proof.validBeforeTs).toBe(NOW_SEC + PAYMENT_VALIDITY_MAX_S);
  });

  it("nonce is EXACTLY the 32 bytes returned by deps.random", async () => {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) bytes[i] = (i * 7 + 1) & 0xff;
    const rng = fixedRandom(bytes);
    const signer = new FakeSigner();
    const proof = await buildX402Payment(
      quoteFrom(),
      signer,
      fakeDeps({ now: () => NOW_MS, random: rng.random, signer }),
    );
    expect(rng.emitted).toHaveLength(1);
    expect(proof.nonce).toBe(toHex(bytes));
    const payload = decodePaymentHeader(proof.headers[X_PAYMENT_HEADER]);
    expect(payload.payload.authorization.nonce).toBe(toHex(bytes));
  });

  it("calls signer.signTypedData EXACTLY once", async () => {
    const signer = new FakeSigner();
    await buildX402Payment(
      quoteFrom(),
      signer,
      fakeDeps({ now: () => NOW_MS, random: fixedRandom(new Uint8Array(32).fill(1)).random, signer }),
    );
    expect(signer.signCount).toBe(1);
  });

  it("throws if deps.random does not return 32 bytes (dep contract)", async () => {
    const signer = new FakeSigner();
    await expect(
      buildX402Payment(
        quoteFrom(),
        signer,
        fakeDeps({ now: () => NOW_MS, random: () => new Uint8Array(16), signer }),
      ),
    ).rejects.toThrow(/32 bytes/);
    expect(signer.signCount).toBe(0);
  });

  it("headers contain EXACTLY X-PAYMENT and nothing else", async () => {
    const signer = new FakeSigner();
    const proof = await buildX402Payment(
      quoteFrom(),
      signer,
      fakeDeps({ now: () => NOW_MS, random: fixedRandom(new Uint8Array(32).fill(2)).random, signer }),
    );
    expect(Object.keys(proof.headers)).toEqual([X_PAYMENT_HEADER]);
  });

  it("signs the correct TransferWithAuthorization typed data (domain + message)", async () => {
    const signer = new FakeSigner({ address: "0x00000000000000000000000000000000000000A1" });
    const quote = quoteFrom({ maxTimeoutSeconds: 120 });
    const rng = fixedRandom(new Uint8Array(32).fill(5));
    await buildX402Payment(
      quote,
      signer,
      fakeDeps({ now: () => NOW_MS, random: rng.random, signer }),
    );
    const td = signer.lastTypedData;
    expect(td).not.toBeNull();
    expect(td?.primaryType).toBe("TransferWithAuthorization");
    expect(td?.domain.name).toBe("USD Coin");
    expect(td?.domain.version).toBe("2");
    expect(td?.domain.chainId).toBe(8453); // base
    expect(td?.domain.verifyingContract).toBe(getAddress(quote.asset));
    expect(td?.message.from).toBe(getAddress(await signer.address()));
    expect(td?.message.to).toBe(getAddress(quote.payTo));
    expect(td?.message.value).toBe("10000");
    expect(td?.message.validAfter).toBe(String(NOW_SEC - CLOCK_SKEW_S));
    expect(td?.message.validBefore).toBe(String(NOW_SEC + 120));
    expect(td?.message.nonce).toBe(toHex(new Uint8Array(32).fill(5)));
  });

  it("encoded X-PAYMENT payload has scheme/network and a signature", async () => {
    const signer = new FakeSigner();
    const proof = await buildX402Payment(
      quoteFrom(),
      signer,
      fakeDeps({ now: () => NOW_MS, random: fixedRandom(new Uint8Array(32).fill(4)).random, signer }),
    );
    const payload = decodePaymentHeader(proof.headers[X_PAYMENT_HEADER]);
    expect(payload.x402Version).toBe(1);
    expect(payload.scheme).toBe("exact");
    expect(payload.network).toBe("base");
    expect(payload.payload.signature).toMatch(/^0x[0-9a-f]+$/i);
    expect(payload.payload.authorization.value).toBe("10000");
  });

  it("X402Payer.buildPayment delegates to buildX402Payment", async () => {
    const signer = new FakeSigner();
    const proof = await new X402Payer().buildPayment(
      quoteFrom(),
      signer,
      fakeDeps({ now: () => NOW_MS, random: fixedRandom(new Uint8Array(32).fill(6)).random, signer }),
    );
    expect(Object.keys(proof.headers)).toEqual([X_PAYMENT_HEADER]);
    expect(signer.signCount).toBe(1);
  });
});

describe("parseSettlementResponse — X-PAYMENT-RESPONSE round-trip + defensive null", () => {
  it("round-trips the same base64 JSON the package emits", () => {
    const settlement = {
      success: true,
      transaction: "0xabc123",
      network: "base-sepolia",
      payer: "0xdef456",
    };
    const header = safeBase64Encode(JSON.stringify(settlement));
    expect(parseSettlementResponse(header)).toEqual(settlement);
  });

  it("returns null on non-base64 / undecodable input", () => {
    expect(parseSettlementResponse("!!! not base64 !!!")).toBeNull();
  });

  it("returns null on base64 of non-JSON", () => {
    expect(parseSettlementResponse(safeBase64Encode("this is not json {"))).toBeNull();
  });

  it("returns null on a JSON primitive (not an object)", () => {
    expect(parseSettlementResponse(safeBase64Encode("5"))).toBeNull();
  });
});

// ===========================================================================
// §3.1a — version echo, version filter, and the v2 payload envelope (WIRE-PARITY)
// ===========================================================================

function quoteFromV2(over: Record<string, unknown> = {}): PaymentQuote {
  const c = parseChallenge(challenge402V2({ accepts: [acceptsEntryV2(over)] }));
  const { quotes } = quoteWithRejections(c);
  expect(quotes).toHaveLength(1);
  return quotes[0];
}

describe("§3.1a rule 2 — version filter + version echo", () => {
  it("an unsupported x402Version (3) → zero quotes, tally { unsupported_x402_version: 1 }", () => {
    const c = parseChallenge(challenge402({ x402Version: 3 }));
    const { quotes, rejected } = quoteWithRejections(c);
    expect(quotes).toEqual([]);
    expect(rejected).toEqual({ unsupported_x402_version: 1 });
  });

  it("a v1 quote carries x402Version:1 and networkAsDeclared === canonical name", () => {
    const q = quoteFrom();
    expect(q.x402Version).toBe(1);
    expect(q.network).toBe("base");
    expect(q.networkAsDeclared).toBe("base");
  });

  it("a v2 quote carries x402Version:2, canonical network, and the RAW CAIP-2 declared string", () => {
    const q = quoteFromV2();
    expect(q.x402Version).toBe(2);
    expect(q.network).toBe("base-sepolia"); // canonical (policy/asset)
    expect(q.networkAsDeclared).toBe("eip155:84532"); // raw (payload echo)
    expect(q.amountAtomic).toBe("1000");
  });

  it("v1 challenge → payload x402Version 1 with top-level scheme/network (echoed raw)", async () => {
    const signer = new FakeSigner();
    const proof = await buildX402Payment(
      quoteFrom(),
      signer,
      fakeDeps({ now: () => NOW_MS, random: fixedRandom(new Uint8Array(32).fill(1)).random, signer }),
    );
    expect(Object.keys(proof.headers)).toEqual([X_PAYMENT_HEADER]);
    const payload = decodePaymentHeader(proof.headers[X_PAYMENT_HEADER]);
    expect(payload.x402Version).toBe(1);
    expect(payload.scheme).toBe("exact");
    expect(payload.network).toBe("base");
    expect(payload.accepted).toBeUndefined(); // v1 has no `accepted`
  });

  it("v2 challenge → PAYMENT-SIGNATURE payload with `accepted` (raw CAIP-2 network + amount), no top-level scheme/network", async () => {
    const signer = new FakeSigner();
    const proof = await buildX402Payment(
      quoteFromV2(),
      signer,
      fakeDeps({ now: () => NOW_MS, random: fixedRandom(new Uint8Array(32).fill(2)).random, signer }),
    );
    expect(Object.keys(proof.headers)).toEqual([PAYMENT_SIGNATURE_HEADER]);
    expect(proof.headers[X_PAYMENT_HEADER]).toBeUndefined();
    const payload = decodePaymentHeader(proof.headers[PAYMENT_SIGNATURE_HEADER]);
    expect(payload.x402Version).toBe(2);
    expect(payload.scheme).toBeUndefined(); // v2 drops top-level scheme/network
    expect(payload.network).toBeUndefined();
    // `accepted` echoes the raw v2 requirements entry byte-for-byte (§3.1a rule 3).
    expect(payload.accepted?.network).toBe("eip155:84532"); // RAW CAIP-2, not canonical
    expect(payload.accepted?.amount).toBe("1000"); // v2 amount field
    expect(payload.accepted?.payTo).toBe("0xffa3e5fa7AE5F0DD1fd196Cbd41d40325E4Aa831");
    // The signed authorization is present under payload regardless of version.
    expect(payload.payload.authorization.value).toBe("1000");
  });

  it("v2 buildPayment derives the EIP-712 domain chainId from the CANONICAL network (84532)", async () => {
    const signer = new FakeSigner();
    await buildX402Payment(
      quoteFromV2(),
      signer,
      fakeDeps({ now: () => NOW_MS, random: fixedRandom(new Uint8Array(32).fill(3)).random, signer }),
    );
    const td = signer.lastTypedData;
    expect(td?.primaryType).toBe("TransferWithAuthorization");
    expect(td?.domain.chainId).toBe(84532); // base-sepolia
    expect(td?.domain.name).toBe("USDC"); // from the v2 entry's extra
    expect(td?.domain.version).toBe("2");
  });
});

// ---------------------------------------------------------------------------
// Helper: decode the X-PAYMENT base64 payload the same way the facilitator would.
// ---------------------------------------------------------------------------
type DecodedPayment = {
  x402Version: number;
  scheme?: string; // v1 only (v2 drops top-level scheme/network for `accepted`)
  network?: string; // v1 only
  accepted?: {
    scheme: string;
    network: string;
    amount: string;
    asset: string;
    payTo: string;
    maxTimeoutSeconds: number;
    extra?: Record<string, unknown>;
  }; // v2 only (§3.1a)
  payload: {
    signature: string;
    authorization: {
      from: string;
      to: string;
      value: string;
      validAfter: string;
      validBefore: string;
      nonce: string;
    };
  };
};

function decodePaymentHeader(header: string): DecodedPayment {
  return JSON.parse(safeBase64Decode(header)) as DecodedPayment;
}
