/**
 * P3′ payfetch — pipeline integration tests (SPEC §4.2, §5, §6, §7, §11, §14).
 *
 * The load-bearing money-path suite, driven end to end through `createPayfetch`
 * with hermetic fakes (FakeFetch + in-memory fs + injected resolver/clock/delay).
 * Count-asserted where money moves: no-double-pay, dry-run signs nothing,
 * reserve-before-pay, unknown-settlement over-counts, boundary math, the §5.2
 * table, auto-deny, the approval matrix, transport guarding, reserved-header
 * hygiene, test-mode mainnet refusal, key-hygiene.
 */

import { safeBase64Decode } from "@x402/core/utils";
import { describe, expect, it } from "vitest";

import { createPayfetch } from "../src/index.js";
import { GUARD_ADVISORY_BUDGET_MS, GUARD_SCREEN_BUDGET_MS } from "../src/core/constants.js";
import { adaptFetch } from "../src/core/transport.js";
import {
  applyJsonContentTypeDefault,
  classifyFromParts,
  classifyTerminal,
} from "../src/core/pipeline.js";
import type { TransportResult } from "../src/core/transport.js";
import type { Policy } from "../src/core/policy.js";
import { createSafetyGuard, createTrustGuard } from "../src/guards/index.js";
import { trustScoreUrl } from "../src/guards/internal.js";
import {
  CountingPayer,
  FakeFetch,
  FakeSigner,
  acceptsEntry,
  challenge402,
  challenge402V2,
  challengeHeaderResponse,
  fakeClock,
  fakeDeps,
  fakeGuard,
  hostResolver,
  immediateDelay,
  inMemoryFs,
  makeQuote,
  neverResolves,
  settlementResponse,
  type LogEntry,
} from "./fakes.js";
import {
  ScriptedGuardFetch,
  gJson,
  gStatus,
  guardRuntime,
  safetyBasic,
  safetyConfig,
  safetyDegraded,
  trustConfig,
  trustReliable,
} from "./fakes_guards.js";
import type { ElicitFn } from "../src/payer/types.js";
import type { PrePayGuard } from "../src/guards/types.js";

const NOW = Date.UTC(2023, 10, 14, 12, 0, 0);
const URL1 = "https://api.example.com/data";

type ClientOpts = {
  fetch: FakeFetch;
  clock?: ReturnType<typeof fakeClock>;
  policy?: Parameters<typeof createPayfetch>[0]["policy"];
  // fakeGuard(...) results OR a real guard (createTrustGuard/createSafetyGuard) —
  // the hot-reload integration test wires a real guard built with a stale mode.
  guards?: PrePayGuard[];
  elicit?: ElicitFn | null;
  testMode?: boolean;
  approver?: boolean;
  resolve?: (h: string) => Promise<string[]>;
  payers?: [CountingPayer];
  signer?: FakeSigner;
  /**
   * Override `deps.fetch` (the seam a budget-reserving guardFetch dials through)
   * independently of the transport's `fetch`. Lets a test observe the `redirect`
   * init option a guard payment carries (L5). Defaults to the FakeFetch's fetch.
   */
  depsFetch?: typeof fetch;
  /**
   * Override the injected `delay` (elicit + guard timeout race). Defaults to
   * `immediateDelay` (timeouts fire instantly). A test that wires a REAL async
   * guard and wants its verdict (not a timeout) passes `neverTimeout` so the
   * guard's check() always wins the race.
   */
  delay?: (ms: number) => Promise<void>;
};

/**
 * A delay that never fires — so the runGuard timeout branch never wins and a real
 * (async) guard's check() always resolves the race with its true verdict.
 */
const neverTimeout = (): Promise<void> => neverResolves<void>();

function mkClient(o: ClientOpts) {
  const clock = o.clock ?? fakeClock(NOW);
  const signer = o.signer ?? new FakeSigner();
  const logSink: LogEntry[] = [];
  const fs = inMemoryFs();
  const deps = fakeDeps({
    fetch: o.depsFetch ?? o.fetch.fetch,
    now: clock.now,
    signer,
    elicit: o.elicit ?? null,
    dataDir: "/data",
    logSink,
  });
  const client = createPayfetch({
    deps,
    fs,
    httpClient: adaptFetch(o.fetch.fetch),
    resolve: o.resolve ?? hostResolver(),
    delay: o.delay ?? immediateDelay,
    testMode: o.testMode ?? false,
    approver: o.approver ?? false,
    guards: o.guards ?? [],
    payers: o.payers,
    policy: o.policy,
  });
  return { client, signer, fetch: o.fetch, logSink, fs, clock };
}

const PAID_OK = settlementResponse({ success: true, transaction: "0xtx" });

// ---------------------------------------------------------------------------

describe("happy path — free + paid_delivered", () => {
  it("non-402 → free, no payment, one receipt", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 200, textBody: "hello" });
    const { client, signer } = mkClient({ fetch });
    const { response, receipt } = await client.fetch(URL1);
    expect(receipt.outcome).toBe("free");
    expect(signer.signCount).toBe(0);
    expect(await response!.text()).toBe("hello");
  });

  it("402 → pay → 200 + settlement confirmed → paid_delivered (ONE signature)", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK);
    const { client, signer } = mkClient({ fetch });
    const { receipt } = await client.fetch(URL1);
    expect(receipt.outcome).toBe("paid_delivered");
    expect(receipt.payment?.settlementConfirmed).toBe(true);
    expect(receipt.payment?.txRef).toBe("0xtx");
    expect(receipt.payment?.settledAmountUsd).toBeCloseTo(0.01, 9);
    expect(signer.signCount).toBe(1);
  });
});

describe("no-double-pay (SPEC §5.3, count-asserted)", () => {
  it("a second 402 on retry → exactly ONE buildPayment; payment_rejected; hold kept then expiry-released", async () => {
    const fetch = new FakeFetch().on(
      "GET",
      URL1,
      { status: 402, jsonBody: challenge402() },
      { status: 402, jsonBody: challenge402() },
    );
    const payer = new CountingPayer();
    const { client, signer, clock } = mkClient({ fetch, payers: [payer] });
    const { receipt } = await client.fetch(URL1);
    expect(receipt.outcome).toBe("payment_rejected");
    expect(payer.buildCount).toBe(1);
    expect(signer.signCount).toBe(1);

    // Hold KEPT until validBefore + margin.
    let status = await client.status();
    expect(status.holds).toHaveLength(1);
    const vb = status.holds[0].validBeforeTs;
    clock.set((vb + 60) * 1000 - 1);
    expect((await client.status()).holds).toHaveLength(1); // still valid → not released
    clock.set((vb + 60) * 1000);
    expect((await client.status()).holds).toHaveLength(0); // released past margin
  });
});

describe("dry-run / quote sign and reserve nothing (SPEC §4.2 D9)", () => {
  it("dryRun → outcome dry_run, zero signatures, zero holds", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() });
    const { client, signer } = mkClient({ fetch });
    const { receipt } = await client.fetch(URL1, {}, { dryRun: true });
    expect(receipt.outcome).toBe("dry_run");
    expect(signer.signCount).toBe(0);
    expect((await client.status()).holds).toHaveLength(0);
  });

  it("quote() → dry_run decision, zero signatures", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() });
    const { client, signer } = mkClient({ fetch });
    const { decision } = await client.quote(URL1);
    expect(decision.decision).toBe("would_pay");
    expect(decision.quote?.amountUsd).toBeCloseTo(0.01, 9);
    expect(signer.signCount).toBe(0);
  });
});

describe("reserve-before-pay (SPEC §5.1) — failed reservation ⇒ zero buildPayment", () => {
  it("daily cap below the quote → budget_exhausted:day, no signature", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK);
    const { client, signer } = mkClient({
      fetch,
      policy: { caps: { dailyUsd: 0.005, perCallUsd: 1, perHostDailyUsd: 1, totalUsd: null } },
    });
    const { receipt } = await client.fetch(URL1);
    expect(receipt.outcome).toBe("policy_denied");
    expect(receipt.denyCode).toBe("budget_exhausted:day");
    expect(receipt.notes).toContain("budget_exhausted:day");
    expect(signer.signCount).toBe(0);
  });
});

describe("unknown-settlement over-counts (SPEC §5.2)", () => {
  it("5xx on the paid retry → unknown_settlement, hold KEPT, blocks a marginal reservation", async () => {
    const fetch = new FakeFetch().on(
      "GET",
      URL1,
      { status: 402, jsonBody: challenge402({ accepts: [acceptsEntry({ maxAmountRequired: "600000" })] }) },
      { status: 503, textBody: "err" },
    );
    const { client, signer } = mkClient({
      fetch,
      policy: { approval: { thresholdUsd: 1, mode: "elicit", elicitFallback: "deny" } },
    });
    const { receipt } = await client.fetch(URL1);
    expect(receipt.outcome).toBe("unknown_settlement");
    expect(signer.signCount).toBe(1);
    const status = await client.status();
    expect(status.holds).toHaveLength(1); // $0.60 held on api.example.com (cap $1.00)
    expect(status.holds[0].amountUsd).toBeCloseTo(0.6, 9);
  });
});

describe("per-call boundary + maxAmountUsd tightens only (SPEC §4.2 D7, §0)", () => {
  const pricey = () => challenge402({ accepts: [acceptsEntry({ maxAmountRequired: "10000" })] }); // $0.01
  it("quote exactly at the per-call cap passes; over the cap denies", async () => {
    const fetchOk = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: pricey() }, PAID_OK);
    const at = mkClient({ fetch: fetchOk, policy: { caps: { perCallUsd: 0.01, dailyUsd: 2, perHostDailyUsd: 1, totalUsd: null } } });
    expect((await at.client.fetch(URL1)).receipt.outcome).toBe("paid_delivered");

    const fetchOver = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: pricey() }, PAID_OK);
    const over = mkClient({ fetch: fetchOver, policy: { caps: { perCallUsd: 0.009, dailyUsd: 2, perHostDailyUsd: 1, totalUsd: null } } });
    const r = await over.client.fetch(URL1);
    expect(r.receipt.denyCode).toBe("per_call_cap_exceeded");
    expect(over.signer.signCount).toBe(0);
  });

  it("maxAmountUsd below the quote tightens (deny); above the cap does not loosen", async () => {
    const f1 = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: pricey() }, PAID_OK);
    const c1 = mkClient({ fetch: f1 });
    expect((await c1.client.fetch(URL1, {}, { maxAmountUsd: 0.005 })).receipt.denyCode).toBe(
      "per_call_cap_exceeded",
    );

    // maxAmountUsd huge cannot exceed the policy perCall cap $1.00 (still bounded).
    const f2 = new FakeFetch().on(
      "GET",
      URL1,
      { status: 402, jsonBody: challenge402({ accepts: [acceptsEntry({ maxAmountRequired: "2000000" })] }) }, // $2.00
      PAID_OK,
    );
    const c2 = mkClient({ fetch: f2 });
    const r = await c2.client.fetch(URL1, {}, { maxAmountUsd: 1000 });
    expect(r.receipt.denyCode).toBe("per_call_cap_exceeded"); // $2.00 > policy $1.00
  });
});

describe("§5.2 hold-disposition table (classifyFromParts, row by row)", () => {
  const q = makeQuote(0.01);
  const rows: [string, number, { success: boolean } | null, string, "settle" | "keep", boolean][] = [
    ["2xx + confirmed", 200, { success: true }, "paid_delivered", "settle", true],
    ["2xx + no settlement", 200, null, "paid_delivered", "settle", false],
    ["2xx + failed settlement", 200, { success: false }, "paid_delivered", "settle", false],
    ["non-2xx + confirmed", 500, { success: true }, "paid_not_delivered", "settle", true],
    ["402-again", 402, null, "payment_rejected", "keep", false],
    ["4xx no settlement", 404, null, "payment_rejected", "keep", false],
    ["5xx no settlement", 503, null, "unknown_settlement", "keep", false],
  ];
  for (const [name, status, settlement, outcome, disp, confirmed] of rows) {
    it(name, () => {
      const c = classifyFromParts(status, settlement, q);
      expect(c.outcome).toBe(outcome);
      expect(c.holdDisposition).toBe(disp);
      expect(c.settlementConfirmed).toBe(confirmed);
    });
  }
  it("2xx without settlement carries the settlement_unconfirmed note", () => {
    expect(classifyFromParts(200, null, q).note).toBe("settlement_unconfirmed");
  });

  // Row 6 + the retry-transport-error disposition (via classifyTerminal). ALL
  // keep the hold — a built signature is money in the wild (SPEC §5.2/§0).
  const errResult = (error: TransportResult["error"]): TransportResult => ({
    ok: false, error, finalUrl: "https://x", finalHost: "x", status: null, headers: null,
    contentType: null, rawBody: null, bodyBytes: null, bodySha256: null, hardCapped: false,
    hopChain: [], redirectCount: 0, notes: [], totalMs: 0,
  });
  it("retry guard-stage failure (provably never sent) → fetch_error, hold KEPT", () => {
    const c = classifyTerminal(errResult("private_target_blocked"), q);
    expect(c.outcome).toBe("fetch_error");
    expect(c.holdDisposition).toBe("keep");
  });
  it("retry network error (may have been sent) → unknown_settlement, hold KEPT", () => {
    const c = classifyTerminal(errResult("fetch_error"), q);
    expect(c.outcome).toBe("unknown_settlement");
    expect(c.holdDisposition).toBe("keep");
  });
});

describe("auto-deny circuit breaker (SPEC §5.4, D6)", () => {
  it("two confirmed strikes engage; a third request is host_auto_denied with no payment", async () => {
    // Each request 402s again on retry → payment_rejected (confirmed strike).
    const rej = () => ({ status: 402, jsonBody: challenge402() }) as const;
    const fetch = new FakeFetch().on("GET", URL1, rej(), rej());
    const { client, signer } = mkClient({ fetch });
    expect((await client.fetch(URL1)).receipt.outcome).toBe("payment_rejected"); // strike 1
    expect((await client.fetch(URL1)).receipt.outcome).toBe("payment_rejected"); // strike 2 → engage
    const signsSoFar = signer.signCount;
    const third = await client.fetch(URL1);
    expect(third.receipt.outcome).toBe("policy_denied");
    expect(third.receipt.denyCode).toBe("host_auto_denied");
    expect(signer.signCount).toBe(signsSoFar); // D6 denies before any payment
  });
});

describe("policy D-steps: deny-beats-allow, allowlist default-deny, wildcard, verdictPath", () => {
  it("deny wins over allow (D4 before D5)", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() });
    const { client } = mkClient({
      fetch,
      policy: { mode: "allowlist", allow: ["api.example.com"], deny: ["api.example.com"] },
    });
    const { receipt } = await client.fetch(URL1);
    expect(receipt.denyCode).toBe("host_denied");
    expect(receipt.verdictPath).toEqual(["parse", "quotes", "select", "deny_list"]);
  });

  it("allowlist mode denies a host not on the allow list", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() });
    const { client } = mkClient({ fetch, policy: { mode: "allowlist", allow: ["other.com"] } });
    expect((await client.fetch(URL1)).receipt.denyCode).toBe("host_not_allowlisted");
  });

  it("wildcard allows a subdomain but not the apex", async () => {
    const sub = "https://api.example.com/x";
    const apex = "https://example.com/x";
    const fSub = new FakeFetch().on("GET", sub, { status: 402, jsonBody: challenge402() }, PAID_OK);
    const cSub = mkClient({ fetch: fSub, policy: { mode: "allowlist", allow: ["*.example.com"] } });
    expect((await cSub.client.fetch(sub)).receipt.outcome).toBe("paid_delivered");

    const fApex = new FakeFetch().on("GET", apex, { status: 402, jsonBody: challenge402() });
    const cApex = mkClient({ fetch: fApex, policy: { mode: "allowlist", allow: ["*.example.com"] } });
    expect((await cApex.client.fetch(apex)).receipt.denyCode).toBe("host_not_allowlisted");
  });

  it("malformed 402 → malformed_402; unsupported terms → unsupported_terms with tally", async () => {
    const fBad = new FakeFetch().on("GET", URL1, { status: 402, textBody: "not json" });
    expect((await mkClient({ fetch: fBad }).client.fetch(URL1)).receipt.denyCode).toBe("malformed_402");

    const fUpto = new FakeFetch().on("GET", URL1, {
      status: 402,
      jsonBody: challenge402({ accepts: [acceptsEntry({ scheme: "upto" })] }),
    });
    const r = await mkClient({ fetch: fUpto }).client.fetch(URL1);
    expect(r.receipt.denyCode).toBe("unsupported_terms");
    expect(r.receipt.rejectedQuotes).toEqual({ unsupported_scheme_upto: 1 });
    expect(r.receipt.notes).toContain("unsupported_scheme_upto");
  });
});

describe("approval matrix (SPEC §6)", () => {
  const pricey = () => challenge402({ accepts: [acceptsEntry({ maxAmountRequired: "300000" })] }); // $0.30

  it("at the threshold no approval is needed; over the threshold approval triggers", async () => {
    // threshold 0.30, quote exactly 0.30 → NOT > threshold → pays without elicit.
    const fAt = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: pricey() }, PAID_OK);
    const cAt = mkClient({ fetch: fAt, elicit: null, policy: { approval: { thresholdUsd: 0.3, mode: "elicit", elicitFallback: "deny" } } });
    expect((await cAt.client.fetch(URL1)).receipt.outcome).toBe("paid_delivered");
  });

  it("elicit approve → pays; elicit deny → approval_denied; elicit timeout → approval_timeout", async () => {
    const approve: ElicitFn = async () => ({ approved: true });
    const fA = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: pricey() }, PAID_OK);
    expect((await mkClient({ fetch: fA, elicit: approve }).client.fetch(URL1)).receipt.outcome).toBe(
      "paid_delivered",
    );

    const deny: ElicitFn = async () => ({ approved: false });
    const fD = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: pricey() }, PAID_OK);
    const cd = mkClient({ fetch: fD, elicit: deny });
    const rd = await cd.client.fetch(URL1);
    expect(rd.receipt.outcome).toBe("approval_denied");
    expect(cd.signer.signCount).toBe(0);

    const hang: ElicitFn = () => neverResolves();
    const fT = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: pricey() }, PAID_OK);
    const ct = mkClient({ fetch: fT, elicit: hang }); // immediateDelay → timeout wins
    const rt = await ct.client.fetch(URL1);
    expect(rt.receipt.outcome).toBe("approval_timeout");
    expect(ct.signer.signCount).toBe(0);
  });

  it("elicit===null fallback: deny → approval_denied; queue → approval_queued", async () => {
    const fDeny = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: pricey() }, PAID_OK);
    const rDeny = await mkClient({
      fetch: fDeny,
      elicit: null,
      policy: { approval: { thresholdUsd: 0.1, mode: "elicit", elicitFallback: "deny" } },
    }).client.fetch(URL1);
    expect(rDeny.receipt.outcome).toBe("approval_denied");
    expect(rDeny.receipt.notes).toContain("elicit_unsupported_fallback:deny");

    const fQueue = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: pricey() }, PAID_OK);
    const rQueue = await mkClient({
      fetch: fQueue,
      elicit: null,
      policy: { approval: { thresholdUsd: 0.1, mode: "elicit", elicitFallback: "queue" } },
    }).client.fetch(URL1);
    expect(rQueue.receipt.outcome).toBe("approval_queued");
    expect(rQueue.receipt.notes).toContain("elicit_unsupported_fallback:queue");
  });

  it("queue mode + in-session approver: self-approve is REFUSED (M6); re-run stays queued, never paid", async () => {
    // M6: with an in-session approver the tool-driven agent both requests AND
    // approves — no requester/approver separation. Its own queued payment can no
    // longer be granted from the session, so a matching re-run re-queues and is
    // never paid. (A non-forbidden approve path is impossible in queue-capable
    // mode: nothing queues unless the mode is queue-capable.)
    const fetch = new FakeFetch().on(
      "GET",
      URL1,
      { status: 402, jsonBody: pricey() },
      { status: 402, jsonBody: pricey() },
    );
    const c = mkClient({
      fetch,
      approver: true,
      policy: { approval: { thresholdUsd: 0.1, mode: "queue", elicitFallback: "deny" } },
    });
    const first = await c.client.fetch(URL1);
    expect(first.receipt.outcome).toBe("approval_queued");

    const pending = c.client.engine.listApprovals();
    expect(pending).toHaveLength(1);
    expect(c.client.engine.resolveApproval(pending[0].approvalId, true)).toEqual({
      ok: false,
      error: "queue_self_approval_forbidden",
    });

    const rerun = await c.client.fetch(URL1);
    expect(rerun.receipt.outcome).toBe("approval_queued"); // no grant → still queued
    expect(c.signer.signCount).toBe(0); // nothing ever paid
  });

  it("approve_pending is refused without PAYFETCH_APPROVER (approver_not_enabled)", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: pricey() });
    const c = mkClient({
      fetch,
      approver: false,
      policy: { approval: { thresholdUsd: 0.1, mode: "queue", elicitFallback: "deny" } },
    });
    await c.client.fetch(URL1); // creates a pending entry
    const pending = c.client.engine.listApprovals();
    expect(c.client.engine.resolveApproval(pending[0].approvalId, true)).toEqual({
      ok: false,
      error: "approver_not_enabled",
    });
  });

  it("approved-then-reserve-fails → honest deny (caps outrank approval)", async () => {
    const approve: ElicitFn = async () => ({ approved: true });
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: pricey() }, PAID_OK);
    const c = mkClient({
      fetch,
      elicit: approve,
      policy: { caps: { dailyUsd: 0.005, perCallUsd: 1, perHostDailyUsd: 1, totalUsd: null } },
    });
    const r = await c.client.fetch(URL1);
    expect(r.receipt.denyCode).toBe("budget_exhausted:day");
    expect(c.signer.signCount).toBe(0);
  });
});

describe("transport integration + reserved-header hygiene (SPEC §11)", () => {
  it("a private-resolving hostname is blocked with ZERO payment attempts", async () => {
    const url = "https://internal.example/x";
    const fetch = new FakeFetch().on("GET", url, { status: 402, jsonBody: challenge402() });
    const { client, signer, fetch: f } = mkClient({
      fetch,
      resolve: hostResolver({ "internal.example": ["10.0.0.9"] }),
    });
    const { receipt, response } = await client.fetch(url);
    expect(receipt.outcome).toBe("fetch_error");
    expect(receipt.notes).toContain("private_target_blocked");
    expect(response).toBeNull();
    expect(signer.signCount).toBe(0);
    expect(f.calls).toHaveLength(0); // never dialed
  });

  it("a private-IP LITERAL target is blocked with ZERO payment attempts", async () => {
    const url = "http://10.0.0.1/pay";
    const fetch = new FakeFetch().on("GET", url, { status: 402, jsonBody: challenge402() });
    const { client, signer, fetch: f } = mkClient({
      fetch,
      resolve: hostResolver({ "10.0.0.1": ["10.0.0.1"] }),
    });
    const { receipt } = await client.fetch(url);
    expect(receipt.outcome).toBe("fetch_error");
    expect(receipt.notes).toContain("private_target_blocked");
    expect(signer.signCount).toBe(0);
    expect(f.calls).toHaveLength(0);
  });

  it("a redirect from an allowed host to a DENIED host evaluates policy at the final host", async () => {
    const start = "https://ok.com/go";
    const dest = "https://denied.com/pay";
    const fetch = new FakeFetch()
      .on("GET", start, { status: 302, headers: { location: dest } })
      .on("GET", dest, { status: 402, jsonBody: challenge402() });
    const { client } = mkClient({ fetch, policy: { deny: ["denied.com"] } });
    const { receipt } = await client.fetch(start);
    expect(receipt.host).toBe("denied.com");
    expect(receipt.denyCode).toBe("host_denied");
  });

  it("strips user-supplied X-PAYMENT and sends OUR proof header on the paid retry", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK);
    const { client, fetch: f } = mkClient({ fetch });
    await client.fetch(URL1, { headers: { "X-PAYMENT": "evil", "X-Custom": "keep" } });
    const leg1 = f.calls[0];
    expect(leg1.headers["x-payment"]).toBeUndefined(); // user X-PAYMENT stripped
    expect(leg1.headers["x-custom"]).toBe("keep");
    const retry = f.calls[1];
    expect(retry.headers["x-payment"]).toBeDefined();
    expect(retry.headers["x-payment"]).not.toBe("evil"); // our real proof header
  });

  it("strips a user-supplied PAYMENT-SIGNATURE and sends our v2 proof only", async () => {
    const fetch = new FakeFetch().on(
      "GET",
      URL1,
      challengeHeaderResponse(challenge402V2()),
      settlementResponse({ success: true, transaction: "0xstripped" }),
    );
    const { client, fetch: f } = mkClient({ fetch, testMode: true });
    await client.fetch(URL1, {
      headers: { "PAYMENT-SIGNATURE": "evil", "X-PAYMENT": "also-evil", "X-Custom": "keep" },
    });
    const leg1 = f.calls[0];
    expect(leg1.headers["payment-signature"]).toBeUndefined();
    expect(leg1.headers["x-payment"]).toBeUndefined();
    expect(leg1.headers["x-custom"]).toBe("keep");
    const retry = f.calls[1];
    expect(retry.headers["x-payment"]).toBeUndefined();
    expect(retry.headers["payment-signature"]).toBeDefined();
    expect(retry.headers["payment-signature"]).not.toBe("evil");
  });
});

describe("Content-Type auto-default for JSON bodies (1.0.1 §1)", () => {
  // The $0.007-dies-on-a-header bug: a JSON POST with no Content-Type is sent as
  // text/plain, and the seller 400s the ALREADY-SIGNED paid retry → payment_rejected.
  const EXA_BODY = JSON.stringify({ query: "latest x402 news", numResults: 3 });

  it("defaults application/json on BOTH the probe AND the paid retry", async () => {
    const fetch = new FakeFetch().on("POST", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK);
    const { client, fetch: f } = mkClient({ fetch });
    const { receipt } = await client.fetch(URL1, { method: "POST", body: EXA_BODY });
    expect(receipt.outcome).toBe("paid_delivered"); // no longer dies on the header
    expect(f.calls[0].headers["content-type"]).toBe("application/json"); // probe leg
    expect(f.calls[1].headers["content-type"]).toBe("application/json"); // paid retry leg
    expect(f.calls[1].body).toBe(EXA_BODY); // same body, now correctly typed
  });

  it("an EXPLICIT caller Content-Type always wins (never overridden)", async () => {
    const fetch = new FakeFetch().on("POST", URL1, { status: 200, textBody: "ok" });
    const { client, fetch: f } = mkClient({ fetch });
    await client.fetch(URL1, {
      method: "POST",
      body: EXA_BODY,
      headers: { "Content-Type": "application/vnd.custom+json" },
    });
    expect(f.calls[0].headers["content-type"]).toBe("application/vnd.custom+json");
  });

  it("a NON-JSON body is left untouched (no Content-Type invented)", async () => {
    const fetch = new FakeFetch().on("POST", URL1, { status: 200, textBody: "ok" });
    const { client, fetch: f } = mkClient({ fetch });
    await client.fetch(URL1, { method: "POST", body: "just plain text" });
    expect(f.calls[0].headers["content-type"]).toBeUndefined();
  });

  it("applyJsonContentTypeDefault: object/array JSON → default; scalar/non-JSON/empty/explicit → untouched", () => {
    // Adds only for an unambiguous JSON object/array body with no caller header.
    expect(applyJsonContentTypeDefault({}, '{"a":1}')["Content-Type"]).toBe("application/json");
    expect(applyJsonContentTypeDefault({}, "[1,2,3]")["Content-Type"]).toBe("application/json");
    // Scalars are ambiguous (could be text) → never relabeled.
    expect(applyJsonContentTypeDefault({}, "42")["Content-Type"]).toBeUndefined();
    expect(applyJsonContentTypeDefault({}, '"hello"')["Content-Type"]).toBeUndefined();
    // Not JSON, or empty/absent → untouched.
    expect(applyJsonContentTypeDefault({}, "not json")["Content-Type"]).toBeUndefined();
    expect(applyJsonContentTypeDefault({}, "")["Content-Type"]).toBeUndefined();
    expect(applyJsonContentTypeDefault({}, null)["Content-Type"]).toBeUndefined();
    // Explicit header (any case) wins and is preserved verbatim.
    expect(applyJsonContentTypeDefault({ "content-type": "text/plain" }, '{"a":1}')).toEqual({
      "content-type": "text/plain",
    });
  });
});

describe("guards D8 (SPEC §7.4) — block denies, warn continues", () => {
  it("a blocking guard → guard_blocked with no payment", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK);
    const guard = fakeGuard("trust", { verdict: "block" });
    const { client, signer } = mkClient({ fetch, guards: [guard] });
    const { receipt } = await client.fetch(URL1);
    expect(receipt.outcome).toBe("guard_blocked");
    expect(receipt.notes).toContain("guard_blocked:trust");
    expect(signer.signCount).toBe(0);
    expect(guard.calls).toBe(1);
  });

  it("a warning guard attaches guard_warn and continues to pay", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK);
    const guard = fakeGuard("trust", { verdict: "warn" });
    const { client } = mkClient({ fetch, guards: [guard] });
    const { receipt } = await client.fetch(URL1);
    expect(receipt.outcome).toBe("paid_delivered");
    expect(receipt.notes).toContain("guard_warn:trust");
  });

  it("a crashing guard is contained as unavailable, never a pipeline exception", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK);
    const guard = fakeGuard("trust", { verdict: "pass" }, { throws: true });
    const { client } = mkClient({ fetch, guards: [guard] });
    const { receipt } = await client.fetch(URL1);
    expect(receipt.outcome).toBe("paid_delivered");
    expect(receipt.notes).toContain("guard_unavailable:trust");
  });
});

describe("guard unavailable × mode × onUnavailable (SPEC §7.2/§7.3) — pipeline resolution", () => {
  // The pipeline (not the guard) resolves "unavailable": advisory → proceed +
  // note; enforce → per onUnavailable (default "block" = fail closed).
  const route = () =>
    new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK);
  const trustPolicy = (mode: "advisory" | "enforce", onUnavailable: "proceed" | "block") => ({
    guards: { trust: { mode, onUnavailable } },
  });

  it("enforce + onUnavailable:block → guard_blocked, unavailable note, ZERO payments/reservations", async () => {
    const payer = new CountingPayer();
    const guard = fakeGuard("trust", { verdict: "unavailable" });
    const c = mkClient({
      fetch: route(), guards: [guard], payers: [payer],
      policy: trustPolicy("enforce", "block"),
    });
    const { receipt } = await c.client.fetch(URL1);
    expect(receipt.outcome).toBe("guard_blocked");
    expect(receipt.denyCode).toBe("guard_blocked");
    expect(receipt.notes).toContain("guard_unavailable:trust");
    expect(receipt.notes).not.toContain("guard_blocked:trust"); // unavailable, not a verdict-block
    expect(payer.buildCount).toBe(0);
    expect(c.signer.signCount).toBe(0);
    expect((await c.client.status()).holds).toHaveLength(0); // no reservation
  });

  it("enforce + onUnavailable:proceed → pays, with the unavailable note on the receipt", async () => {
    const guard = fakeGuard("trust", { verdict: "unavailable" });
    const c = mkClient({
      fetch: route(), guards: [guard], policy: trustPolicy("enforce", "proceed"),
    });
    const { receipt } = await c.client.fetch(URL1);
    expect(receipt.outcome).toBe("paid_delivered");
    expect(receipt.notes).toContain("guard_unavailable:trust");
  });

  it("advisory → proceeds even with onUnavailable:block set (advisory ignores it)", async () => {
    const guard = fakeGuard("trust", { verdict: "unavailable" });
    const c = mkClient({
      fetch: route(), guards: [guard], policy: trustPolicy("advisory", "block"),
    });
    const { receipt } = await c.client.fetch(URL1);
    expect(receipt.outcome).toBe("paid_delivered");
    expect(receipt.notes).toContain("guard_unavailable:trust");
  });

  // Same trio for the SAFETY guard (applies() gated on context.tokenAddress).
  const safetyGuard = () =>
    fakeGuard("safety", { verdict: "unavailable" }, {
      appliesFn: (i) => i.context.tokenAddress !== undefined,
    });
  const safetyPolicy = (mode: "advisory" | "enforce", onUnavailable: "proceed" | "block") => ({
    guards: { safety: { enabled: true, mode, onUnavailable } },
  });
  const TOKEN = { tokenAddress: "0x1111111111111111111111111111111111111111", chain: "base" as const };

  it("safety enforce + block → guard_blocked with zero payments; without tokenAddress the guard is skipped", async () => {
    const payer = new CountingPayer();
    const c = mkClient({
      fetch: route(), guards: [safetyGuard()], payers: [payer],
      policy: safetyPolicy("enforce", "block"),
    });
    const { receipt } = await c.client.fetch(URL1, {}, TOKEN);
    expect(receipt.outcome).toBe("guard_blocked");
    expect(receipt.notes).toContain("guard_unavailable:safety");
    expect(payer.buildCount).toBe(0);

    // No tokenAddress → applies() false → guard never consulted → pays.
    const c2 = mkClient({
      fetch: route(), guards: [safetyGuard()], policy: safetyPolicy("enforce", "block"),
    });
    const r2 = await c2.client.fetch(URL1);
    expect(r2.receipt.outcome).toBe("paid_delivered");
    expect(r2.receipt.guards).toHaveLength(0);
  });

  it("safety enforce + proceed → pays with note", async () => {
    const c = mkClient({
      fetch: route(), guards: [safetyGuard()], policy: safetyPolicy("enforce", "proceed"),
    });
    const { receipt } = await c.client.fetch(URL1, {}, TOKEN);
    expect(receipt.outcome).toBe("paid_delivered");
    expect(receipt.notes).toContain("guard_unavailable:safety");
  });

  it("safety advisory → pays even with onUnavailable:block", async () => {
    const c = mkClient({
      fetch: route(), guards: [safetyGuard()], policy: safetyPolicy("advisory", "block"),
    });
    const { receipt } = await c.client.fetch(URL1, {}, TOKEN);
    expect(receipt.outcome).toBe("paid_delivered");
    expect(receipt.notes).toContain("guard_unavailable:safety");
  });
});

// ===========================================================================
// Guard budget through the PIPELINE (SPEC §7.1/§7.5) — the mode-scoped time-box.
//
// Two gaps the guard-scope suite can't see (it calls check() directly):
//  (1) MEDIUM #1 — the pipeline `runGuard` race delay (`#delay(budgetMs)`) is
//      never value-asserted, so a mutation there passes. A guard whose check()
//      HANGS makes the race — not the socket abort — the binding timeout; a
//      recording `delay` fake captures the exact ms the race is sized to.
//  (2) HIGH regression — a guard BUILT with one mode but consulted under a
//      hot-reloaded (different) live mode must use the LIVE mode in BOTH layers
//      (the pipeline race AND the guard's own socket-abort / verdict mapping).
// ===========================================================================

describe("pipeline runGuard budget (SPEC §7.1) — the race is sized to the LIVE mode", () => {
  // A `delay` that records the ms it is asked to wait, then resolves at once so a
  // HANGING guard's race is decided by the TIMEOUT branch. recorded[0] is the
  // guard race (D8, before any D10 approval delay).
  const recordingDelay = (recorded: number[]) => (ms: number): Promise<void> => {
    recorded.push(ms);
    return Promise.resolve();
  };
  const route = () =>
    new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK);

  it("enforce safety: the race is sized to the 13000ms screen budget (not the old 2000)", async () => {
    const recorded: number[] = [];
    const guard = fakeGuard("safety", { verdict: "pass" }, {
      hang: true,
      appliesFn: (i) => i.context.tokenAddress !== undefined,
    });
    const { client } = mkClient({
      fetch: route(),
      guards: [guard],
      delay: recordingDelay(recorded),
      policy: { guards: { safety: { enabled: true, mode: "enforce", onUnavailable: "block" } } },
    });
    const { receipt } = await client.fetch(URL1, {}, { tokenAddress: "0xtok", chain: "base" });
    expect(recorded[0]).toBe(GUARD_SCREEN_BUDGET_MS); // 13000 — mutation-catching value assert
    expect(receipt.outcome).toBe("guard_blocked"); // hang → race TIMEOUT → unavailable → enforce block
  });

  it("advisory trust (default): the race is sized to the 2000ms proceed-fast budget", async () => {
    const recorded: number[] = [];
    const guard = fakeGuard("trust", { verdict: "pass" }, { hang: true });
    const { client } = mkClient({ fetch: route(), guards: [guard], delay: recordingDelay(recorded) });
    await client.fetch(URL1); // trust default advisory
    expect(recorded[0]).toBe(GUARD_ADVISORY_BUDGET_MS); // 2000
  });

  it("HOT-RELOAD regression: a REAL safety guard BUILT advisory BLOCKS a danger screen when the LIVE policy is enforce (both layers use the live mode)", async () => {
    // The guard is captured with mode:"advisory" at build (blockOrWarn→warn, 2s
    // box). The live policy is enforce. If the guard used its captured cfg, a real
    // `danger` would map to WARN and the payment would proceed. Correct behaviour:
    // the pipeline threads the LIVE enforce cfg → the guard BLOCKS.
    const builtAdvisory = createSafetyGuard(
      safetyConfig({ enabled: true, mode: "advisory" }),
      guardRuntime({ guardFetch: new ScriptedGuardFetch(gJson(safetyBasic("danger"))).fetch }),
    );
    const { client } = mkClient({
      fetch: route(),
      guards: [builtAdvisory],
      // neverTimeout: let the REAL guard's async check() (fetch + json) win the
      // race and return its true verdict, not a race-timeout unavailable.
      delay: neverTimeout,
      policy: { guards: { safety: { enabled: true, mode: "enforce", onUnavailable: "block" } } },
    });
    const { receipt } = await client.fetch(URL1, {}, { tokenAddress: "0xtok", chain: "base" });
    expect(receipt.outcome).toBe("guard_blocked"); // live enforce ⇒ block; stale advisory would WARN (pay)
    expect(receipt.notes).toContain("guard_blocked:safety"); // a verdict-block, not an unavailable
  });
});

describe("guardFetch budget>0 (SPEC §7.2/§7.5) — pays without approval, one signature", () => {
  it("pays a 402 from the guard host and NEVER invokes approval", async () => {
    const gurl = "https://trust.p2.example/v1/trust/score";
    const fetch = new FakeFetch().on(
      "GET",
      gurl,
      { status: 402, jsonBody: challenge402({ accepts: [acceptsEntry({ resource: gurl })] }) },
      PAID_OK,
    );
    let elicitCalls = 0;
    const elicit: ElicitFn = async () => {
      elicitCalls += 1;
      return { approved: true };
    };
    const { client, signer } = mkClient({ fetch, elicit, resolve: hostResolver() });
    const gf = client.engine.makeGuardFetch("trust", 0.5, "https://trust.p2.example");
    const resp = await gf(gurl, { method: "GET" });
    expect(resp.status).toBe(200); // paid → delivered
    expect(elicitCalls).toBe(0); // guard spend never prompts a human (review #9)
    expect(signer.signCount).toBe(1); // exactly one signature for the guard payment
    // A guard-spend receipt is written like any spend.
    const recs = await client.receipts({});
    expect(recs.some((r) => r.verdictPath.includes("guard_spend"))).toBe(true);
  });
});

describe("M5 — guards.<id>.enabled honored (disabled ⇒ zero phone-home, no receipt entry)", () => {
  it("trust disabled ⇒ ZERO guardFetch calls and no trust GuardResult on the receipt", async () => {
    const gf = new ScriptedGuardFetch(gJson(trustReliable()));
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK);
    const { client } = mkClient({ fetch, policy: { guards: { trust: { enabled: false } } } });
    client.engine.guards = [createTrustGuard(trustConfig(), guardRuntime({ guardFetch: gf.fetch }))];
    const { receipt } = await client.fetch(URL1);
    expect(gf.callCount).toBe(0); // README contract: disable the guard ⇒ zero phone-home
    expect(receipt.guards.some((g) => g.id === "trust")).toBe(false); // produced no result
    expect(receipt.outcome).toBe("paid_delivered"); // a disabled guard cannot block the pay
  });

  it("safety disabled ⇒ ZERO guardFetch calls even WITH a tokenAddress (applies() would be true)", async () => {
    const gf = new ScriptedGuardFetch(gJson(safetyBasic("safe")));
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK);
    const { client } = mkClient({ fetch, policy: { guards: { safety: { enabled: false } } } });
    // The guard is fully armed (enabled cfg); only the POLICY toggle disables it.
    client.engine.guards = [
      createSafetyGuard(safetyConfig({ enabled: true }), guardRuntime({ guardFetch: gf.fetch })),
    ];
    const { receipt } = await client.fetch(URL1, {}, {
      tokenAddress: "So11111111111111111111111111111111111111112",
      chain: "solana",
    });
    expect(gf.callCount).toBe(0);
    expect(receipt.guards.some((g) => g.id === "safety")).toBe(false);
    expect(receipt.outcome).toBe("paid_delivered");
  });

  it("enabled path still works — an enabled trust guard DOES call and DOES appear", async () => {
    const gf = new ScriptedGuardFetch(gJson(trustReliable()));
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK);
    // neverTimeout: let the real (async) guard resolve its true verdict.
    const { client } = mkClient({
      fetch,
      delay: neverTimeout,
      policy: { guards: { trust: { enabled: true } } },
    });
    client.engine.guards = [createTrustGuard(trustConfig(), guardRuntime({ guardFetch: gf.fetch }))];
    const { receipt } = await client.fetch(URL1);
    expect(gf.callCount).toBe(1);
    expect(receipt.guards.find((g) => g.id === "trust")?.verdict).toBe("pass");
  });
});

describe("L3 — a dry-run/quote is signature-free even with a paying guard (SPEC §4.2/§9 T2)", () => {
  const base = "https://trust.p2.example";
  const guardScoreUrl = trustScoreUrl(base, URL1);
  const guard402 = () =>
    challenge402({ accepts: [acceptsEntry({ resource: guardScoreUrl })] });
  const payingTrustGuard = (client: ReturnType<typeof mkClient>["client"], budget: number) => {
    // Wire a REAL trust guard whose guardFetch is the ENGINE's budget-reserving
    // wrapper, so the dryRun gating is exercised end to end (not a fake shortcut).
    client.engine.guards = [
      createTrustGuard(
        trustConfig({ dailyBudgetUsd: budget }),
        guardRuntime({ guardFetch: client.engine.makeGuardFetch("trust", budget, base) }),
      ),
    ];
  };

  it("dryRun runs a PAYING guard on the FREE tier — zero signatures, verdict still present", async () => {
    const fetch = new FakeFetch()
      .on("GET", URL1, { status: 402, jsonBody: challenge402() })
      .on("GET", guardScoreUrl, { status: 402, jsonBody: guard402() }, PAID_OK);
    // neverTimeout: the guard's REAL verdict must win (the free-tier 402), not a
    // timeout — otherwise "unavailable" would be ambiguous.
    const { client, signer } = mkClient({ fetch, delay: neverTimeout });
    payingTrustGuard(client, 0.5);

    const { receipt } = await client.fetch(URL1, {}, { dryRun: true });
    expect(receipt.outcome).toBe("dry_run");
    expect(signer.signCount).toBe(0); // NEVER signs on a dry-run, even with a paying guard
    const trustG = receipt.guards.find((g) => g.id === "trust");
    expect(trustG).toBeDefined(); // the guard verdict still populates the quote (§9 T2)
    expect(trustG?.verdict).toBe("unavailable"); // free-tier 402 → unavailable (acceptable)
    const recs = await client.receipts({});
    expect(recs.some((r) => r.verdictPath.includes("guard_spend"))).toBe(false); // nothing reserved/paid
  });

  it("CONTRAST: a real (non-dry) paid_fetch with the SAME paying guard DOES attempt the paying path", async () => {
    const fetch = new FakeFetch()
      .on("GET", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK)
      .on("GET", guardScoreUrl, { status: 402, jsonBody: guard402() }, PAID_OK);
    // neverTimeout: runGuard must AWAIT the guard's payment (not time it out and
    // let it run detached), so the guard-spend receipt exists before we assert.
    const { client, signer } = mkClient({ fetch, delay: neverTimeout });
    payingTrustGuard(client, 0.5);

    await client.fetch(URL1);
    // The guard's 402 WAS paid on the non-dry path — a guard-spend receipt + a
    // signature prove the dryRun FLAG (not the budget) is what gates paying.
    const recs = await client.receipts({});
    expect(recs.some((r) => r.verdictPath.includes("guard_spend"))).toBe(true);
    expect(signer.signCount).toBeGreaterThanOrEqual(1);
  });
});

describe("L5 — a guard's paying fetch never follows redirects (off-host 402 stays unpaid, SPEC §11)", () => {
  it("a 3xx from the guard base is issued with redirect:'manual' and is never paid", async () => {
    const base = "https://trust.p2.example";
    const offHost = "https://evil.example/pay";
    const seen: Array<{ url: string; redirect: RequestInit["redirect"] }> = [];
    // A deps.fetch that records the `redirect` option and WOULD serve a payable
    // 402 off-host IF a redirect were ever followed.
    const recordingFetch = (async (input: unknown, init: RequestInit = {}): Promise<Response> => {
      const url = String(input);
      seen.push({ url, redirect: init.redirect });
      if (new URL(url).hostname === "trust.p2.example") {
        // A real fetch with redirect:"manual" would yield an opaque redirect
        // (status 0); the fake returns the raw 3xx, which is likewise not a 402.
        return new Response(null, { status: 302, headers: { location: offHost } });
      }
      return new Response(
        JSON.stringify(challenge402({ accepts: [acceptsEntry({ resource: offHost })] })),
        { status: 402, headers: { "content-type": "application/json" } },
      );
    }) as typeof fetch;

    const { client, signer } = mkClient({ fetch: new FakeFetch(), depsFetch: recordingFetch });
    const gf = client.engine.makeGuardFetch("trust", 0.5, base);
    const resp = await gf(`${base}/v1/trust/score?url=x`, { method: "GET" });

    expect(resp.status).toBe(302); // the 3xx is returned as-is, never treated as a payable 402
    expect(seen.find((c) => c.url.startsWith(base))?.redirect).toBe("manual"); // re-pins, no auto-follow
    expect(seen.some((c) => c.url.startsWith(offHost))).toBe(false); // off-host 402 never dialed
    expect(signer.signCount).toBe(0); // nothing signed
    const recs = await client.receipts({});
    expect(recs.some((r) => r.verdictPath.includes("guard_spend"))).toBe(false); // nothing reserved/paid
  });
});

describe("M6 — in-session queue self-approval is forbidden (SPEC §6)", () => {
  const pricey = () => challenge402({ accepts: [acceptsEntry({ maxAmountRequired: "300000" })] }); // $0.30

  it("mode=queue + approver: approve → queue_self_approval_forbidden; deny + list still work", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: pricey() });
    const c = mkClient({
      fetch,
      approver: true,
      policy: { approval: { thresholdUsd: 0.1, mode: "queue", elicitFallback: "deny" } },
    });
    expect(c.client.engine.queueCapableNow()).toBe(true);
    await c.client.fetch(URL1); // → approval_queued
    const [pending] = c.client.engine.listApprovals();

    // GRANT is refused WITHOUT consuming the pending item.
    expect(c.client.engine.resolveApproval(pending.approvalId, true)).toEqual({
      ok: false,
      error: "queue_self_approval_forbidden",
    });
    expect(c.client.engine.listApprovals()).toHaveLength(1); // untouched

    // deny still works (removes the pending); list is always permitted.
    expect(c.client.engine.resolveApproval(pending.approvalId, false)).toEqual({ ok: true });
    expect(c.client.engine.listApprovals()).toHaveLength(0);
  });

  it("mode=elicit + elicitFallback=queue is ALSO queue-capable ⇒ approve forbidden", async () => {
    // elicit === null (no bridge) → the elicitFallback:queue path queues a grant.
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: pricey() });
    const c = mkClient({
      fetch,
      approver: true,
      elicit: null,
      policy: { approval: { thresholdUsd: 0.1, mode: "elicit", elicitFallback: "queue" } },
    });
    expect(c.client.engine.queueCapableNow()).toBe(true);
    const r = await c.client.fetch(URL1);
    expect(r.receipt.outcome).toBe("approval_queued");
    const [pending] = c.client.engine.listApprovals();
    expect(c.client.engine.resolveApproval(pending.approvalId, true)).toEqual({
      ok: false,
      error: "queue_self_approval_forbidden",
    });
  });

  it("a NON-queue-capable policy (elicit + fallback deny) does NOT block approve", async () => {
    // Nothing queues here, so resolveApproval is not M6-gated: an unknown id
    // simply returns approval_not_found (the gate is open, the item is absent).
    const c = mkClient({
      fetch: new FakeFetch(),
      approver: true,
      policy: { approval: { thresholdUsd: 0.1, mode: "elicit", elicitFallback: "deny" } },
    });
    expect(c.client.engine.queueCapableNow()).toBe(false);
    expect(c.client.engine.resolveApproval("missing", true)).toEqual({
      ok: false,
      error: "approval_not_found",
    });
  });
});

describe("test-mode (SPEC §12)", () => {
  it("refuses a base MAINNET quote with note test_mode; receipts are test:true", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() });
    const { client, signer } = mkClient({ fetch, testMode: true });
    const { receipt } = await client.fetch(URL1);
    expect(receipt.test).toBe(true);
    expect(receipt.denyCode).toBe("test_mode");
    expect(receipt.notes).toContain("test_mode");
    expect(signer.signCount).toBe(0);
  });

  it("allows a base-sepolia quote in test mode", async () => {
    const fetch = new FakeFetch().on(
      "GET",
      URL1,
      {
        status: 402,
        jsonBody: challenge402({
          accepts: [acceptsEntry({ network: "base-sepolia", asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e" })],
        }),
      },
      PAID_OK,
    );
    const { client } = mkClient({ fetch, testMode: true });
    expect((await client.fetch(URL1)).receipt.outcome).toBe("paid_delivered");
  });
});

describe("§3.1a — v2 header-channel end-to-end (WIRE-PARITY WAVE)", () => {
  it("a v2 hello-shaped challenge (PAYMENT-REQUIRED header) → paid_delivered with a correct receipt", async () => {
    // Matches the LIVE scaffold hello facts (RESULTS.md): eip155:84532, Base Sepolia
    // USDC, amount "1000" ($0.001), maxTimeoutSeconds 60; challenge in the header,
    // settlement in PAYMENT-RESPONSE.
    const fetch = new FakeFetch().on(
      "GET",
      URL1,
      challengeHeaderResponse(challenge402V2()),
      settlementResponse({
        success: true,
        transaction: "0xhellotx",
        network: "eip155:84532",
        payer: "0xffa3e5fa7AE5F0DD1fd196Cbd41d40325E4Aa831",
      }),
    );
    const { client, signer, fetch: f } = mkClient({ fetch, testMode: true });
    const { receipt } = await client.fetch(URL1);

    expect(receipt.outcome).toBe("paid_delivered");
    expect(receipt.test).toBe(true);
    expect(receipt.payment?.settlementConfirmed).toBe(true);
    expect(receipt.payment?.txRef).toBe("0xhellotx");
    expect(receipt.quote?.x402Version).toBe(2);
    expect(receipt.quote?.network).toBe("base-sepolia"); // canonical (policy/asset/budget)
    expect(receipt.quote?.networkAsDeclared).toBe("eip155:84532"); // raw (payload echo)
    expect(receipt.quote?.amountUsd).toBeCloseTo(0.001, 9);
    expect(signer.signCount).toBe(1);

    // The paid retry echoes the RAW CAIP-2 dialect in the v2 payload's `accepted`
    // (policy normalizes to canonical; the seller hears its own dialect back).
    const retry = f.calls[1];
    expect(retry.headers["x-payment"]).toBeUndefined();
    const payload = JSON.parse(safeBase64Decode(retry.headers["payment-signature"]));
    expect(payload.x402Version).toBe(2);
    expect(payload.accepted.network).toBe("eip155:84532");
    expect(payload.accepted.amount).toBe("1000");
    expect(payload.scheme).toBeUndefined(); // v2 drops top-level scheme/network
  });

  it("the header challenge wins over a stale v1 body on the same 402", async () => {
    // Seller ships BOTH: a v2 challenge in the header and a different v1 body.
    const staleBody = challenge402({ accepts: [acceptsEntry({ maxAmountRequired: "999999" })] });
    const fetch = new FakeFetch().on(
      "GET",
      URL1,
      challengeHeaderResponse(challenge402V2(), { jsonBody: staleBody }),
      settlementResponse({ success: true, transaction: "0xtx" }),
    );
    const { client } = mkClient({ fetch, testMode: true });
    const { receipt } = await client.fetch(URL1);
    expect(receipt.outcome).toBe("paid_delivered");
    expect(receipt.quote?.amountAtomic).toBe("1000"); // header terms, not the $0.99 body
  });
});

describe("§3.1a rule 5 — settlement channel (PAYMENT-RESPONSE first, else legacy)", () => {
  it("parses settlement from the v2-canonical PAYMENT-RESPONSE header", async () => {
    const fetch = new FakeFetch().on(
      "GET",
      URL1,
      { status: 402, jsonBody: challenge402() },
      settlementResponse({ success: true, transaction: "0xnew" }), // default: PAYMENT-RESPONSE
    );
    const { receipt } = await mkClient({ fetch }).client.fetch(URL1);
    expect(receipt.outcome).toBe("paid_delivered");
    expect(receipt.payment?.settlementConfirmed).toBe(true);
    expect(receipt.payment?.txRef).toBe("0xnew");
  });

  it("still parses settlement from the legacy X-PAYMENT-RESPONSE header", async () => {
    const fetch = new FakeFetch().on(
      "GET",
      URL1,
      { status: 402, jsonBody: challenge402() },
      settlementResponse(
        { success: true, transaction: "0xlegacy" },
        { settlementChannel: "x-payment-response" },
      ),
    );
    const { receipt } = await mkClient({ fetch }).client.fetch(URL1);
    expect(receipt.outcome).toBe("paid_delivered");
    expect(receipt.payment?.txRef).toBe("0xlegacy");
  });
});

describe("key-hygiene (SPEC §12) — no key/signature material in receipts or logs", () => {
  it("the fake signature never appears in any receipt or log line", async () => {
    const fetch = new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK);
    const { client, logSink, fs } = mkClient({ fetch });
    await client.fetch(URL1);
    const SIG = "ab".repeat(65);
    const captured = [
      JSON.stringify([...fs.files.entries()]),
      JSON.stringify(logSink),
      JSON.stringify(await client.receipts({})),
    ].join("\n");
    expect(captured).not.toContain(SIG);
  });
});

// ===========================================================================
// L1 — the paid retry targets the 402-ISSUING host (leg1.finalUrl), never
// re-walking a leg-1 redirect chain with the signed X-PAYMENT (SPEC §11).
// ===========================================================================

describe("L1 — paid retry re-pins to leg1.finalUrl; X-PAYMENT never reaches an intermediate host", () => {
  it("a leg-1 redirect A→C: the proof retry hits C directly, and A (the intermediate) is dialed once WITHOUT the proof", async () => {
    const A = "https://start.example/go";
    const C = "https://issuer.example/pay";
    const fetch = new FakeFetch()
      .on("GET", A, { status: 302, headers: { location: C } })
      .on(
        "GET",
        C,
        { status: 402, jsonBody: challenge402({ accepts: [acceptsEntry({ resource: C })] }) },
        PAID_OK,
      );
    const { client, signer, fetch: f } = mkClient({ fetch });
    const { receipt } = await client.fetch(A);

    expect(receipt.outcome).toBe("paid_delivered");
    expect(signer.signCount).toBe(1);
    // The intermediate host is dialed exactly ONCE (the leg-1 GET) and carries NO
    // proof — the retry does not re-walk A→C.
    const toA = f.calls.filter((c) => c.url === A);
    expect(toA).toHaveLength(1);
    expect(toA[0].headers["x-payment"]).toBeUndefined();
    // The signed X-PAYMENT is presented ONLY to the 402-issuing host C.
    const proofCalls = f.calls.filter((c) => c.headers["x-payment"] !== undefined);
    expect(proofCalls).toHaveLength(1);
    expect(proofCalls[0].url).toBe(C);
  });
});

// ===========================================================================
// L2 — dryRun normalization: a truthy NON-boolean dryRun must stop the main pay
// AND force a funded guard onto the free tier (one `dry` boolean drives both).
// ===========================================================================

describe("L2 — a truthy non-boolean dryRun is normalized in BOTH the guard tier and the D9 stop", () => {
  it("dryRun:'yes' ⇒ dry_run outcome AND a funded guard signs nothing (free tier)", async () => {
    const base = "https://trust.p2.example";
    const guardScoreUrl = trustScoreUrl(base, URL1);
    const fetch = new FakeFetch()
      .on("GET", URL1, { status: 402, jsonBody: challenge402() })
      .on(
        "GET",
        guardScoreUrl,
        { status: 402, jsonBody: challenge402({ accepts: [acceptsEntry({ resource: guardScoreUrl })] }) },
        PAID_OK,
      );
    // neverTimeout: the paying trust guard's REAL free-tier verdict must win.
    const { client, signer } = mkClient({ fetch, delay: neverTimeout });
    client.engine.guards = [
      createTrustGuard(
        trustConfig({ dailyBudgetUsd: 0.5 }),
        guardRuntime({ guardFetch: client.engine.makeGuardFetch("trust", 0.5, base) }),
      ),
    ];
    // A direct library embedder passing a truthy non-boolean (pre-fix: D9 stopped
    // but the guard tier saw dryRun=false ⇒ a funded guard would sign a micro-payment).
    const { receipt } = await client.fetch(URL1, {}, { dryRun: "yes" as unknown as boolean });
    expect(receipt.outcome).toBe("dry_run");
    expect(signer.signCount).toBe(0); // funded guard forced onto the free tier ⇒ zero signatures
    const trustG = receipt.guards.find((g) => g.id === "trust");
    expect(trustG?.verdict).toBe("unavailable"); // free-tier 402 → unavailable (never paid)
  });
});

// ===========================================================================
// L3 — the guard's dailyBudgetUsd is read from the LIVE policy snapshot each
// call (hot-reload), not captured at build time. Wired exactly as
// buildDefaultGuards does: `makeGuardFetch(id, () => liveGuardBudgetUsd(id), …)`.
// Observable: the PAYING path re-pins deps.fetch with redirect:"manual"; the
// FREE path passes reqInit through (no redirect option).
// ===========================================================================

describe("L3 — guard dailyBudgetUsd is hot-reloaded from the live policy (tighten AND loosen, no restart)", () => {
  const base = "https://trust.p2.example";
  const gurl = `${base}/v1/trust/score?url=x`;

  const recorder = () => {
    const seen: Array<RequestInit["redirect"]> = [];
    const rfetch = (async (_input: unknown, init: RequestInit = {}): Promise<Response> => {
      seen.push(init.redirect);
      return new Response("ok", { status: 200 }); // 200 ⇒ paying path short-circuits before reserving
    }) as typeof fetch;
    return { seen, fetch: rfetch };
  };

  it("lowering guards.trust.dailyBudgetUsd 0.5→0 live flips paying→free; raising it re-arms", async () => {
    const rec = recorder();
    const { client, fs } = mkClient({
      fetch: new FakeFetch(),
      depsFetch: rec.fetch,
      policy: { guards: { trust: { dailyBudgetUsd: 0.5 } } },
    });
    // Wired EXACTLY as buildDefaultGuards does — a LIVE budget getter over policyProvider.
    const gf = client.engine.makeGuardFetch("trust", () => client.engine.liveGuardBudgetUsd("trust"), base);

    // Live budget 0.5 ⇒ PAYING path (own host re-pinned redirect:"manual").
    expect(client.engine.liveGuardBudgetUsd("trust")).toBe(0.5);
    await gf(gurl, { method: "GET" });
    expect(rec.seen.at(-1)).toBe("manual");

    // Operator lowers it to 0 live (config.json rewrite bumps mtime → reload).
    fs.writeText("/data/config.json", JSON.stringify({ guards: { trust: { dailyBudgetUsd: 0 } } }));
    expect(client.engine.liveGuardBudgetUsd("trust")).toBe(0); // tightened live
    await gf(gurl, { method: "GET" });
    expect(rec.seen.at(-1)).toBeUndefined(); // FREE path ⇒ no redirect:"manual", nothing reserved/paid

    // Raise it back live ⇒ re-arms (loosen).
    fs.writeText("/data/config.json", JSON.stringify({ guards: { trust: { dailyBudgetUsd: 0.75 } } }));
    expect(client.engine.liveGuardBudgetUsd("trust")).toBe(0.75);
    await gf(gurl, { method: "GET" });
    expect(rec.seen.at(-1)).toBe("manual");
  });
});

// ===========================================================================
// dim5-MED (P3 side) — an enforce safety guard fails CLOSED on a degraded screen
// (verdict∈{unknown,caution} && degraded===true) → guard_blocked. A CLEAN
// (non-degraded) unknown is an honest unknown and still pays.
// ===========================================================================

describe("dim5-MED — degraded enforce screen fails closed; clean unknown pays", () => {
  const route = () => new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK);
  const TOKEN = { tokenAddress: "0xtok", chain: "base" as const };
  const enforceSafety = {
    guards: { safety: { enabled: true, mode: "enforce" as const, onUnavailable: "block" as const } },
  };
  const mkSafety = (body: unknown) =>
    createSafetyGuard(
      safetyConfig({ enabled: true, mode: "enforce" }),
      guardRuntime({ guardFetch: new ScriptedGuardFetch(gJson(body)).fetch }),
    );

  it("degraded unknown (200 OK) ⇒ guard_blocked (fail-closed via onUnavailable), zero signatures", async () => {
    const { client, signer } = mkClient({
      fetch: route(),
      delay: neverTimeout,
      guards: [mkSafety(safetyDegraded("unknown"))],
      policy: enforceSafety,
    });
    const { receipt } = await client.fetch(URL1, {}, TOKEN);
    expect(receipt.outcome).toBe("guard_blocked");
    expect(receipt.notes).toContain("guard_unavailable:safety"); // fail-closed, not a verdict-block
    expect(receipt.notes).not.toContain("guard_blocked:safety");
    expect(signer.signCount).toBe(0);
  });

  it("CONTRAST: a CLEAN (non-degraded) unknown (200 OK) ⇒ paid_delivered (honest-unknown pass, unaffected)", async () => {
    const { client, signer } = mkClient({
      fetch: route(),
      delay: neverTimeout,
      guards: [mkSafety(safetyBasic("unknown"))],
      policy: enforceSafety,
    });
    const { receipt } = await client.fetch(URL1, {}, TOKEN);
    expect(receipt.outcome).toBe("paid_delivered");
    expect(signer.signCount).toBe(1);
  });
});

// ===========================================================================
// P3 review §2 — Desktop elicitation fallback (SPEC §6). A client that cannot
// elicit (never advertised it, or dismissed the dialog — e.g. Claude Desktop
// returns `cancel` immediately) must NOT be mistaken for a human denial, and an
// operator config pre-approval is the non-elicitation path above threshold.
// ===========================================================================

describe("P3 — desktop elicitation fallback + config pre-approval (SPEC §6)", () => {
  const pricey = () => challenge402({ accepts: [acceptsEntry({ maxAmountRequired: "300000" })] }); // $0.30
  const route = () => new FakeFetch().on("GET", URL1, { status: 402, jsonBody: pricey() }, PAID_OK);
  const overThreshold = {
    approval: { thresholdUsd: 0.1, mode: "elicit" as const, elicitFallback: "deny" as const },
  };

  it("elicit CANCELLED is NOT a human denial — it routes to elicitFallback with a distinct cause note", async () => {
    const cancelled: ElicitFn = async () => ({ approved: false, cancelled: true });
    const c = mkClient({ fetch: route(), elicit: cancelled, policy: overThreshold });
    const { receipt } = await c.client.fetch(URL1);
    expect(receipt.outcome).toBe("approval_denied");
    expect(receipt.notes).toContain("elicit_cancelled"); // distinguishable from a real denial
    expect(receipt.notes).toContain("elicit_unsupported_fallback:deny");
    expect(c.signer.signCount).toBe(0);
  });

  it("a GENUINE human denial carries NEITHER elicit_cancelled NOR elicit_unsupported", async () => {
    const deny: ElicitFn = async () => ({ approved: false });
    const c = mkClient({ fetch: route(), elicit: deny, policy: overThreshold });
    const { receipt } = await c.client.fetch(URL1);
    expect(receipt.outcome).toBe("approval_denied");
    expect(receipt.notes).not.toContain("elicit_cancelled");
    expect(receipt.notes).not.toContain("elicit_unsupported");
  });

  it("elicit CANCELLED + elicitFallback queue ⇒ approval_queued (not denied)", async () => {
    const cancelled: ElicitFn = async () => ({ approved: false, cancelled: true });
    const c = mkClient({
      fetch: route(),
      elicit: cancelled,
      policy: { approval: { thresholdUsd: 0.1, mode: "elicit", elicitFallback: "queue" } },
    });
    const { receipt } = await c.client.fetch(URL1);
    expect(receipt.outcome).toBe("approval_queued");
    expect(receipt.notes).toContain("elicit_cancelled");
    expect(receipt.notes).toContain("elicit_unsupported_fallback:queue");
  });

  it("elicit UNSUPPORTED (client never advertised) + fallback deny ⇒ clear-cause note elicit_unsupported", async () => {
    const c = mkClient({ fetch: route(), elicit: null, policy: overThreshold });
    const { receipt } = await c.client.fetch(URL1);
    expect(receipt.outcome).toBe("approval_denied");
    expect(receipt.notes).toContain("elicit_unsupported");
    expect(receipt.notes).toContain("elicit_unsupported_fallback:deny");
  });

  it("config pre-approval by CAP lets a NON-eliciting client pay above threshold (approvedBy config)", async () => {
    const c = mkClient({
      fetch: route(),
      elicit: null,
      policy: {
        approval: { thresholdUsd: 0.1, mode: "elicit", elicitFallback: "deny", preApprovedUpToUsd: 0.5 },
      },
    });
    const { receipt } = await c.client.fetch(URL1);
    expect(receipt.outcome).toBe("paid_delivered");
    expect(receipt.approval).toEqual({ mode: "elicit", approvedBy: "config" });
    expect(receipt.notes).toContain("preapproved:cap");
    expect(c.signer.signCount).toBe(1);
  });

  it("config pre-approval by HOST pays above threshold in mode 'elicit' (note preapproved:host)", async () => {
    const c = mkClient({
      fetch: route(),
      elicit: null,
      policy: {
        approval: {
          thresholdUsd: 0.1,
          mode: "elicit",
          elicitFallback: "deny",
          preApprovedHosts: ["api.example.com"],
        },
      },
    });
    const { receipt } = await c.client.fetch(URL1);
    expect(receipt.outcome).toBe("paid_delivered");
    expect(receipt.notes).toContain("preapproved:host");
  });

  // P3 money-path review: `approval.mode: "deny"` is the operator's HARD
  // kill-switch. A stale config pre-approval MUST NOT override it — `deny` must
  // fully deny above threshold. This makes `deny` strictly TIGHTER, never looser.
  it("mode 'deny' IGNORES a pre-approved HOST — still denied, zero signatures", async () => {
    const c = mkClient({
      fetch: route(),
      elicit: null,
      policy: {
        approval: {
          thresholdUsd: 0.1,
          mode: "deny",
          elicitFallback: "deny",
          preApprovedHosts: ["api.example.com"],
        },
      },
    });
    const { receipt } = await c.client.fetch(URL1);
    expect(receipt.outcome).toBe("approval_denied");
    expect(receipt.notes).toContain("approval_mode_deny");
    expect(receipt.notes).not.toContain("preapproved:host");
    expect(c.signer.signCount).toBe(0);
  });

  it("mode 'deny' IGNORES a preApprovedUpToUsd ceiling — still denied, zero signatures", async () => {
    const c = mkClient({
      fetch: route(),
      elicit: null,
      policy: {
        approval: {
          thresholdUsd: 0.1,
          mode: "deny",
          elicitFallback: "deny",
          preApprovedUpToUsd: 5, // ceiling well above the $0.30 price
        },
      },
    });
    const { receipt } = await c.client.fetch(URL1);
    expect(receipt.outcome).toBe("approval_denied");
    expect(receipt.notes).toContain("approval_mode_deny");
    expect(receipt.notes).not.toContain("preapproved:cap");
    expect(c.signer.signCount).toBe(0);
  });

  it("a pre-approval ceiling BELOW the price does not fire ⇒ still fail-closed denied", async () => {
    const c = mkClient({
      fetch: route(),
      elicit: null,
      policy: {
        approval: { thresholdUsd: 0.1, mode: "elicit", elicitFallback: "deny", preApprovedUpToUsd: 0.1 },
      },
    });
    const { receipt } = await c.client.fetch(URL1); // $0.30 > $0.10 ceiling
    expect(receipt.outcome).toBe("approval_denied");
    expect(receipt.notes).not.toContain("preapproved:cap");
    expect(c.signer.signCount).toBe(0);
  });

  it("pre-approval NEVER bypasses caps — a reserve failure is still an honest deny, zero signatures", async () => {
    const c = mkClient({
      fetch: route(),
      elicit: null,
      policy: {
        approval: { thresholdUsd: 0.1, mode: "elicit", elicitFallback: "deny", preApprovedUpToUsd: 1 },
        caps: { dailyUsd: 0.005, perCallUsd: 1, perHostDailyUsd: 1, totalUsd: null },
      },
    });
    const { receipt } = await c.client.fetch(URL1);
    expect(receipt.denyCode).toBe("budget_exhausted:day");
    expect(c.signer.signCount).toBe(0);
  });

  it("pre-approval does NOT bypass guards — an enforce safety block still blocks (guards precede approval)", async () => {
    const guard = fakeGuard("safety", { verdict: "block" }, {
      appliesFn: (i) => i.context.tokenAddress !== undefined,
    });
    const c = mkClient({
      fetch: route(),
      elicit: null,
      guards: [guard],
      policy: {
        approval: { thresholdUsd: 0.1, mode: "elicit", elicitFallback: "deny", preApprovedUpToUsd: 1 },
        guards: { safety: { enabled: true, mode: "enforce" } },
      },
    });
    const { receipt } = await c.client.fetch(URL1, {}, { tokenAddress: "0xtok", chain: "base" });
    expect(receipt.outcome).toBe("guard_blocked");
    expect(c.signer.signCount).toBe(0);
  });
});

// ===========================================================================
// P3 review §3 — guard-block legibility. A fail-closed block (degraded/timeout/
// unavailable) is distinguishable at the top level (`guardBlockReason`) from a
// real `danger` verdict-block, so the agent can tell "retry may work" from
// "dangerous host."
// ===========================================================================

describe("P3 — guard-block legibility (guardBlockReason)", () => {
  const route = () => new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK);
  const TOKEN = { tokenAddress: "0xtok", chain: "base" as const };

  it("a real verdict-block ⇒ guardBlockReason 'danger' (do not retry)", async () => {
    const guard = fakeGuard("trust", { verdict: "block" });
    const { client, signer } = mkClient({ fetch: route(), guards: [guard] });
    const { receipt } = await client.fetch(URL1);
    expect(receipt.outcome).toBe("guard_blocked");
    expect(receipt.guardBlockReason).toBe("danger");
    expect(signer.signCount).toBe(0);
  });

  it("an enforce block from a plain 'unavailable' ⇒ guardBlockReason 'unavailable' (retryable)", async () => {
    const guard = fakeGuard("trust", { verdict: "unavailable" }); // detail {} → no reason
    const { client } = mkClient({
      fetch: route(),
      guards: [guard],
      policy: { guards: { trust: { mode: "enforce", onUnavailable: "block" } } },
    });
    const { receipt } = await client.fetch(URL1);
    expect(receipt.outcome).toBe("guard_blocked");
    expect(receipt.guardBlockReason).toBe("unavailable");
  });

  it("a guard TIMEOUT (hang → race timeout) ⇒ guardBlockReason 'timeout' (retryable)", async () => {
    const guard = fakeGuard("safety", { verdict: "pass" }, {
      hang: true,
      appliesFn: (i) => i.context.tokenAddress !== undefined,
    });
    const { client } = mkClient({
      fetch: route(),
      guards: [guard], // default delay=immediateDelay → the race TIMEOUT branch wins
      policy: { guards: { safety: { enabled: true, mode: "enforce", onUnavailable: "block" } } },
    });
    const { receipt } = await client.fetch(URL1, {}, TOKEN);
    expect(receipt.outcome).toBe("guard_blocked");
    expect(receipt.guardBlockReason).toBe("timeout");
  });

  it("an enforce DEGRADED screen ⇒ guardBlockReason 'degraded' (retryable), still fail-closed", async () => {
    const guard = createSafetyGuard(
      safetyConfig({ enabled: true, mode: "enforce" }),
      guardRuntime({ guardFetch: new ScriptedGuardFetch(gJson(safetyDegraded("unknown"))).fetch }),
    );
    const { client, signer } = mkClient({
      fetch: route(),
      delay: neverTimeout,
      guards: [guard],
      policy: { guards: { safety: { enabled: true, mode: "enforce", onUnavailable: "block" } } },
    });
    const { receipt } = await client.fetch(URL1, {}, TOKEN);
    expect(receipt.outcome).toBe("guard_blocked");
    expect(receipt.guardBlockReason).toBe("degraded");
    expect(receipt.notes).toContain("guard_unavailable:safety");
    expect(signer.signCount).toBe(0);
  });
});

// ===========================================================================
// P3 review §4b — the `onDegraded` axis, decoupled from `onUnavailable`. An
// operator can soften the degrade-block NOISE without softening a genuinely
// dead-P1 block, and vice-versa. Default `onDegraded: "block"` == prior behavior.
// ===========================================================================

describe("P3 — onDegraded axis (decoupled from onUnavailable)", () => {
  const route = () => new FakeFetch().on("GET", URL1, { status: 402, jsonBody: challenge402() }, PAID_OK);
  const TOKEN = { tokenAddress: "0xtok", chain: "base" as const };
  const mkSafety = (body: unknown) =>
    createSafetyGuard(
      safetyConfig({ enabled: true, mode: "enforce" }),
      guardRuntime({ guardFetch: new ScriptedGuardFetch(gJson(body)).fetch }),
    );
  const safety = (over: Record<string, unknown>) => ({
    guards: { safety: { enabled: true, mode: "enforce" as const, ...over } },
  });

  it("onDegraded default 'block' ⇒ degraded screen fails closed (guardBlockReason degraded)", async () => {
    const { client, signer } = mkClient({
      fetch: route(),
      delay: neverTimeout,
      guards: [mkSafety(safetyDegraded("unknown"))],
      policy: safety({ onUnavailable: "block" }),
    });
    const { receipt } = await client.fetch(URL1, {}, TOKEN);
    expect(receipt.outcome).toBe("guard_blocked");
    expect(receipt.guardBlockReason).toBe("degraded");
    expect(signer.signCount).toBe(0);
  });

  it("onDegraded 'warn' ⇒ pays with guard_warn (degrade softened, not blocked)", async () => {
    const { client, signer } = mkClient({
      fetch: route(),
      delay: neverTimeout,
      guards: [mkSafety(safetyDegraded("unknown"))],
      policy: safety({ onDegraded: "warn" }),
    });
    const { receipt } = await client.fetch(URL1, {}, TOKEN);
    expect(receipt.outcome).toBe("paid_delivered");
    expect(receipt.notes).toContain("guard_warn:safety");
    expect(signer.signCount).toBe(1);
  });

  it("onDegraded 'proceed' ⇒ pays quietly (no warn); guard_unavailable note remains", async () => {
    const { client } = mkClient({
      fetch: route(),
      delay: neverTimeout,
      guards: [mkSafety(safetyDegraded("unknown"))],
      policy: safety({ onDegraded: "proceed" }),
    });
    const { receipt } = await client.fetch(URL1, {}, TOKEN);
    expect(receipt.outcome).toBe("paid_delivered");
    expect(receipt.notes).toContain("guard_unavailable:safety");
    expect(receipt.notes).not.toContain("guard_warn:safety");
  });

  it("onDegraded 'proceed' does NOT soften a genuinely dead P1 — a 402 still blocks via onUnavailable", async () => {
    const guard = createSafetyGuard(
      safetyConfig({ enabled: true, mode: "enforce" }),
      guardRuntime({ guardFetch: new ScriptedGuardFetch(gStatus(402)).fetch }),
    );
    const { client, signer } = mkClient({
      fetch: route(),
      delay: neverTimeout,
      guards: [guard],
      policy: safety({ onDegraded: "proceed", onUnavailable: "block" }),
    });
    const { receipt } = await client.fetch(URL1, {}, TOKEN);
    expect(receipt.outcome).toBe("guard_blocked");
    expect(receipt.guardBlockReason).toBe("unavailable");
    expect(signer.signCount).toBe(0);
  });

  it("CONVERSE: onUnavailable 'proceed' does NOT soften a DEGRADED screen when onDegraded stays 'block'", async () => {
    const { client, signer } = mkClient({
      fetch: route(),
      delay: neverTimeout,
      guards: [mkSafety(safetyDegraded("unknown"))],
      policy: safety({ onUnavailable: "proceed", onDegraded: "block" }),
    });
    const { receipt } = await client.fetch(URL1, {}, TOKEN);
    expect(receipt.outcome).toBe("guard_blocked");
    expect(receipt.guardBlockReason).toBe("degraded");
    expect(signer.signCount).toBe(0);
  });
});
