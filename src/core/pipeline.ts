/**
 * P3′ payfetch — the paying-fetch state machine (SPEC §3, §4.2, §5, §6, §7).
 * Fable-reviewed judgment core: money can only move safely.
 *
 * Purpose: orchestrate one logical request end to end — transport (§11) → 402
 * parse (§3) → decision pipeline D1–D11 (§4.2) → payment execution + settlement
 * classification (§5.2/§5.3) → receipt (§8) — enforcing the two cardinal
 * invariants: money moves only inside a reservation, at most once per request;
 * agent inputs only tighten, never loosen (§0).
 *
 * Invariants (SPEC §5):
 *  - `buildPayment` is invoked AT MOST ONCE per logical request
 *    (MAX_PAYMENT_ATTEMPTS_PER_REQUEST = 1; count-asserted). A second 402 is an
 *    answer, not an invitation to re-quote.
 *  - Reservation (D11) precedes payment; a failed reservation ⇒ zero signatures.
 *  - Dry-run/quote reserves nothing and signs nothing (stops at D9).
 *  - Approval never pre-reserves; a post-approval reservation failure is an
 *    honest deny (caps outrank humans-in-the-moment, §6).
 *  - Every outcome — free, dry_run, denial, paid, unknown — leaves one receipt
 *    with budgets snapshotted at decision time (§8.3).
 *  - Guards run sequentially (trust→safety), time-boxed, crash-contained; a guard
 *    is never a pipeline exception (§7.4).
 *  - When settlement is unknown, the hold is KEPT — budgets over-count, never
 *    free early (§5.2). No path releases a hold while its authorization is valid.
 */

import {
  APPROVAL_ELICIT_TIMEOUT_S,
  CLIENT_VERSION,
  GUARD_SEND_QUERY,
  INTEGRATION_HEADER,
  guardBudgetMs,
  KNOWN_ASSETS,
  PAYMENT_REQUIRED_HEADER,
  PAYMENT_RESPONSE_HEADER,
  PAYMENT_SIGNATURE_HEADER,
  POLICY_VERSION,
  X_PAYMENT_HEADER,
  X_PAYMENT_RESPONSE_HEADER,
} from "./constants.js";
import type { Budget, RemainingBudgets, ReserveCaps } from "./budget.js";
import type { PayfetchFs } from "./fs.js";
import {
  Ledger,
  guardDayKey,
  utcDate,
  type GuardBlockReason,
  type Outcome,
  type Receipt,
} from "./ledger.js";
import {
  budgetExhausted,
  elicitUnsupportedFallback,
  guardBlocked,
  guardUnavailable,
  guardWarn,
  preapproved,
} from "./notes.js";
import { matchesAnyHost, type Policy } from "./policy.js";
import {
  deliverBody,
  transportFetch,
  type TransportIo,
  type TransportResult,
} from "./transport.js";
import { parse402Challenge, parseChallenge } from "../payer/parse402.js";
import type {
  ElicitRequest,
  ParsedChallenge,
  PayfetchDeps,
  PaymentPayer,
  PaymentQuote,
} from "../payer/types.js";
import {
  parseSettlementResponse,
  quoteWithRejections,
  selectQuote,
} from "../payer/x402.js";
import type {
  GuardId,
  GuardInput,
  GuardResult,
  GuardRuntime,
  PrePayGuard,
  SafetyGuardConfig,
  TrustGuardConfig,
} from "../guards/types.js";
import type { PreapprovedNote } from "./notes.js";

// ---------------------------------------------------------------------------
// Public result shapes (SPEC §10)
// ---------------------------------------------------------------------------

export type FetchOpts = {
  maxAmountUsd?: number;
  dryRun?: boolean;
  tokenAddress?: string;
  chain?: string;
  responseMode?: "inline" | "file";
};

export type PayfetchFetchResult = { response: Response | null; receipt: Receipt };

export type Decision = {
  outcome: Outcome;
  denyCode: string | null;
  decision: "would_pay" | "would_deny" | "free";
  quote: PaymentQuote | null;
  rejectedQuotes: Record<string, number> | null;
  guards: GuardResult[];
  remainingBudgets: RemainingBudgets;
  notes: string[];
};

export type SpendStatus = {
  date: string;
  day: { spentUsd: number; remainingUsd: number };
  total: { spentUsd: number; remainingUsd: number | null };
  perHost: Record<string, { spentUsd: number; remainingUsd: number }>;
  holds: { holdId: string; amountUsd: number; host: string; validBeforeTs: number }[];
  autoDenied: { host: string; untilTs: number }[];
  recentPayments: {
    receiptId: string;
    host: string;
    amountUsd: number | null;
    outcome: Outcome;
    ts: number;
  }[];
};

// GuardRuntime (SPEC §7.5) lives in guards/types.ts (single source); re-exported
// here so `src/index.ts` has one import point for the wiring seam.
export type { GuardRuntime } from "../guards/types.js";

// ---------------------------------------------------------------------------
// Engine configuration
// ---------------------------------------------------------------------------

export type EngineConfig = {
  deps: PayfetchDeps;
  fs: PayfetchFs;
  ledger: Ledger;
  budget: Budget;
  payers: PaymentPayer[];
  /** Current-policy provider (mtime-reloaded, immutable per call). */
  policyProvider: () => { ok: true; policy: Policy } | { ok: false; error: string };
  transportIo: Omit<TransportIo, "now" | "log" | "fs">;
  testMode: boolean;
  approverEnabled: boolean;
  /** Injected delay for elicit/guard timeouts (tests neutralize it). */
  delay?: (ms: number) => Promise<void>;
  /** Guard base URLs for the budget-reserving guardFetch host restriction. */
  guardBaseUrls: { trust: string | null; safety: string | null };
  via: string | null;
};

const defaultDelay = (ms: number): Promise<void> =>
  new Promise((r) => {
    // These delays back the guard/elicit `Promise.race` timeouts. When the OTHER
    // racer wins (the common warm path — a guard resolves in ~110ms), this timer
    // is the loser and would otherwise keep a one-shot CLI's event loop alive for
    // the whole budget (~8s guard / ~120s elicit). `.unref()` lets the process
    // exit while still firing if it IS the winner (fix F4).
    const t = setTimeout(r, ms);
    (t as { unref?: () => void }).unref?.();
  });

// ---------------------------------------------------------------------------
// Small deterministic id helpers (SPEC §8.3 uuid4, §12 installId)
// ---------------------------------------------------------------------------

function hex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}
function uuid4FromBytes(b: Uint8Array): string {
  const h = hex(b.subarray(0, 16)).split("");
  // Set version (4) and variant (10xx) nibbles.
  h[12] = "4";
  const variant = (parseInt(h[16], 16) & 0x3) | 0x8;
  h[16] = variant.toString(16);
  const s = h.join("");
  return `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20, 32)}`;
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

export class PayfetchEngine {
  readonly #cfg: EngineConfig;
  readonly #deps: PayfetchDeps;
  readonly #delay: (ms: number) => Promise<void>;
  /** Guards, attached post-construction (they close over this engine's guardFetch). */
  guards: PrePayGuard[] = [];

  constructor(cfg: EngineConfig) {
    this.#cfg = cfg;
    this.#deps = cfg.deps;
    this.#delay = cfg.delay ?? defaultDelay;
  }

  private newReceiptId(): string {
    return uuid4FromBytes(this.#deps.random());
  }

  private capsOf(policy: Policy): ReserveCaps {
    return {
      dailyUsd: policy.caps.dailyUsd,
      perHostDailyUsd: policy.caps.perHostDailyUsd,
      totalUsd: policy.caps.totalUsd,
    };
  }

  private transportIo(): TransportIo {
    return {
      ...this.#cfg.transportIo,
      now: this.#deps.now,
      log: this.#deps.log,
      fs: this.#cfg.fs,
    };
  }

  // === public API (SPEC §10) ===========================================

  async fetch(url: string, init?: RequestInit, opts?: FetchOpts): Promise<PayfetchFetchResult> {
    return this.run(url, init ?? {}, opts ?? {}, false);
  }

  async quote(url: string, init?: RequestInit): Promise<{ decision: Decision; receipt: Receipt }> {
    const { receipt } = await this.run(url, init ?? {}, { dryRun: true }, true);
    return { decision: this.decisionFromReceipt(receipt), receipt };
  }

  async status(): Promise<SpendStatus> {
    this.#cfg.budget.sweepExpired();
    const pol = this.#cfg.policyProvider();
    const caps = pol.ok ? this.capsOf(pol.policy) : { dailyUsd: 0, perHostDailyUsd: 0, totalUsd: null };
    const now = this.#deps.now();
    const date = utcDate(now);
    const state = this.#cfg.budget.state;
    const dayKeyStr = `day:${date}`;
    const daySpent = state.counters[dayKeyStr] ?? 0;
    const totalSpent = state.counters["total"] ?? 0;
    const perHost: Record<string, { spentUsd: number; remainingUsd: number }> = {};
    for (const [k, v] of Object.entries(state.counters)) {
      const m = /^host:(.+):(\d{4}-\d{2}-\d{2})$/.exec(k);
      if (m && m[2] === date) {
        const host = m[1];
        const rem = this.#cfg.budget.remaining(caps, host);
        perHost[host] = { spentUsd: v, remainingUsd: rem.hostRemainingUsd };
      }
    }
    const remaining = this.#cfg.budget.remaining(caps, "");
    const recent = this.#cfg.ledger
      .readAllReceipts()
      .filter((r) => r.payment !== null)
      .sort((a, b) => b.ts - a.ts)
      .slice(0, 10)
      .map((r) => ({
        receiptId: r.receiptId,
        host: r.host,
        amountUsd: r.payment?.settledAmountUsd ?? r.quote?.amountUsd ?? null,
        outcome: r.outcome,
        ts: r.ts,
      }));
    return {
      date,
      day: { spentUsd: daySpent, remainingUsd: remaining.dayRemainingUsd },
      total: { spentUsd: totalSpent, remainingUsd: remaining.totalRemainingUsd },
      perHost,
      holds: state.holds.map((h) => ({
        holdId: h.holdId,
        amountUsd: h.amountUsd,
        host: h.host,
        validBeforeTs: h.validBeforeTs,
      })),
      autoDenied: this.#cfg.budget.autoDeniedHosts(),
      recentPayments: recent,
    };
  }

  receipts(q: {
    sinceTs?: number;
    host?: string;
    outcome?: Outcome;
    limit?: number;
  }): Receipt[] {
    const limit = Math.min(Math.max(q.limit ?? 50, 1), 200);
    let rs = this.#cfg.ledger.readAllReceipts();
    if (q.sinceTs !== undefined) rs = rs.filter((r) => r.ts >= q.sinceTs!);
    if (q.host !== undefined) rs = rs.filter((r) => r.host === q.host);
    if (q.outcome !== undefined) rs = rs.filter((r) => r.outcome === q.outcome);
    rs.sort((a, b) => b.ts - a.ts);
    return rs.slice(0, limit);
  }

  // === approval queue (SPEC §9 T5 substrate; guarded in the tool layer) =

  listApprovals(): ReturnType<Budget["listApprovals"]> {
    return this.#cfg.budget.listApprovals();
  }

  /**
   * Is the CURRENT policy "queue-capable" — i.e. does it produce an
   * agent-resolvable QUEUED grant? True iff `approval.mode === "queue"` OR
   * (`approval.mode === "elicit"` AND `approval.elicitFallback === "queue"`), the
   * latter because an unavailable elicitation degrades to the queue. Read from the
   * live snapshot so a config hot-reload toggle is honored (SPEC §6, fix M6). An
   * invalid policy is treated as NOT queue-capable (nothing can queue anyway).
   */
  queueCapableNow(): boolean {
    const p = this.#cfg.policyProvider();
    if (!p.ok) return false;
    const a = p.policy.approval;
    return a.mode === "queue" || (a.mode === "elicit" && a.elicitFallback === "queue");
  }

  resolveApproval(approvalId: string, approve: boolean): { ok: boolean; error?: string } {
    if (!this.#cfg.approverEnabled) return { ok: false, error: "approver_not_enabled" };
    // M6 (self-approval): in an MCP session the agent drives EVERY tool — including
    // approve_pending — so an in-session approver + a queue-capable policy has no
    // requester/approver separation: a prompt-injected agent could both request a
    // paid_fetch AND approve its own over-threshold payment. There is no
    // out-of-band approve channel today, so refuse the GRANT action (approve)
    // WITHOUT touching the queue. `deny` (approve === false) and `list` stay
    // permitted — a deny only REMOVES a pending item and cannot authorize a
    // payment (SPEC §6, fix M6).
    if (approve && this.queueCapableNow()) {
      return { ok: false, error: "queue_self_approval_forbidden" };
    }
    const g = this.#cfg.budget.resolvePending(approvalId, approve);
    return g ? { ok: true } : { ok: false, error: "approval_not_found" };
  }

  // === the pipeline =====================================================

  private async run(
    url: string,
    init: RequestInit,
    opts: FetchOpts,
    quoteMode: boolean,
  ): Promise<PayfetchFetchResult> {
    const deps = this.#deps;
    const receiptId = this.newReceiptId();
    const verdictPath: string[] = [];
    const notes: string[] = [];
    if (this.#cfg.testMode) notes.push("test_mode");

    // Sweep expired holds first (SPEC §5.2 lazy sweep before any reserve).
    this.#cfg.budget.sweepExpired();

    // Policy snapshot (immutable for this evaluation; SPEC §4.1).
    const pol = this.#cfg.policyProvider();
    if (!pol.ok) {
      return this.finish(
        this.baseReceipt(receiptId, url, init, "", "policy_denied", verdictPath, notes, null, {
          dayRemainingUsd: 0,
          hostRemainingUsd: 0,
          totalRemainingUsd: null,
        }, { denyCode: "policy_config_invalid", notesExtra: [pol.error] }),
        null,
      );
    }
    const policy = pol.policy;
    const caps = this.capsOf(policy);

    const method = (init.method ?? "GET").toUpperCase();
    const body = typeof init.body === "string" ? init.body : null;
    // Content-Type auto-default (1.0.1) applied ONCE here so both legs (probe +
    // paid retry) carry it; explicit caller headers always win. See the helper.
    const userHeaders = applyJsonContentTypeDefault(stripReservedHeaders(init.headers), body);
    const responseMode = opts.responseMode ?? "inline";
    // L2 (dryRun normalization): ONE boolean drives both the guard-tier gate (D8)
    // and the D9 stop, so a truthy non-boolean `opts.dryRun` can never suppress the
    // main pay while a funded guard still sees `dryRun=false` (would-sign mismatch).
    const dry = quoteMode || Boolean(opts.dryRun);

    // --- Transport leg 1 (SPEC §11) ---
    const io = this.transportIo();
    const leg1 = await transportFetch(url, { method, headers: userHeaders, body }, policy, io);
    for (const n of leg1.notes) notes.push(n);

    if (!leg1.ok) {
      // Transport-level failure BEFORE any 402 — nothing paid, no hold.
      const budgets = this.#cfg.budget.remaining(caps, leg1.finalHost);
      const outcome: Outcome = "fetch_error";
      const receipt = this.baseReceipt(
        receiptId, url, init, leg1.finalHost, outcome, verdictPath, notes, null, budgets,
        { http: this.httpBlock(leg1) },
      );
      return this.finish(receipt, null);
    }

    const finalHost = leg1.finalHost;
    const budgetsAtDecision = this.#cfg.budget.remaining(caps, finalHost);

    // --- Non-402 ⇒ free (SPEC §10) ---
    if (leg1.status !== 402) {
      const delivered = deliverBody(leg1.rawBody ?? new Uint8Array(0), responseMode, {
        fs: io.fs,
        downloadPath: this.#cfg.ledger.downloadPath(receiptId),
      });
      if (delivered.mode === "inline" && delivered.truncated) notes.push("body_truncated");
      const receipt = this.baseReceipt(
        receiptId, url, init, finalHost, "free", verdictPath, notes, null, budgetsAtDecision,
        { http: this.httpBlock(leg1) },
      );
      return this.finish(receipt, this.materialize(leg1, delivered));
    }

    // ======================= D1–D11 (SPEC §4.2) =======================
    // Challenge channel (§3.1a rule 1): a base64 PAYMENT-REQUIRED header IS the
    // challenge (v2-canonical); else the body JSON is (v1 style).
    const challenge = parse402Challenge(
      leg1.rawBody ?? new Uint8Array(0),
      leg1.headers?.get(PAYMENT_REQUIRED_HEADER) ?? null,
    );

    // D1 parse
    verdictPath.push("parse");
    if (challenge.malformed) {
      return this.deny(receiptId, url, init, finalHost, verdictPath, notes, null, budgetsAtDecision,
        "malformed_402", ["malformed_402"], "policy_denied", leg1);
    }

    // D2 quotes (filter §3.2) + tally
    verdictPath.push("quotes");
    const payer = this.detectPayer(challenge);
    const { quotes, rejected } = this.quoteAndReject(challenge, payer);
    if (quotes.length === 0) {
      const rejNotes = tallyNotes(rejected);
      return this.deny(receiptId, url, init, finalHost, verdictPath, notes, null, budgetsAtDecision,
        "unsupported_terms", ["unsupported_terms", ...rejNotes], "policy_denied", leg1, rejected);
    }

    // D3 select (§3.3)
    verdictPath.push("select");
    const quote = selectQuote(quotes);
    if (quote === null) {
      return this.deny(receiptId, url, init, finalHost, verdictPath, notes, null, budgetsAtDecision,
        "unsupported_terms", ["unsupported_terms"], "policy_denied", leg1, rejected);
    }

    // Test-mode mainnet refusal (SPEC §12): never touch base mainnet in test mode.
    if (this.#cfg.testMode && quote.network === "base") {
      return this.deny(receiptId, url, init, finalHost, verdictPath, notes, quote, budgetsAtDecision,
        "test_mode", ["test_mode"], "policy_denied", leg1, rejected);
    }

    // D4 deny list (always enforced; wins over allow)
    verdictPath.push("deny_list");
    if (matchesAnyHost(finalHost, policy.deny)) {
      return this.deny(receiptId, url, init, finalHost, verdictPath, notes, quote, budgetsAtDecision,
        "host_denied", ["host_denied"], "policy_denied", leg1, rejected);
    }

    // D5 allow list (allowlist mode → default-deny)
    verdictPath.push("allow_list");
    if (policy.mode === "allowlist" && !matchesAnyHost(finalHost, policy.allow)) {
      return this.deny(receiptId, url, init, finalHost, verdictPath, notes, quote, budgetsAtDecision,
        "host_not_allowlisted", ["host_not_allowlisted"], "policy_denied", leg1, rejected);
    }

    // D6 auto-deny (SPEC §5.4)
    verdictPath.push("auto_deny");
    if (policy.autoDeny.enabled && this.#cfg.budget.isAutoDenied(finalHost)) {
      return this.deny(receiptId, url, init, finalHost, verdictPath, notes, quote, budgetsAtDecision,
        "host_auto_denied", ["host_auto_denied"], "policy_denied", leg1, rejected);
    }

    // D7 per-call cap (agent maxAmountUsd only TIGHTENS — SPEC §0/§4.2)
    verdictPath.push("per_call");
    const effectivePerCall = Math.min(
      policy.caps.perCallUsd,
      opts.maxAmountUsd ?? Number.POSITIVE_INFINITY,
    );
    if (microUsd(quote.amountUsd) > microUsd(effectivePerCall)) {
      return this.deny(receiptId, url, init, finalHost, verdictPath, notes, quote, budgetsAtDecision,
        "per_call_cap_exceeded", ["per_call_cap_exceeded"], "policy_denied", leg1, rejected);
    }

    // D8 guards (SPEC §7.4) — sequential trust→safety, time-boxed, crash-contained
    verdictPath.push("guards");
    const guardInput: GuardInput = {
      url: guardUrl(leg1.finalUrl),
      host: finalHost,
      quote,
      context: {
        tokenAddress: opts.tokenAddress,
        chain: opts.chain as GuardInput["context"]["chain"],
      },
      // §4.2/§L3: a payment_quote / dryRun paid_fetch runs guards on the FREE
      // tier only — a paying guard signs nothing during a dry-run (L2: `dry`
      // is the same normalized boolean the D9 stop uses).
      dryRun: dry,
    };
    const guardResults: GuardResult[] = [];
    for (const guard of this.guards) {
      // M5 (privacy contract): read the guard's CURRENT config from the immutable
      // per-evaluation snapshot and SKIP a disabled guard BEFORE applies()/runGuard
      // — a disabled guard makes ZERO external calls (no phone-home) and produces
      // no GuardResult, so `guards.<id>.enabled = false` ⇒ truly inert (SPEC §4.1).
      const cfg = guard.id === "trust" ? policy.guards.trust : policy.guards.safety;
      if (!cfg.enabled) continue;
      if (!guard.applies(guardInput)) continue;
      // Thread the LIVE per-request config into the guard so its OWN time-box +
      // verdict mapping use the same snapshot as this race — no hot-reload drift
      // (SPEC §4.1/§7.5). `budgetMs` and `config` are both derived from `cfg`.
      const res = await this.runGuard(guard, { ...guardInput, config: cfg }, guardBudgetMs(cfg.mode));
      guardResults.push(res);
      if (res.verdict === "block") {
        // A real VERDICT-block (P1 danger / serial_rugger deployer, or a P2
        // unreliable enforce block). guardBlockReason "danger" tells the agent NOT
        // to retry (P3 review §3).
        notes.push(guardBlocked(res.id as GuardId));
        return this.denyGuardBlocked(receiptId, url, init, finalHost, verdictPath, notes, quote,
          budgetsAtDecision, leg1, rejected, guardResults, "danger");
      }
      if (res.verdict === "warn") notes.push(guardWarn(res.id as GuardId));
      if (res.verdict === "unavailable") {
        notes.push(guardUnavailable(res.id as GuardId));
        // §7.2/§7.3 + P3 review §4b: resolving "unavailable" is the PIPELINE's job.
        // Advisory → proceed (note only). Enforce → per the SPLIT axes: a DEGRADED
        // screen (danger-relevant upstream capped/absent → maybe under-calling danger)
        // resolves via `onDegraded`; a genuinely dead guard (402/5xx/timeout/crash) via
        // `onUnavailable`. Both default "block" (fail closed — unchanged behavior). A
        // softened axis (`warn`/`proceed`) proceeds WITHOUT signing. The receipt's
        // guard_unavailable:{id} note + guardBlockReason distinguish this from a
        // verdict-block. Reuse the loop-top `cfg` (same immutable snapshot).
        const disposition = resolveUnavailable(cfg, res);
        if (disposition === "block") {
          return this.denyGuardBlocked(receiptId, url, init, finalHost, verdictPath, notes, quote,
            budgetsAtDecision, leg1, rejected, guardResults, guardBlockReasonFor(res));
        }
        if (disposition === "warn") notes.push(guardWarn(res.id as GuardId));
        // "proceed" → fall through to the next guard / D9.
      }
    }

    // D9 dry-run (SPEC §4.2) — STOP, reserve nothing, sign nothing
    verdictPath.push("dry_run");
    if (dry) {
      const receipt = this.baseReceipt(
        receiptId, url, init, finalHost, "dry_run", verdictPath, notes, quote, budgetsAtDecision,
        { rejectedQuotes: rejected, guards: guardResults, http: this.httpBlock(leg1) },
      );
      return this.finish(receipt, null);
    }

    // D10 approval (SPEC §6) — never pre-reserves
    verdictPath.push("approval");
    let approvedBy: "elicit" | "queue" | "config" | null = null;
    if (microUsd(quote.amountUsd) > microUsd(policy.approval.thresholdUsd)) {
      const appr = await this.runApproval(policy, finalHost, quote, guardResults, budgetsAtDecision, receiptId);
      for (const n of appr.notes) notes.push(n);
      if (appr.kind === "denied") {
        const receipt = this.baseReceipt(
          receiptId, url, init, finalHost, appr.outcome, verdictPath, notes, quote, budgetsAtDecision,
          { rejectedQuotes: rejected, guards: guardResults, http: this.httpBlock(leg1),
            approval: { mode: policy.approval.mode, approvedBy: null } },
        );
        return this.finish(receipt, null);
      }
      approvedBy = appr.approvedBy; // approved / grant-consumed ⇒ fall through to reserve
    }
    const approvalBlock =
      approvedBy !== null ? { mode: policy.approval.mode, approvedBy } : null;

    // D11 reserve (SPEC §5.1) — atomic check-and-hold across all caps
    verdictPath.push("reserve");
    const reservation = this.#cfg.budget.reserve({
      holdId: receiptId,
      amountUsd: quote.amountUsd,
      host: finalHost,
      caps,
    });
    if (!reservation.ok) {
      return this.deny(receiptId, url, init, finalHost, verdictPath, notes, quote, budgetsAtDecision,
        `budget_exhausted:${reservation.which}`, [budgetExhausted(reservation.which as "day" | "host" | "total")],
        "policy_denied", leg1, rejected, guardResults, approvalBlock);
    }

    // PAY (SPEC §5.3) — ONE buildPayment; retry the 402-ISSUING host + proof.
    // L1: target `leg1.finalUrl` (the host that actually issued the 402), NOT the
    // original `url` — retrying `url` would re-walk any leg-1 redirect chain and
    // present the signed payment header to every intermediate host.
    verdictPath.push("pay");
    return this.executePayment(
      receiptId, url, leg1.finalUrl, init, method, userHeaders, body, finalHost, quote, payer, policy,
      verdictPath, notes, rejected, guardResults, budgetsAtDecision, responseMode, approvalBlock,
    );
  }

  // === payment execution + §5.2 classification =========================

  private async executePayment(
    receiptId: string,
    url: string,
    /** The 402-issuing host's URL (`leg1.finalUrl`) — the paying-leg target (L1). */
    finalUrl: string,
    init: RequestInit,
    method: string,
    userHeaders: Record<string, string>,
    body: string | null,
    finalHost: string,
    quote: PaymentQuote,
    payer: PaymentPayer,
    policy: Policy,
    verdictPath: string[],
    notes: string[],
    rejected: Record<string, number>,
    guardResults: GuardResult[],
    budgets: RemainingBudgets,
    responseMode: "inline" | "file",
    approval: { mode: string; approvedBy: "elicit" | "queue" | "config" | null } | null,
  ): Promise<PayfetchFetchResult> {
    const deps = this.#deps;
    const budget = this.#cfg.budget;

    // 1. buildPayment — the ONE signature (SPEC §5.3; count-asserted).
    let proof;
    try {
      proof = await payer.buildPayment(quote, deps.signer, deps);
    } catch (err) {
      // Provably no authorization exists ⇒ release the hold (SPEC §5.2).
      budget.release(receiptId);
      deps.log("payment.build_failed", { host: finalHost, message: scrub((err as Error).message) });
      const receipt = this.baseReceipt(
        receiptId, url, init, finalHost, "fetch_error", verdictPath, notes, quote, budgets,
        { rejectedQuotes: rejected, guards: guardResults, approval },
      );
      return this.finish(receipt, null);
    }
    // Pin the hold's real authorization window (SPEC §5.2).
    budget.setHoldValidBefore(receiptId, proof.validBeforeTs);
    const payerAddress = await deps.signer.address();

    // 2. retry the 402-ISSUING host + proof headers (reserved-name hygiene done).
    // L1 / §11: present the signed payment header to `finalUrl` (the 402 issuer) with
    // `followRedirects: false` — the proof is never carried across a further
    // redirect hop (matching the guard path's `redirect:"manual"` discipline); a
    // 3xx here is a terminal payment_rejected (hold kept), never chased off-host.
    const io = this.transportIo();
    const retry = await transportFetch(
      finalUrl,
      { method, headers: { ...userHeaders, ...proof.headers }, body },
      policy,
      io,
      { followRedirects: false },
    );
    for (const n of retry.notes) if (!notes.includes(n)) notes.push(n);

    // 3. classify the terminal event (SPEC §5.2 table).
    const cls = classifyTerminal(retry, quote);
    if (cls.note) notes.push(cls.note);

    if (cls.holdDisposition === "settle") {
      budget.settle(receiptId, cls.settledAmountUsd ?? quote.amountUsd);
    }
    // "keep" ⇒ leave the hold; it releases only at validBeforeTs + margin (§5.2).

    // 4. auto-deny strike (SPEC §5.4), gated on policy.
    if (policy.autoDeny.enabled) {
      const strikeCls = strikeClassFor(cls.outcome);
      if (strikeCls) budget.recordStrike(finalHost, strikeCls);
    }

    // 5. deliver body (inline/file) for delivered outcomes.
    let response: Response | null = null;
    if (cls.outcome === "paid_delivered" && retry.ok) {
      const delivered = deliverBody(retry.rawBody ?? new Uint8Array(0), responseMode, {
        fs: io.fs,
        downloadPath: this.#cfg.ledger.downloadPath(receiptId),
      });
      if (delivered.mode === "inline" && delivered.truncated) notes.push("body_truncated");
      response = this.materialize(retry, delivered);
    }

    const receipt = this.baseReceipt(
      receiptId, url, init, finalHost, cls.outcome, verdictPath, notes, quote, budgets,
      {
        rejectedQuotes: rejected,
        guards: guardResults,
        approval,
        http: retry.ok ? this.httpBlock(retry) : null,
        payment: {
          payerAddress,
          nonce: proof.nonce,
          validBeforeTs: proof.validBeforeTs,
          settledAmountUsd: cls.holdDisposition === "settle" ? cls.settledAmountUsd ?? quote.amountUsd : null,
          txRef: cls.txRef,
          settlementConfirmed: cls.settlementConfirmed,
        },
      },
    );
    return this.finish(receipt, response);
  }

  // === guards ===========================================================

  private async runGuard(
    guard: PrePayGuard,
    input: GuardInput,
    budgetMs: number,
  ): Promise<GuardResult> {
    const start = this.#deps.now();
    const TIMEOUT = Symbol("guard_timeout");
    try {
      // §7.5 belt-and-suspenders: the guard's own `guardFetchWithTimeout` aborts
      // the socket at the same mode-scoped budget; this race caps the WHOLE
      // check() (parse/crash included) at that budget so a wedged guard can never
      // hang the payment path. Enforce = generous cold-screen budget; advisory =
      // proceed-fast (guardBudgetMs).
      const res = await Promise.race([
        guard.check(input, this.#deps),
        this.#delay(budgetMs).then(() => TIMEOUT),
      ]);
      if (res === TIMEOUT) return this.guardUnavailableResult(guard.id, start, "timeout");
      return res as GuardResult;
    } catch (err) {
      this.#deps.log("guard.crash", { id: guard.id, message: scrub((err as Error).message) });
      return this.guardUnavailableResult(guard.id, start, "crash");
    }
  }
  private guardUnavailableResult(id: GuardId, start: number, reason: string): GuardResult {
    return { id, verdict: "unavailable", detail: { reason }, latencyMs: this.#deps.now() - start, costUsd: 0 };
  }

  // === approval (SPEC §6) ==============================================

  private async runApproval(
    policy: Policy,
    host: string,
    quote: PaymentQuote,
    guardResults: GuardResult[],
    budgets: RemainingBudgets,
    receiptId: string,
  ): Promise<
    | { kind: "approved"; approvedBy: "elicit" | "queue" | "config"; notes: string[] }
    | { kind: "denied"; outcome: Outcome; notes: string[] }
  > {
    // `approval.mode: "deny"` is the operator's HARD kill-switch — a "never
    // auto-pay above the threshold" gate (P3 money-path review). It is resolved
    // FIRST so a stale config pre-approval (preApprovedUpToUsd / preApprovedHosts)
    // can NEVER override it: a `deny` mode must fully deny above the threshold.
    // Pre-approval can only ever LOOSEN (grant an above-threshold auto-pay), so
    // ignoring it here makes `deny` strictly TIGHTER, never looser. Pre-approval
    // stays active in the elicit/queue modes below.
    const mode = policy.approval.mode;
    if (mode === "deny") {
      return { kind: "denied", outcome: "approval_denied", notes: ["approval_mode_deny"] };
    }

    // NON-elicitation config pre-approval (P3 review): an operator-EXPLICIT grant
    // (config.json is operator-owned; no tool mutates it) is honored in the
    // elicit/queue modes — the path a client that CANNOT elicit uses to transact
    // above threshold. Guards already ran (D8) and every cap still applies (D7 +
    // the D11 reserve), so this substitutes ONLY for the human gate. It is NEVER an
    // agent self-approval, so the M6 prohibition is untouched.
    const preNote = preApprovedNote(policy, host, quote);
    if (preNote) {
      return { kind: "approved", approvedBy: "config", notes: [preNote] };
    }

    if (mode === "queue") {
      return this.queueApproval(host, quote, receiptId, []);
    }
    // mode === "elicit"
    if (this.#deps.elicit === null) {
      // The client never advertised the `elicitation` capability — there is no
      // in-session human channel. Resolve via elicitFallback with a CLEAR cause note.
      return this.elicitUnavailable(policy, host, quote, receiptId, "elicit_unsupported");
    }
    // Elicit with timeout (SPEC §6, APPROVAL_ELICIT_TIMEOUT_S).
    const req: ElicitRequest = {
      host,
      resource: quote.resource,
      amountUsd: quote.amountUsd,
      networkLabel: quote.network,
      assetLabel: assetLabel(quote.asset),
      guards: guardResults,
      remainingBudgets: budgets,
    };
    type ElicitRace = { approved: boolean; cancelled?: boolean } | { __timeout: true };
    let decision: ElicitRace;
    try {
      decision = await Promise.race<ElicitRace>([
        this.#deps.elicit(req),
        this.#delay(APPROVAL_ELICIT_TIMEOUT_S * 1000).then(() => ({ __timeout: true }) as const),
      ]);
    } catch {
      // An elicitation channel ERROR (the bridge threw) is not a human decision —
      // it means the client couldn't service the prompt. Resolve like a cancel
      // (fail-closed via elicitFallback), NOT as a silent denial.
      return this.elicitUnavailable(policy, host, quote, receiptId, "elicit_cancelled");
    }
    if ("__timeout" in decision) {
      return { kind: "denied", outcome: "approval_timeout", notes: ["approval_timeout"] };
    }
    if (decision.cancelled) {
      // The client ADVERTISED elicitation but dismissed/cancelled the dialog without
      // a human decision (e.g. Claude Desktop returns `cancel` immediately). This is
      // NOT a denial — resolving it as "user said no" would silently block EVERY
      // above-threshold payment on such a client. Route it through elicitFallback,
      // exactly like an absent channel (P3 desktop-fallback fix).
      return this.elicitUnavailable(policy, host, quote, receiptId, "elicit_cancelled");
    }
    if (!decision.approved) {
      // A GENUINE human denial (declined, or left "approve" unchecked). No fallback.
      return { kind: "denied", outcome: "approval_denied", notes: [] };
    }
    return { kind: "approved", approvedBy: "elicit", notes: [] };
  }

  /**
   * Resolve an elicit-UNAVAILABLE (client never advertised elicitation, or
   * advertised it but cancelled/errored without a human decision). Per
   * `approval.elicitFallback`: `queue` → enqueue for an out-of-band approver;
   * `deny` → a CLEAR block, not a silent one — the `cause` note lets the tool layer
   * tell the operator the payment was blocked purely because the client can't elicit
   * (raise the threshold, set `preApprovedUpToUsd`, or pre-approve the host). SPEC §6.
   */
  private elicitUnavailable(
    policy: Policy,
    host: string,
    quote: PaymentQuote,
    receiptId: string,
    cause: "elicit_unsupported" | "elicit_cancelled",
  ):
    | { kind: "approved"; approvedBy: "queue"; notes: string[] }
    | { kind: "denied"; outcome: Outcome; notes: string[] } {
    const fb = policy.approval.elicitFallback;
    const fbNote = elicitUnsupportedFallback(fb);
    if (fb === "queue") {
      return this.queueApproval(host, quote, receiptId, [cause, fbNote]);
    }
    return { kind: "denied", outcome: "approval_denied", notes: [cause, fbNote] };
  }

  private queueApproval(
    host: string,
    quote: PaymentQuote,
    receiptId: string,
    extraNotes: string[],
  ):
    | { kind: "approved"; approvedBy: "queue"; notes: string[] }
    | { kind: "denied"; outcome: Outcome; notes: string[] } {
    const grant = this.#cfg.budget.findGrant(host, quote.amountUsd);
    if (grant) {
      this.#cfg.budget.consumeGrant(grant.approvalId);
      return { kind: "approved", approvedBy: "queue", notes: extraNotes };
    }
    this.#cfg.budget.addPendingApproval({
      approvalId: receiptId, // stable, unique per request
      host,
      amountUsd: quote.amountUsd,
      createdTs: this.#deps.now(),
      resource: quote.resource,
    });
    return { kind: "denied", outcome: "approval_queued", notes: extraNotes };
  }

  // === guardFetch (SPEC §7.5) ==========================================

  /**
   * L3 (hot-reload): the guard's live daily spend ceiling read from the CURRENT
   * policy snapshot (`policyProvider`), so lowering `guards.<id>.dailyBudgetUsd`
   * TIGHTENS guard spend without a restart — and raising it LOOSENS live — exactly
   * like the mode/verdict HIGH-fix (which threads the live config via `req.config`).
   * An invalid policy ⇒ 0 (free tier only, fail-safe). `buildDefaultGuards` wires
   * `makeGuardFetch`'s budget getter to this.
   */
  liveGuardBudgetUsd(id: GuardId): number {
    const pol = this.#cfg.policyProvider();
    if (!pol.ok) return 0;
    return id === "trust"
      ? pol.policy.guards.trust.dailyBudgetUsd
      : pol.policy.guards.safety.dailyBudgetUsd;
  }

  /**
   * Build a guard's `guardFetch` (SPEC §7.5). Budget 0 ⇒ plain `deps.fetch` (any
   * 402 becomes the guard's "unavailable"). Budget > 0 ⇒ a payer-backed wrapper
   * restricted to the guard's base host that pays from `guard:{id}:{day}` (plus
   * the main caps) and NEVER invokes approval or nested guards (review #9).
   *
   * L3: `budgetUsd` may be a LIVE getter (`() => number`) so the ceiling is read
   * from the current policy snapshot on EVERY call (hot-reload — tighten AND loosen
   * without restart). `buildDefaultGuards` passes `() => liveGuardBudgetUsd(id)`;
   * direct callers may pass a static number.
   */
  makeGuardFetch(
    id: GuardId,
    budgetUsd: number | (() => number),
    baseUrl: string | null,
  ): GuardRuntime["guardFetch"] {
    const resolveBudget = typeof budgetUsd === "function" ? budgetUsd : (): number => budgetUsd;
    return async (url: string, reqInit: RequestInit, opts?: { dryRun?: boolean }): Promise<Response> => {
      // Resolve the LIVE budget once per call (L3): tighten/loosen take effect
      // immediately, and the gate + reservation cap use the SAME value.
      const budget = resolveBudget();
      // §4.2/§L3: a dry-run is treated exactly like a zero budget — the FREE path,
      // never a reservation or signature — even when the guard has a budget.
      if (budget <= 0 || opts?.dryRun) return this.#deps.fetch(url, reqInit);
      let host: string;
      try {
        host = new URL(url).hostname;
      } catch {
        return this.#deps.fetch(url, reqInit);
      }
      const baseHost = baseUrl ? safeHostname(baseUrl) : null;
      if (baseHost && host !== baseHost) return this.#deps.fetch(url, reqInit); // pay only own host
      return this.payGuardFetch(id, budget, host, url, reqInit);
    };
  }

  private async payGuardFetch(
    id: GuardId,
    budgetUsd: number,
    host: string,
    url: string,
    reqInit: RequestInit,
  ): Promise<Response> {
    const deps = this.#deps;
    // L5 / SPEC §11 (re-pin, no off-host pay): a guard payment must be served
    // DIRECTLY by the guard's base host. `deps.fetch` is WHATWG fetch, which
    // auto-follows redirects; `redirect: "manual"` turns any 3xx into an opaque
    // redirect (status 0) — neither 402 nor 2xx — so a base host that 3xx-redirects
    // off-host to a 402 can NEVER have that 402 paid, and the proof retry likewise
    // cannot chase a redirect to a settling endpoint. A direct 200/402 is
    // unaffected. Only the PAYING path re-pins; the free path keeps default fetch.
    const resp = await deps.fetch(url, { ...reqInit, redirect: "manual" });
    if (resp.status !== 402) return resp;
    const bytes = new Uint8Array(await resp.arrayBuffer());
    const challenge = parseChallenge(bytes);
    const { quotes } = quoteWithRejections(challenge);
    const quote = selectQuote(quotes);
    // Any un-payable 402 stays a 402 ⇒ the guard maps it to "unavailable".
    const as402 = (): Response => new Response(bytes, { status: 402, headers: resp.headers });
    if (!quote) return as402();
    if (this.#cfg.testMode && quote.network === "base") return as402();

    const pol = this.#cfg.policyProvider();
    if (!pol.ok) return as402();
    const caps = this.capsOf(pol.policy);
    const receiptId = this.newReceiptId();
    const day = utcDate(deps.now());
    const reservation = this.#cfg.budget.reserve({
      holdId: receiptId,
      amountUsd: quote.amountUsd,
      host,
      caps,
      extra: [{ key: guardDayKey(id, day), cap: budgetUsd, which: `guard:${id}` }],
    });
    if (!reservation.ok) return as402();

    let proof;
    try {
      proof = await this.#cfg.payers[0].buildPayment(quote, deps.signer, deps);
    } catch {
      this.#cfg.budget.release(receiptId);
      return as402();
    }
    this.#cfg.budget.setHoldValidBefore(receiptId, proof.validBeforeTs);
    const payerAddress = await deps.signer.address();

    const method = (reqInit.method ?? "GET").toUpperCase();
    const userHeaders = stripReservedHeaders(reqInit.headers);
    const bodyStr = typeof reqInit.body === "string" ? reqInit.body : null;
    const retry = await deps.fetch(url, {
      method,
      headers: { ...userHeaders, ...proof.headers },
      body: bodyStr ?? undefined,
      redirect: "manual", // L5 / SPEC §11: never chase a redirect to an off-host settling endpoint.
    });
    const retryBytes = new Uint8Array(await retry.clone().arrayBuffer());
    // Settlement channel (§3.1a rule 5): PAYMENT-RESPONSE first, else X-PAYMENT-RESPONSE.
    const settlementHeader = readSettlementHeader(retry.headers);
    const settlement = settlementHeader ? parseSettlementResponse(settlementHeader) : null;
    const cls = classifyFromParts(retry.status, settlement, quote);
    if (cls.holdDisposition === "settle") {
      this.#cfg.budget.settle(receiptId, cls.settledAmountUsd ?? quote.amountUsd);
    }
    // NOTE (guard spend): no approval, no nested guards, no auto-deny strike on
    // the operator's own infra host (SPEC §7.2). Write a receipt like any spend.
    const budgets = this.#cfg.budget.remaining(caps, host);
    const receipt: Receipt = {
      schema: "p3f.receipt.v1",
      receiptId,
      ts: deps.now(),
      clientVersion: CLIENT_VERSION,
      policyVersion: POLICY_VERSION,
      test: this.#cfg.testMode,
      url,
      method,
      host,
      outcome: cls.outcome,
      denyCode: null,
      verdictPath: ["guard_spend"],
      quote,
      rejectedQuotes: null,
      guards: [],
      approval: null,
      payment: {
        payerAddress,
        nonce: proof.nonce,
        validBeforeTs: proof.validBeforeTs,
        settledAmountUsd: cls.holdDisposition === "settle" ? cls.settledAmountUsd ?? quote.amountUsd : null,
        txRef: cls.txRef,
        settlementConfirmed: cls.settlementConfirmed,
      },
      budgets: {
        dayRemainingUsd: budgets.dayRemainingUsd,
        hostRemainingUsd: budgets.hostRemainingUsd,
        totalRemainingUsd: budgets.totalRemainingUsd,
      },
      http: {
        status: retry.status,
        contentType: retry.headers.get("content-type"),
        bodyBytes: retryBytes.length,
        bodySha256: null,
        truncated: false,
        totalMs: 0,
      },
      notes: this.#cfg.testMode ? ["test_mode", ...(cls.note ? [cls.note] : [])] : cls.note ? [cls.note] : [],
    };
    this.#cfg.ledger.append(receipt);
    // Re-materialize so the guard can read the (2xx) body.
    return new Response(retryBytes, { status: retry.status, headers: retry.headers });
  }

  // === receipt construction / finish ===================================

  private detectPayer(challenge: ParsedChallenge): PaymentPayer {
    const p = this.#cfg.payers.find((x) => x.detects(challenge));
    // v1: x402 always detects an x402 challenge; fall back to the first payer.
    return p ?? this.#cfg.payers[0];
  }

  private quoteAndReject(
    challenge: ParsedChallenge,
    payer: PaymentPayer,
  ): { quotes: PaymentQuote[]; rejected: Record<string, number> } {
    if (payer.rail === "x402") return quoteWithRejections(challenge);
    return { quotes: payer.quotes(challenge), rejected: {} };
  }

  private httpBlock(t: TransportResult): Receipt["http"] {
    return {
      status: t.status,
      contentType: t.contentType,
      bodyBytes: t.bodyBytes,
      bodySha256: t.bodySha256,
      truncated: t.hardCapped,
      totalMs: t.totalMs,
    };
  }

  private materialize(t: TransportResult, delivered: ReturnType<typeof deliverBody>): Response {
    const headers = t.headers ?? new Headers();
    if (delivered.mode === "file") {
      return new Response(null, { status: t.status ?? 200, headers });
    }
    return new Response(delivered.text, { status: t.status ?? 200, headers });
  }

  private deny(
    receiptId: string,
    url: string,
    init: RequestInit,
    host: string,
    verdictPath: string[],
    notes: string[],
    quote: PaymentQuote | null,
    budgets: RemainingBudgets,
    denyCode: string,
    denyNotes: string[],
    outcome: Outcome,
    leg1: TransportResult,
    rejected?: Record<string, number>,
    guards?: GuardResult[],
    approval?: { mode: string; approvedBy: "elicit" | "queue" | "config" | null } | null,
  ): PayfetchFetchResult {
    for (const n of denyNotes) if (!notes.includes(n)) notes.push(n);
    const receipt = this.baseReceipt(receiptId, url, init, host, outcome, verdictPath, notes, quote, budgets, {
      denyCode,
      rejectedQuotes: rejected ?? null,
      guards: guards ?? [],
      http: this.httpBlock(leg1),
      approval: approval ?? null,
    });
    return this.finish(receipt, null);
  }

  /**
   * A D8 guard block (SPEC §7.4) — outcome + denyCode `guard_blocked`, carrying the
   * top-level `guardBlockReason` (P3 review §3) so the agent can tell a retryable
   * fail-close (degraded/timeout/unavailable) from a genuinely dangerous host
   * (danger). The distinguishing `guard_*:{id}` note is already on `notes`.
   */
  private denyGuardBlocked(
    receiptId: string,
    url: string,
    init: RequestInit,
    host: string,
    verdictPath: string[],
    notes: string[],
    quote: PaymentQuote | null,
    budgets: RemainingBudgets,
    leg1: TransportResult,
    rejected: Record<string, number>,
    guards: GuardResult[],
    reason: GuardBlockReason,
  ): PayfetchFetchResult {
    const receipt = this.baseReceipt(receiptId, url, init, host, "guard_blocked", verdictPath, notes, quote, budgets, {
      denyCode: "guard_blocked",
      rejectedQuotes: rejected,
      guards,
      http: this.httpBlock(leg1),
      guardBlockReason: reason,
    });
    return this.finish(receipt, null);
  }

  private baseReceipt(
    receiptId: string,
    url: string,
    init: RequestInit,
    host: string,
    outcome: Outcome,
    verdictPath: string[],
    notes: string[],
    quote: PaymentQuote | null,
    budgets: RemainingBudgets,
    extra: {
      denyCode?: string;
      rejectedQuotes?: Record<string, number> | null;
      guards?: GuardResult[];
      approval?: { mode: string; approvedBy: "elicit" | "queue" | "config" | null } | null;
      payment?: Receipt["payment"];
      http?: Receipt["http"];
      notesExtra?: string[];
      guardBlockReason?: GuardBlockReason;
    } = {},
  ): Receipt {
    const method = (init.method ?? "GET").toUpperCase();
    const finalNotes = [...notes];
    for (const n of extra.notesExtra ?? []) finalNotes.push(n);
    return {
      schema: "p3f.receipt.v1",
      receiptId,
      ts: this.#deps.now(),
      clientVersion: CLIENT_VERSION,
      policyVersion: POLICY_VERSION,
      test: this.#cfg.testMode,
      url,
      method,
      host,
      outcome,
      denyCode: extra.denyCode ?? null,
      guardBlockReason: extra.guardBlockReason ?? null,
      verdictPath: [...verdictPath],
      quote,
      rejectedQuotes: extra.rejectedQuotes ?? null,
      guards: extra.guards ?? [],
      approval: extra.approval ?? null,
      payment: extra.payment ?? null,
      budgets: {
        dayRemainingUsd: budgets.dayRemainingUsd,
        hostRemainingUsd: budgets.hostRemainingUsd,
        totalRemainingUsd: budgets.totalRemainingUsd,
      },
      http: extra.http ?? null,
      notes: finalNotes,
    };
  }

  private finish(receipt: Receipt, response: Response | null): PayfetchFetchResult {
    this.#cfg.ledger.append(receipt);
    return { response, receipt };
  }

  private decisionFromReceipt(r: Receipt): Decision {
    const decision: Decision["decision"] =
      r.outcome === "dry_run" ? "would_pay" : r.outcome === "free" ? "free" : "would_deny";
    return {
      outcome: r.outcome,
      denyCode: r.denyCode,
      decision,
      quote: r.quote,
      rejectedQuotes: r.rejectedQuotes,
      guards: r.guards,
      remainingBudgets: {
        dayRemainingUsd: r.budgets.dayRemainingUsd,
        hostRemainingUsd: r.budgets.hostRemainingUsd,
        totalRemainingUsd: r.budgets.totalRemainingUsd,
      },
      notes: r.notes,
    };
  }
}

// ---------------------------------------------------------------------------
// §5.2 terminal-event classification (table-driven, pure)
// ---------------------------------------------------------------------------

export type TerminalClass = {
  outcome: Outcome;
  holdDisposition: "settle" | "keep";
  settlementConfirmed: boolean;
  settledAmountUsd: number | null;
  txRef: string | null;
  note: string | null;
};

/** Classify a retry TransportResult per the §5.2 table. */
export function classifyTerminal(retry: TransportResult, quote: PaymentQuote): TerminalClass {
  if (!retry.ok) {
    // Guard-stage failure (proven not sent) ⇒ fetch_error, hold kept, no strike.
    if (retry.error === "private_target_blocked" || retry.error === "insecure_redirect") {
      return { outcome: "fetch_error", holdDisposition: "keep", settlementConfirmed: false, settledAmountUsd: null, txRef: null, note: null };
    }
    // Network/timeout after the request was issued (may have been sent) ⇒
    // unknown_settlement: hold KEPT, budgets over-count (SPEC §5.2/§0).
    return { outcome: "unknown_settlement", holdDisposition: "keep", settlementConfirmed: false, settledAmountUsd: null, txRef: null, note: null };
  }
  const settlement = retry.headers
    ? parseSettlementFromHeaders(retry.headers)
    : null;
  return classifyFromParts(retry.status ?? 0, settlement, quote);
}

/** Settlement channel (§3.1a rule 5): PAYMENT-RESPONSE first, else legacy X-PAYMENT-RESPONSE. */
function readSettlementHeader(headers: Headers): string | null {
  return headers.get(PAYMENT_RESPONSE_HEADER) ?? headers.get(X_PAYMENT_RESPONSE_HEADER);
}

function parseSettlementFromHeaders(headers: Headers): { success: boolean; transaction?: string } | null {
  const v = readSettlementHeader(headers);
  if (!v) return null;
  return parseSettlementResponse(v);
}

/** The pure §5.2 disposition given (status, settlement, quote). */
export function classifyFromParts(
  status: number,
  settlement: { success: boolean; transaction?: string } | null,
  _quote: PaymentQuote,
): TerminalClass {
  const confirmed = settlement?.success === true;
  const txRef = settlement?.transaction ?? null;
  const is2xx = status >= 200 && status < 300;

  if (is2xx) {
    if (confirmed) {
      return { outcome: "paid_delivered", holdDisposition: "settle", settlementConfirmed: true, settledAmountUsd: null, txRef, note: null };
    }
    // 2xx but no/unparseable/failed settlement evidence — we got goods, assume paid.
    return { outcome: "paid_delivered", holdDisposition: "settle", settlementConfirmed: false, settledAmountUsd: null, txRef, note: "settlement_unconfirmed" };
  }
  // non-2xx
  if (confirmed) {
    return { outcome: "paid_not_delivered", holdDisposition: "settle", settlementConfirmed: true, settledAmountUsd: null, txRef, note: null };
  }
  if (status >= 500) {
    // 5xx after header sent ⇒ unknown_settlement (hold kept).
    return { outcome: "unknown_settlement", holdDisposition: "keep", settlementConfirmed: false, settledAmountUsd: null, txRef: null, note: null };
  }
  // 402-again / 4xx, no settlement ⇒ payment_rejected (hold kept).
  return { outcome: "payment_rejected", holdDisposition: "keep", settlementConfirmed: false, settledAmountUsd: null, txRef: null, note: null };
}

/** Strike class an outcome contributes (SPEC §5.4). */
function strikeClassFor(o: Outcome): "confirmed" | "soft" | null {
  if (o === "paid_not_delivered" || o === "payment_rejected") return "confirmed";
  if (o === "unknown_settlement") return "soft";
  return null;
}

// ---------------------------------------------------------------------------
// Guard unavailable-resolution + block-reason helpers (SPEC §7.2/§7.3, P3 review)
// ---------------------------------------------------------------------------

/** True iff `res` is the safety guard's DEGRADED-screen fail-close (dim5-MED). */
function isDegradedScreen(res: GuardResult): boolean {
  return res.verdict === "unavailable" && res.detail?.reason === "degraded_screen";
}

/**
 * The PIPELINE's resolution of a guard "unavailable" (SPEC §7.2/§7.3 + P3 review
 * §4b). Advisory NEVER fail-closes (proceed + note only). Enforce splits the axes:
 * a DEGRADED screen resolves via the safety guard's `onDegraded`; any other
 * unavailability (dead P1 / 402 / 5xx / timeout / crash) via `onUnavailable`. Both
 * default "block". Only the safety guard has `onDegraded`; a trust guard degrade is
 * impossible (P2 has no `degraded` flag), so the `"onDegraded" in cfg` narrowing is
 * exact.
 */
function resolveUnavailable(
  cfg: TrustGuardConfig | SafetyGuardConfig,
  res: GuardResult,
): "proceed" | "warn" | "block" {
  if (cfg.mode !== "enforce") return "proceed";
  if (isDegradedScreen(res) && "onDegraded" in cfg) return cfg.onDegraded;
  return cfg.onUnavailable;
}

/** Why a `guard_blocked` fired, from the blocking guard result (P3 review §3). */
function guardBlockReasonFor(res: GuardResult): GuardBlockReason {
  if (res.verdict === "block") return "danger";
  const reason = typeof res.detail?.reason === "string" ? res.detail.reason : "";
  if (reason === "degraded_screen") return "degraded";
  if (reason === "timeout") return "timeout";
  return "unavailable";
}

/**
 * Config PRE-APPROVAL (P3 review): does an operator-explicit grant approve this
 * above-threshold payment without an in-session human dialog? A per-host allow
 * wins, else the `preApprovedUpToUsd` ceiling (integer-microUSD compare, inclusive).
 * Returns the `preapproved:{which}` receipt note, or null. Never bypasses caps.
 */
function preApprovedNote(policy: Policy, host: string, quote: PaymentQuote): PreapprovedNote | null {
  const a = policy.approval;
  if (matchesAnyHost(host, a.preApprovedHosts)) return preapproved("host");
  if (a.preApprovedUpToUsd !== null && microUsd(quote.amountUsd) <= microUsd(a.preApprovedUpToUsd)) {
    return preapproved("cap");
  }
  return null;
}

// ---------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------

function microUsd(x: number): number {
  return Number.isFinite(x) ? Math.round(x * 1_000_000) : Number.POSITIVE_INFINITY;
}

/**
 * Content-Type auto-default (1.0.1): when a request carries a body, the caller
 * supplied NO Content-Type (any case), and the body parses as a JSON object/array,
 * default `Content-Type: application/json`. WHATWG fetch / undici otherwise send a
 * string body as `text/plain`, which strict JSON APIs answer with a 400 — and on
 * the PAYING leg that burns an already-SIGNED x402 authorization on a header (the
 * observed `$0.007-dies-on-a-header` bug: Exa-shape POST → `payment_rejected`).
 * Applied ONCE in `run()` (after reserved-header stripping) so BOTH the initial
 * 402-probing request AND the paid retry carry it. An EXPLICIT caller Content-Type
 * ALWAYS wins; a scalar / non-JSON / empty body is left untouched (text/plain
 * default preserved) — the relabel is conservative, only for unambiguous JSON.
 */
export function applyJsonContentTypeDefault(
  headers: Record<string, string>,
  body: string | null,
): Record<string, string> {
  if (body === null || body.length === 0) return headers;
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === "content-type") return headers; // caller was explicit → wins
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return headers; // not JSON → keep the text/plain default
  }
  // Only an object/array body is UNAMBIGUOUSLY JSON; a bare scalar (number /
  // quoted string / bool / null) could legitimately be text, so never relabel it.
  if (typeof parsed !== "object" || parsed === null) return headers;
  return { ...headers, "Content-Type": "application/json" };
}

/** Strip reserved header names from user-supplied headers (SPEC §11). */
export function stripReservedHeaders(headers: RequestInit["headers"]): Record<string, string> {
  const reserved = new Set([
    X_PAYMENT_HEADER.toLowerCase(),
    X_PAYMENT_RESPONSE_HEADER.toLowerCase(),
    PAYMENT_SIGNATURE_HEADER.toLowerCase(),
    PAYMENT_RESPONSE_HEADER.toLowerCase(),
    INTEGRATION_HEADER.toLowerCase(),
  ]);
  const out: Record<string, string> = {};
  if (!headers) return out;
  const h = new Headers(headers);
  h.forEach((value, key) => {
    if (!reserved.has(key.toLowerCase())) out[key] = value;
  });
  return out;
}

/** Query-strip a guard target URL unless GUARD_SEND_QUERY (SPEC §7.1/§15). */
function guardUrl(fullUrl: string): string {
  if (GUARD_SEND_QUERY) return fullUrl;
  try {
    const u = new URL(fullUrl);
    return `${u.origin}${u.pathname}`;
  } catch {
    return fullUrl;
  }
}

function assetLabel(asset: string): string {
  const known = KNOWN_ASSETS.find((a) => a.address.toLowerCase() === asset.toLowerCase());
  return known?.label ?? asset;
}

function safeHostname(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

/** Per-reason rejection tally → §13 notes (only the codes §13 defines). */
function tallyNotes(rejected: Record<string, number>): string[] {
  const out: string[] = [];
  for (const reason of Object.keys(rejected)) {
    if (reason === "unsupported_scheme_upto") out.push("unsupported_scheme_upto");
    else if (reason === "unknown_asset") out.push("unknown_asset");
    else if (reason === "unsupported_network") out.push("unsupported_network");
  }
  return out;
}

/** Redact anything key-shaped from a string bound for logs/errors (SPEC §12). */
function scrub(s: string): string {
  return s.replace(/0x[0-9a-fA-F]{40,}/g, "0x<redacted>");
}
