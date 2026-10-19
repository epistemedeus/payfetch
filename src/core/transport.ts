/**
 * P3′ payfetch — transport mechanics: SSRF guard, DNS pin, redirects, caps (SPEC §11).
 *
 * Purpose: everything that happens to an HTTP request BEFORE the pipeline sees a
 * 402. The private-target/SSRF guard, manual redirect following with per-hop
 * re-guarding, per-leg timeouts, the hard read cap, inline truncation, and file
 * streaming all live here. Structured so the guard decision is a PURE function
 * over `(url, resolvedIps, policy)` — unit-testable without sockets — with the
 * undici DNS-pin wiring a thin shell around it.
 *
 * DNS PIN (P2-review #9, verbatim directive): "the vetted IP is the IP dialed"
 * cannot be done with stock fetch. Production dials through an `undici.Agent`
 * whose `connect.lookup` (a node `net` lookup fn) resolves the host, vets EVERY
 * returned address with the SAME `evaluateTarget`/`isBlockedIp` used by the loop,
 * and returns a vetted address — so the address the socket connects to is exactly
 * the one that passed the guard. The pin is never silently dropped: if no address
 * passes, the lookup errors and the connection fails closed.
 *
 * Invariants (SPEC §11, §0):
 *  - Schemes other than http/https are ALWAYS refused (conservative reading of
 *    §11 — `allowPrivateTargets` relaxes ONLY the private-IP blocklist, never the
 *    scheme restriction; a config flag must never enable `file:`/`ftp:`).
 *  - A host resolving to ANY blocked range is refused (rebinding-safe) unless
 *    `allowPrivateTargets`. Every redirect hop is re-resolved and re-guarded.
 *  - `https → http` downgrade on redirect ABORTS (`insecure_redirect`).
 *  - Policy/payment always evaluate against the FINAL host (§11) — the loop
 *    returns it; the receipt records the hop chain.
 *  - At most `RESPONSE_MAX_BYTES` are ever read; inline returns are truncated at
 *    `RESPONSE_INLINE_MAX_BYTES` with `body_truncated`.
 *  - Reserved header stripping (X-PAYMENT*, integration header) is done by the
 *    pipeline before calling in; this module never invents payment headers.
 */

import { createHash } from "node:crypto";

import {
  FETCH_TIMEOUT_MS,
  INTEGRATION_HEADER,
  MAX_REDIRECTS,
  RESPONSE_INLINE_MAX_BYTES,
  RESPONSE_MAX_BYTES,
  PAYMENT_SIGNATURE_HEADER,
  X_PAYMENT_HEADER,
  X_PAYMENT_RESPONSE_HEADER,
} from "./constants.js";
import type { PayfetchFs } from "./fs.js";
import type { Policy } from "./policy.js";

// ---------------------------------------------------------------------------
// IP blocklist (SPEC §11) — pure, unit-testable
// ---------------------------------------------------------------------------

/** Parse dotted-quad IPv4 to 4 octets, or null. */
export function parseIpv4(s: string): number[] | null {
  const m = s.split(".");
  if (m.length !== 4) return null;
  const out: number[] = [];
  for (const part of m) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    out.push(n);
  }
  return out;
}

/** Parse IPv6 (incl. "::" compression and embedded IPv4) to 8 hextets, or null. */
export function parseIpv6(input: string): number[] | null {
  let s = input;
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  // Strip a zone id (fe80::1%eth0).
  const pct = s.indexOf("%");
  if (pct >= 0) s = s.slice(0, pct);
  if (!s.includes(":")) return null;

  // Embedded IPv4 tail (::ffff:1.2.3.4).
  let tailHextets: number[] = [];
  const lastColon = s.lastIndexOf(":");
  const tail = s.slice(lastColon + 1);
  if (tail.includes(".")) {
    const v4 = parseIpv4(tail);
    if (!v4) return null;
    tailHextets = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
    s = s.slice(0, lastColon + 1); // keep trailing colon for splitting
  }

  const halves = s.split("::");
  if (halves.length > 2) return null;

  const toHextets = (part: string): number[] | null => {
    if (part === "") return [];
    const groups = part.split(":").filter((g) => g.length > 0);
    const out: number[] = [];
    for (const g of groups) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };

  if (halves.length === 2) {
    const head = toHextets(halves[0]);
    const rest = toHextets(halves[1]);
    if (head === null || rest === null) return null;
    const full = [...head, ...rest, ...tailHextets];
    if (full.length > 8) return null;
    const zeros = new Array(8 - full.length).fill(0);
    return [...head, ...zeros, ...rest, ...tailHextets];
  }
  const head = toHextets(halves[0]);
  if (head === null) return null;
  const full = [...head, ...tailHextets];
  return full.length === 8 ? full : null;
}

function isBlockedIpv4(o: number[]): boolean {
  const [a, b] = o;
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10/8 RFC1918
  if (a === 127) return true; // 127/8 loopback
  if (a === 169 && b === 254) return true; // 169.254/16 link-local
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16/12 RFC1918
  if (a === 192 && b === 168) return true; // 192.168/16 RFC1918
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64/10 CGNAT
  return false;
}

function isBlockedIpv6(h: number[]): boolean {
  if (h.every((x) => x === 0)) return true; // :: unspecified
  if (h.slice(0, 7).every((x) => x === 0) && h[7] === 1) return true; // ::1 loopback
  if ((h[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((h[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 ULA
  // IPv4-mapped ::ffff:a.b.c.d → check embedded v4.
  if (h.slice(0, 5).every((x) => x === 0) && h[5] === 0xffff) {
    const v4 = [(h[6] >> 8) & 0xff, h[6] & 0xff, (h[7] >> 8) & 0xff, h[7] & 0xff];
    return isBlockedIpv4(v4);
  }
  return false;
}

/**
 * Is `ip` in a blocked range (SPEC §11: RFC1918 / loopback / link-local /
 * CGNAT / 0.0.0.0/8 / IPv6 loopback+link-local+ULA)? An unparseable literal is
 * treated as blocked (fail closed).
 */
export function isBlockedIp(ip: string): boolean {
  const v4 = parseIpv4(ip);
  if (v4) return isBlockedIpv4(v4);
  const v6 = parseIpv6(ip);
  if (v6) return isBlockedIpv6(v6);
  return true; // unrecognized ⇒ refuse
}

// ---------------------------------------------------------------------------
// Target evaluation (SPEC §11) — pure over (url, resolvedIps, policy)
// ---------------------------------------------------------------------------

export type TargetReason = "scheme" | "private_target" | "invalid_url" | "unresolved";
export type TargetVerdict = { ok: true; host: string } | { ok: false; reason: TargetReason };

/**
 * Decide whether `url` may be dialed given its `resolvedIps` and the policy
 * (SPEC §11). Pure: no sockets, no DNS. Scheme restriction is unconditional;
 * `allowPrivateTargets` relaxes only the IP blocklist. A host resolving to ANY
 * blocked IP is refused (rebinding-safe).
 */
export function evaluateTarget(
  url: string,
  resolvedIps: readonly string[],
  policy: Pick<Policy, "allowPrivateTargets">,
): TargetVerdict {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return { ok: false, reason: "invalid_url" };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { ok: false, reason: "scheme" };
  }
  if (policy.allowPrivateTargets) return { ok: true, host: u.hostname };
  if (resolvedIps.length === 0) return { ok: false, reason: "unresolved" };
  for (const ip of resolvedIps) {
    if (isBlockedIp(ip)) return { ok: false, reason: "private_target" };
  }
  return { ok: true, host: u.hostname };
}

// ---------------------------------------------------------------------------
// DNS pin: undici Agent connect.lookup (SPEC §11 verbatim directive)
// ---------------------------------------------------------------------------

/** One resolved address in the modern (options.all) callback shape. */
export type LookupAddress = { address: string; family: number };

/**
 * node `net` lookup options. `net.connect` passes `all: true` when
 * `autoSelectFamily` is enabled (the Node ≥20 DEFAULT) and then expects the
 * callback as `(err, LookupAddress[])`; without `all` it expects the legacy
 * `(err, address, family)` 3-arg form. Both shapes MUST be honored — returning
 * a string to an `all: true` caller makes net index it like an array and dial
 * `undefined` (live-eval #1 production bug).
 */
export type NetLookupOptions = { all?: boolean; family?: number };

type NetLookupCb = (
  err: Error | null,
  address: string | LookupAddress[],
  family?: number,
) => void;
type NetLookup = (
  hostname: string,
  options: NetLookupOptions | undefined,
  callback: NetLookupCb,
) => void;

/**
 * Build the pinned `connect.lookup` for an undici Agent (SPEC §11). Resolves via
 * the injected async resolver, vets every address with the SAME blocklist the
 * transport loop uses, and dials only VETTED addresses — or errors, failing
 * closed. This is the load-bearing "vetted IP is the IP dialed" guarantee; do
 * not bypass it. Honors both `net` callback contracts (see NetLookupOptions):
 * with `all: true` every vetted address is returned so autoSelectFamily can
 * race them — the rebinding-safe rule is unchanged (ANY blocked resolution
 * refuses the whole host, so "all vetted" ≡ "all resolved" when it succeeds).
 */
export function createPinnedLookup(
  resolve: (host: string) => Promise<string[]>,
  policy: Pick<Policy, "allowPrivateTargets">,
): NetLookup {
  return (hostname, options, callback) => {
    const fail = (err: Error): void => {
      if (options?.all) callback(err, []);
      else callback(err, "", 0);
    };
    const deliver = (ips: string[]): void => {
      if (options?.all) {
        callback(
          null,
          ips.map((ip) => ({ address: ip, family: parseIpv4(ip) ? 4 : 6 })),
        );
        return;
      }
      const ip = ips[0];
      callback(null, ip, parseIpv4(ip) ? 4 : 6);
    };
    resolve(hostname)
      .then((ips) => {
        if (ips.length === 0) {
          fail(new Error(`payfetch: DNS resolution failed for ${hostname}`));
          return;
        }
        if (policy.allowPrivateTargets) {
          deliver(ips);
          return;
        }
        if (ips.some((ip) => isBlockedIp(ip))) {
          // ANY blocked address refuses the host (rebinding-safe). Fail closed.
          fail(
            new Error(`payfetch: refusing to dial ${hostname} — resolves to a blocked address`),
          );
          return;
        }
        deliver(ips); // none blocked ⇒ every address is vetted
      })
      .catch((err) => fail(err as Error));
  };
}

// ---------------------------------------------------------------------------
// HTTP client seam — low-level, no auto-follow, readable Location (SPEC §11)
// ---------------------------------------------------------------------------

export type HttpResponse = {
  status: number;
  headers: Headers;
  body: ReadableStream<Uint8Array> | null;
};
export type HttpRequestInit = {
  method: string;
  headers: Record<string, string>;
  body: string | null;
  signal?: AbortSignal;
};
export type HttpClient = (url: string, init: HttpRequestInit) => Promise<HttpResponse>;

/**
 * Adapt a WHATWG `fetch` into the low-level client (tests inject FakeFetch here;
 * also used for guard calls). `redirect: "manual"` keeps us in control of hops —
 * FakeFetch ignores it and exposes Location/status directly. Production transport
 * uses `createUndiciHttpClient` instead (stock fetch hides Location on manual
 * redirects — SPEC §11 rationale).
 */
export function adaptFetch(fetchFn: typeof fetch): HttpClient {
  return async (url, init) => {
    const resp = await fetchFn(url, {
      method: init.method,
      headers: init.headers,
      body: init.body ?? undefined,
      redirect: "manual",
      signal: init.signal,
    });
    return { status: resp.status, headers: resp.headers, body: resp.body };
  };
}

// ---------------------------------------------------------------------------
// Capped body read (SPEC §11 hard read cap)
// ---------------------------------------------------------------------------

export type CappedBody = { bytes: Uint8Array; hardCapped: boolean };

/** Read at most `maxBytes` from a stream; flag whether the source exceeded it. */
export async function readCapped(
  body: ReadableStream<Uint8Array> | null,
  maxBytes: number,
): Promise<CappedBody> {
  if (body === null) return { bytes: new Uint8Array(0), hardCapped: false };
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let hardCapped = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    if (total + value.length > maxBytes) {
      chunks.push(value.subarray(0, maxBytes - total));
      total = maxBytes;
      hardCapped = true;
      await reader.cancel().catch(() => {});
      break;
    }
    chunks.push(value);
    total += value.length;
  }
  const bytes = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    bytes.set(c, off);
    off += c.length;
  }
  return { bytes, hardCapped };
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

// ---------------------------------------------------------------------------
// Transport fetch loop (SPEC §11) — manual redirects, re-guard each hop
// ---------------------------------------------------------------------------

export type TransportIo = {
  request: HttpClient;
  /** Resolve a host to IPs for per-hop guarding (prod: dns.lookup all). */
  resolve: (host: string) => Promise<string[]>;
  fs: PayfetchFs;
  now: () => number;
  log: (msg: string, fields?: Record<string, unknown>) => void;
  /** Injected timer for the per-leg timeout (tests can neutralize it). */
  setTimer?: (fn: () => void, ms: number) => { clear: () => void };
};

export type TransportError = "private_target_blocked" | "insecure_redirect" | "fetch_error";

/** Per-call transport options (SPEC §11). */
export type TransportOpts = {
  /**
   * Follow 3xx redirects (default true). The PAYING leg passes `false` (L1 / §11):
   * the signed payment header is presented ONLY to the 402-issuing host
   * (`leg1.finalUrl`) and a redirect is NOT chased — mirroring the guard path's
   * `redirect:"manual"`. A 3xx is returned as a terminal response.
   */
  followRedirects?: boolean;
};

export type TransportResult = {
  ok: boolean;
  error: TransportError | null;
  finalUrl: string;
  finalHost: string;
  status: number | null;
  headers: Headers | null;
  contentType: string | null;
  /** The capped raw body bytes (for 402 challenge parse / body handling). */
  rawBody: Uint8Array | null;
  bodyBytes: number | null;
  bodySha256: string | null;
  hardCapped: boolean;
  hopChain: string[];
  redirectCount: number;
  notes: string[];
  totalMs: number;
};

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * Headers that MUST NOT be replayed across a CROSS-ORIGIN redirect (I2 / THESIS
 * §9 / §11): a signed payment proof or a bearer/cookie credential is scoped to
 * the origin it was minted for, so a redirect A→B (different origin) must not
 * carry it to B. Same-origin hops keep them (the credential is still for that
 * origin). Lowercased for case-insensitive matching. `X-PAYMENT` and
 * `PAYMENT-SIGNATURE` cover the paying leg's proof. `Authorization`, `Cookie`,
 * and `Proxy-Authorization` cover user-supplied credentials. The integration
 * header is our own per-target identity. (The paying leg additionally never
 * FOLLOWS redirects — `followRedirects: false`, the guard-path `redirect:"manual"`
 * discipline — so
 * this is defense-in-depth for the leg-1 resource fetch.)
 */
const SENSITIVE_REDIRECT_HEADERS: ReadonlySet<string> = new Set([
  "authorization",
  "cookie",
  "proxy-authorization",
  X_PAYMENT_HEADER.toLowerCase(),
  X_PAYMENT_RESPONSE_HEADER.toLowerCase(),
  PAYMENT_SIGNATURE_HEADER.toLowerCase(),
  INTEGRATION_HEADER.toLowerCase(),
]);

/** Drop sensitive headers (case-insensitive) for a cross-origin redirect hop. */
function stripSensitiveHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (!SENSITIVE_REDIRECT_HEADERS.has(k.toLowerCase())) out[k] = v;
  }
  return out;
}

function defaultTimer(fn: () => void, ms: number): { clear: () => void } {
  const t = setTimeout(fn, ms);
  return { clear: () => clearTimeout(t) };
}

/**
 * Fetch `url` with SSRF guarding, manual redirect following (≤ MAX_REDIRECTS,
 * re-guarded each hop), per-leg timeout, and the hard read cap (SPEC §11).
 * Returns a normalized result; the caller (pipeline) maps it to an outcome and
 * applies inline/file body handling.
 */
export async function transportFetch(
  url: string,
  init: { method: string; headers: Record<string, string>; body: string | null },
  policy: Pick<Policy, "allowPrivateTargets">,
  io: TransportIo,
  opts: TransportOpts = {},
): Promise<TransportResult> {
  const startMs = io.now();
  const timer = io.setTimer ?? defaultTimer;
  // L1 / §11 (paying-leg discipline): the caller may forbid redirect following so
  // a signed proof is presented ONLY to the 402-issuing host — the guard path's
  // `redirect:"manual"`. A 3xx then becomes a terminal response (classified
  // payment_rejected, hold kept) instead of chasing an off-host settling endpoint.
  const followRedirects = opts.followRedirects ?? true;
  const hopChain: string[] = [];
  const notes: string[] = [];
  let current = url;
  let method = init.method;
  let body = init.body;
  // Mutable so a cross-origin redirect can drop sensitive headers (I2); starts as
  // the caller's headers and is replayed as-is across SAME-origin hops.
  let headers = init.headers;
  let redirectCount = 0;

  const base = (finalUrl: string): TransportResult => ({
    ok: false,
    error: null,
    finalUrl,
    finalHost: safeHost(finalUrl),
    status: null,
    headers: null,
    contentType: null,
    rawBody: null,
    bodyBytes: null,
    bodySha256: null,
    hardCapped: false,
    hopChain,
    redirectCount,
    notes,
    totalMs: io.now() - startMs,
  });

  for (;;) {
    // --- per-hop guard (re-resolve + re-evaluate) ---
    let host: string;
    let ips: string[];
    try {
      host = new URL(current).hostname;
    } catch {
      return { ...base(current), error: "fetch_error" };
    }
    try {
      ips = await io.resolve(host);
    } catch {
      ips = [];
    }
    const verdict = evaluateTarget(current, ips, policy);
    if (!verdict.ok) {
      if (verdict.reason === "scheme" || verdict.reason === "private_target") {
        notes.push("private_target_blocked");
        return { ...base(current), error: "private_target_blocked" };
      }
      return { ...base(current), error: "fetch_error" };
    }
    hopChain.push(current);

    // --- issue the request with a per-leg timeout ---
    const controller = new AbortController();
    const t = timer(() => controller.abort(), FETCH_TIMEOUT_MS);
    let resp: HttpResponse;
    try {
      resp = await io.request(current, { method, headers, body, signal: controller.signal });
    } catch (err) {
      io.log("transport.fetch_error", { host, message: (err as Error).message });
      return { ...base(current), error: "fetch_error" };
    } finally {
      t.clear();
    }

    // --- redirect handling ---
    if (followRedirects && REDIRECT_STATUSES.has(resp.status) && redirectCount < MAX_REDIRECTS) {
      const location = resp.headers.get("location");
      if (location) {
        await resp.body?.cancel().catch(() => {});
        let next: URL;
        try {
          next = new URL(location, current);
        } catch {
          return { ...base(current), error: "fetch_error" };
        }
        if (new URL(current).protocol === "https:" && next.protocol === "http:") {
          notes.push("insecure_redirect");
          return { ...base(current), error: "insecure_redirect" };
        }
        redirectCount += 1;
        // I2 / §11: a CROSS-ORIGIN redirect drops sensitive headers (Authorization,
        // Cookie, X-PAYMENT*, integration) so a credential/proof never reaches an
        // intermediate or third-party host. Same-origin hops keep them.
        if (new URL(current).origin !== next.origin) {
          headers = stripSensitiveHeaders(headers);
        }
        // 303 (and legacy 301/302 on non-GET/HEAD) → GET without a body.
        if (resp.status === 303 || (method !== "GET" && method !== "HEAD" && resp.status !== 307 && resp.status !== 308)) {
          method = "GET";
          body = null;
        }
        current = next.toString();
        continue;
      }
    }

    // --- terminal response: read the body (capped) ---
    const { bytes, hardCapped } = await readCapped(resp.body, RESPONSE_MAX_BYTES);
    if (redirectCount > 0) notes.push(`redirected:${redirectCount}`);
    return {
      ok: true,
      error: null,
      finalUrl: current,
      finalHost: safeHost(current),
      status: resp.status,
      headers: resp.headers,
      contentType: resp.headers.get("content-type"),
      rawBody: bytes,
      bodyBytes: bytes.length,
      bodySha256: sha256(bytes),
      hardCapped,
      hopChain,
      redirectCount,
      notes,
      totalMs: io.now() - startMs,
    };
  }
}

function safeHost(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

// ---------------------------------------------------------------------------
// Body delivery (SPEC §11) — inline truncation / file streaming
// ---------------------------------------------------------------------------

export type DeliveredBody =
  | { mode: "inline"; text: string; truncated: boolean }
  | { mode: "file"; path: string; truncated: false };

/**
 * Deliver a terminal body per `responseMode` (SPEC §11). Inline returns ≤
 * `RESPONSE_INLINE_MAX_BYTES` (truncating with a flag); file writes the full
 * capped body to `{dataDir}/downloads/{receiptId}` and returns the path.
 */
export function deliverBody(
  bytes: Uint8Array,
  responseMode: "inline" | "file",
  ctx: { fs: PayfetchFs; downloadPath: string },
): DeliveredBody {
  if (responseMode === "file") {
    ctx.fs.writeBytes(ctx.downloadPath, bytes);
    return { mode: "file", path: ctx.downloadPath, truncated: false };
  }
  const truncated = bytes.length > RESPONSE_INLINE_MAX_BYTES;
  const slice = truncated ? bytes.subarray(0, RESPONSE_INLINE_MAX_BYTES) : bytes;
  return { mode: "inline", text: new TextDecoder("utf-8", { fatal: false }).decode(slice), truncated };
}
