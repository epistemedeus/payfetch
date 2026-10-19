/**
 * P3′ payfetch — transport tests (SPEC §11, §14 "Transport").
 *
 * Pure-guard coverage (no sockets): isBlockedIp across IPv4/IPv6 ranges;
 * evaluateTarget scheme + private-IP refusal + allowPrivateTargets override; the
 * pinned lookup blocks private resolutions. Loop coverage (FakeFetch): redirect
 * re-guard, https→http downgrade abort, inline truncation boundary, file mode.
 */

import { describe, expect, it } from "vitest";

import { RESPONSE_INLINE_MAX_BYTES } from "../src/core/constants.js";
import {
  adaptFetch,
  createPinnedLookup,
  deliverBody,
  evaluateTarget,
  isBlockedIp,
  parseIpv6,
  transportFetch,
  type TransportIo,
} from "../src/core/transport.js";
import { FakeFetch, hostResolver, inMemoryFs, fakeClock } from "./fakes.js";

const OPEN = { allowPrivateTargets: false };

describe("isBlockedIp — SPEC §11 blocklist (pure)", () => {
  it("blocks IPv4 private / loopback / link-local / CGNAT / 0.0.0.0", () => {
    for (const ip of [
      "10.0.0.1",
      "172.16.5.5",
      "172.31.255.255",
      "192.168.1.1",
      "127.0.0.1",
      "169.254.1.1",
      "100.64.0.1",
      "0.0.0.0",
    ]) {
      expect(isBlockedIp(ip)).toBe(true);
    }
  });

  it("allows public IPv4", () => {
    for (const ip of ["8.8.8.8", "93.184.216.34", "1.1.1.1", "172.32.0.1", "172.15.0.1"]) {
      expect(isBlockedIp(ip)).toBe(false);
    }
  });

  it("blocks IPv6 loopback / link-local / ULA / mapped-private", () => {
    expect(isBlockedIp("::1")).toBe(true);
    expect(isBlockedIp("fe80::1")).toBe(true);
    expect(isBlockedIp("fc00::1")).toBe(true);
    expect(isBlockedIp("fd12:3456::1")).toBe(true);
    expect(isBlockedIp("::ffff:127.0.0.1")).toBe(true);
    expect(isBlockedIp("::")).toBe(true);
  });

  it("allows public IPv6 and treats garbage as blocked (fail closed)", () => {
    expect(isBlockedIp("2606:4700:4700::1111")).toBe(false);
    expect(isBlockedIp("not-an-ip")).toBe(true);
  });

  it("parseIpv6 handles compression + embedded IPv4", () => {
    expect(parseIpv6("::1")).toEqual([0, 0, 0, 0, 0, 0, 0, 1]);
    expect(parseIpv6("::ffff:1.2.3.4")).toEqual([0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304]);
  });
});

describe("evaluateTarget — SPEC §11 (pure)", () => {
  it("refuses non-http(s) schemes unconditionally (even with allowPrivateTargets)", () => {
    expect(evaluateTarget("file:///etc/passwd", [], OPEN)).toMatchObject({ reason: "scheme" });
    expect(evaluateTarget("file:///etc/passwd", [], { allowPrivateTargets: true })).toMatchObject({
      reason: "scheme",
    });
  });

  it("refuses a host resolving to ANY blocked IP (rebinding-safe)", () => {
    expect(evaluateTarget("http://x.com", ["93.184.216.34", "10.0.0.1"], OPEN)).toMatchObject({
      reason: "private_target",
    });
  });

  it("allows a public host, and honors allowPrivateTargets", () => {
    expect(evaluateTarget("https://x.com", ["93.184.216.34"], OPEN)).toMatchObject({ ok: true });
    expect(evaluateTarget("http://x.com", ["10.0.0.1"], { allowPrivateTargets: true })).toMatchObject({
      ok: true,
    });
  });

  it("unresolved host → refused", () => {
    expect(evaluateTarget("https://x.com", [], OPEN)).toMatchObject({ reason: "unresolved" });
  });
});

describe("createPinnedLookup — the DNS pin (SPEC §11)", () => {
  type CbArgs = { err: Error | null; addr: unknown; family?: number };
  const invoke = (
    lookup: ReturnType<typeof createPinnedLookup>,
    host: string,
    options: Parameters<ReturnType<typeof createPinnedLookup>>[1],
  ): Promise<CbArgs> =>
    new Promise((res) => lookup(host, options, (err, addr, family) => res({ err, addr, family })));

  it("returns a vetted public address and errors on a private resolution (legacy form)", async () => {
    const lookup = createPinnedLookup(hostResolver({ "good.com": ["93.184.216.34"] }), OPEN);
    const okRes = await invoke(lookup, "good.com", {});
    expect(okRes.err).toBeNull();
    expect(okRes.addr).toBe("93.184.216.34");
    expect(okRes.family).toBe(4);

    const blockLookup = createPinnedLookup(hostResolver({ "evil.com": ["10.0.0.1"] }), OPEN);
    const blocked = await invoke(blockLookup, "evil.com", {});
    expect(blocked.err).not.toBeNull();
  });

  it("legacy form also holds when options is omitted (undefined)", async () => {
    const lookup = createPinnedLookup(hostResolver({ "good.com": ["93.184.216.34"] }), OPEN);
    const res = await invoke(lookup, "good.com", undefined);
    expect(res.err).toBeNull();
    expect(res.addr).toBe("93.184.216.34"); // a STRING, with family as third arg
    expect(res.family).toBe(4);
  });

  it("modern net contract (all:true, autoSelectFamily): ARRAY of {address,family}, all vetted, mixed v4/v6", async () => {
    // Node ≥20 net.connect passes {all: true, family: 0} and expects an array —
    // the live-eval #1 regression: a string here dials `undefined`.
    const lookup = createPinnedLookup(
      hostResolver({ "good.com": ["93.184.216.34", "2606:4700:4700::1111"] }),
      OPEN,
    );
    const res = await invoke(lookup, "good.com", { all: true, family: 0 });
    expect(res.err).toBeNull();
    expect(res.addr).toEqual([
      { address: "93.184.216.34", family: 4 },
      { address: "2606:4700:4700::1111", family: 6 },
    ]);
  });

  it("all:true + ANY blocked address in the resolve set → error (rebinding rule intact)", async () => {
    const lookup = createPinnedLookup(
      hostResolver({ "evil.com": ["93.184.216.34", "10.0.0.1"] }),
      OPEN,
    );
    const res = await invoke(lookup, "evil.com", { all: true, family: 0 });
    expect(res.err).not.toBeNull();
    expect(res.err?.message).toMatch(/blocked/);
  });

  it("all:true + allowPrivateTargets → every resolved address returned as {address,family}", async () => {
    const lookup = createPinnedLookup(
      hostResolver({ internal: ["10.0.0.1", "fd12:3456::1"] }),
      { allowPrivateTargets: true },
    );
    const res = await invoke(lookup, "internal", { all: true, family: 0 });
    expect(res.err).toBeNull();
    expect(res.addr).toEqual([
      { address: "10.0.0.1", family: 4 },
      { address: "fd12:3456::1", family: 6 },
    ]);
  });

  it("all:true + unresolvable host → error with an empty array shape (fail closed)", async () => {
    const lookup = createPinnedLookup(hostResolver({}, []), OPEN);
    const res = await invoke(lookup, "nowhere.example", { all: true });
    expect(res.err).not.toBeNull();
    expect(res.addr).toEqual([]);
  });
});

function io(fetch: FakeFetch, resolve: (h: string) => Promise<string[]>): TransportIo {
  return {
    request: adaptFetch(fetch.fetch),
    resolve,
    fs: inMemoryFs(),
    now: fakeClock().now,
    log: () => {},
    // Neutralize the per-leg timeout so a hermetic hang cannot stall the suite.
    setTimer: () => ({ clear: () => {} }),
  };
}

describe("transportFetch — redirects + guards + caps (SPEC §11)", () => {
  it("follows a redirect, re-guards each hop, and reports the hop chain", async () => {
    const fetch = new FakeFetch()
      .on("GET", "https://a.com/", { status: 302, headers: { location: "https://b.com/" } })
      .on("GET", "https://b.com/", { status: 200, textBody: "ok" });
    const res = await transportFetch(
      "https://a.com/",
      { method: "GET", headers: {}, body: null },
      OPEN,
      io(fetch, hostResolver()),
    );
    expect(res.ok).toBe(true);
    expect(res.finalHost).toBe("b.com");
    expect(res.hopChain).toEqual(["https://a.com/", "https://b.com/"]);
    expect(res.redirectCount).toBe(1);
    expect(res.notes).toContain("redirected:1");
  });

  it("blocks a redirect to a private-resolving host (re-guard each hop)", async () => {
    const fetch = new FakeFetch()
      .on("GET", "https://a.com/", { status: 302, headers: { location: "https://internal/" } });
    const res = await transportFetch(
      "https://a.com/",
      { method: "GET", headers: {}, body: null },
      OPEN,
      io(fetch, hostResolver({ internal: ["10.0.0.5"], "a.com": ["93.184.216.34"] })),
    );
    expect(res.ok).toBe(false);
    expect(res.error).toBe("private_target_blocked");
  });

  it("aborts an https→http downgrade redirect (insecure_redirect)", async () => {
    const fetch = new FakeFetch().on("GET", "https://a.com/", {
      status: 301,
      headers: { location: "http://a.com/" },
    });
    const res = await transportFetch(
      "https://a.com/",
      { method: "GET", headers: {}, body: null },
      OPEN,
      io(fetch, hostResolver({ "a.com": ["93.184.216.34"] })),
    );
    expect(res.ok).toBe(false);
    expect(res.error).toBe("insecure_redirect");
    expect(res.notes).toContain("insecure_redirect");
  });

  // I2 — strip sensitive/Authorization headers on a CROSS-ORIGIN redirect (both legs).
  it("strips sensitive headers (Authorization, Cookie, X-PAYMENT) on a CROSS-ORIGIN redirect", async () => {
    const fetch = new FakeFetch()
      .on("GET", "https://a.com/", { status: 302, headers: { location: "https://b.com/" } })
      .on("GET", "https://b.com/", { status: 200, textBody: "ok" });
    await transportFetch(
      "https://a.com/",
      {
        method: "GET",
        headers: {
          authorization: "Bearer secret",
          cookie: "sid=abc",
          "x-payment": "proof",
          "payment-signature": "v2proof",
          "x-custom": "keep",
        },
        body: null,
      },
      OPEN,
      io(fetch, hostResolver()),
    );
    const toA = fetch.calls.find((c) => c.url === "https://a.com/")!;
    const toB = fetch.calls.find((c) => c.url === "https://b.com/")!;
    expect(toA.headers["authorization"]).toBe("Bearer secret"); // first hop keeps them
    expect(toA.headers["x-payment"]).toBe("proof");
    expect(toA.headers["payment-signature"]).toBe("v2proof");
    expect(toB.headers["authorization"]).toBeUndefined(); // cross-origin ⇒ stripped
    expect(toB.headers["cookie"]).toBeUndefined();
    expect(toB.headers["x-payment"]).toBeUndefined();
    expect(toB.headers["payment-signature"]).toBeUndefined();
    expect(toB.headers["x-custom"]).toBe("keep"); // a non-sensitive header survives
  });

  it("KEEPS sensitive headers on a SAME-origin redirect (still that origin's credential)", async () => {
    const fetch = new FakeFetch()
      .on("GET", "https://a.com/", { status: 302, headers: { location: "https://a.com/next" } })
      .on("GET", "https://a.com/next", { status: 200, textBody: "ok" });
    await transportFetch(
      "https://a.com/",
      { method: "GET", headers: { authorization: "Bearer secret" }, body: null },
      OPEN,
      io(fetch, hostResolver()),
    );
    const toNext = fetch.calls.find((c) => c.url === "https://a.com/next")!;
    expect(toNext.headers["authorization"]).toBe("Bearer secret");
  });

  // L1 — the paying-leg discipline: followRedirects:false returns a 3xx as terminal.
  it("followRedirects:false returns a 3xx as a TERMINAL response (never chases it off-host)", async () => {
    // b.com has NO route — if the redirect were followed, FakeFetch would throw.
    const fetch = new FakeFetch().on("GET", "https://a.com/", {
      status: 302,
      headers: { location: "https://b.com/" },
    });
    const res = await transportFetch(
      "https://a.com/",
      { method: "GET", headers: { "x-payment": "proof" }, body: null },
      OPEN,
      io(fetch, hostResolver()),
      { followRedirects: false },
    );
    expect(res.ok).toBe(true);
    expect(res.status).toBe(302);
    expect(res.redirectCount).toBe(0);
    expect(fetch.calls).toHaveLength(1); // b.com was never dialed
  });
});

describe("deliverBody — inline truncation + file mode (SPEC §11)", () => {
  it("truncates inline at RESPONSE_INLINE_MAX_BYTES", () => {
    const big = new Uint8Array(RESPONSE_INLINE_MAX_BYTES + 10).fill(65);
    const d = deliverBody(big, "inline", { fs: inMemoryFs(), downloadPath: "/x" });
    expect(d.mode).toBe("inline");
    if (d.mode === "inline") {
      expect(d.truncated).toBe(true);
      expect(d.text.length).toBe(RESPONSE_INLINE_MAX_BYTES);
    }
  });

  it("does not truncate a small inline body", () => {
    const d = deliverBody(new TextEncoder().encode("hi"), "inline", {
      fs: inMemoryFs(),
      downloadPath: "/x",
    });
    if (d.mode === "inline") expect(d.truncated).toBe(false);
  });

  it("file mode writes the full body and returns the path", () => {
    const fs = inMemoryFs();
    const bytes = new Uint8Array(RESPONSE_INLINE_MAX_BYTES + 100).fill(66);
    const d = deliverBody(bytes, "file", { fs, downloadPath: "/data/downloads/r1" });
    expect(d.mode).toBe("file");
    if (d.mode === "file") {
      expect(d.path).toBe("/data/downloads/r1");
      expect((fs.files.get("/data/downloads/r1") as Uint8Array).length).toBe(bytes.length);
    }
  });
});
