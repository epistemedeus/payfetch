/**
 * Package-boundary regression for the public payfetch entry.
 *
 * Builds this checkout, packs it, and installs that tarball plus the published
 * `@forum-labs/payfetch` release into separate directories outside this repo.
 * Each run imports only that install's public entry (`exports["."]`). Source
 * tests already cover the header fix; this command checks the built artifact.
 *
 * The test process injects a scripted transport, a resolver, an in-memory
 * filesystem, and a synthetic signer. DNS, sockets, fetch, and writes under
 * the sentinel directory fail closed. Registry access happens only while
 * installing the artifacts. Output keeps header names, decoded x402Version,
 * decisions, and counts. It does not print header values or signatures.
 *
 * Wire names checked here are the ones `x402HTTPClient.encodePaymentSignatureHeader`
 * uses: v1 `X-PAYMENT`, v2 `PAYMENT-SIGNATURE`. This file does not import or
 * reimplement that client. The standalone encoder only base64-encodes a value.
 */

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import fs from "node:fs";
import fsp from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import dns from "node:dns";
import { lookup as esmLookup } from "node:dns/promises";
import { syncBuiltinESMExports } from "node:module";
import net from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import tls from "node:tls";
import { fileURLToPath, pathToFileURL } from "node:url";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const REPO = path.resolve(path.dirname(SCRIPT_PATH), "..");
const MODE = process.argv[2];
const STAGING = MODE === "--runtime" || MODE === "--classification-self-test" ? null : mkdtempSync(path.join(tmpdir(), "payfetch-packaged-entry-"));
const SPECIFIER = "@forum-labs/payfetch";
const ENTRY_TARGET = "dist/src/index.js";
const V1_HEADER = "x-payment";
const V2_HEADER = "payment-signature";
const URL1 = "https://api.example.com/data";
const NOW = Date.UTC(2023, 10, 14, 12, 0, 0);
const SIG_MARK = "1".repeat(20);
const RESOLVE_IP = "203.0.113.10";
const HEAP_FLAG = "--max-old-space-size=1024";

const hits = { dns: 0, connect: 0, fetch: 0, fs: 0 };

if (MODE === "--runtime") await runRuntime();
else if (MODE === "--classification-self-test") await classificationSelfTest();
else await runOrchestrator();

function resetHits() {
  hits.dns = 0;
  hits.connect = 0;
  hits.fetch = 0;
  hits.fs = 0;
}

function blocked(kind) {
  function failClosed() {
    hits[kind] += 1;
    const err = new Error("payfetch_packaged_entry_network_blocked");
    err.code = "PAYFETCH_NETWORK_BLOCKED";
    throw err;
  }
  failClosed.payfetchBlocked = true;
  return failClosed;
}

function sanitize(value) {
  return String(value ?? "")
    .replace(/0x[0-9a-fA-F]{8,}/g, "0x[redacted]")
    .replace(/[A-Za-z0-9+/]{40,}={0,2}/g, "[redacted]")
    .replace(/1{16,}/g, "[redacted]")
    .slice(0, 400);
}

function parseJsonText(text) {
  const start = String(text).search(/[[{]/);
  if (start < 0) throw new Error("command output had no JSON");
  return JSON.parse(String(text).slice(start));
}

function engineWarningLines(stderr) {
  const text = String(stderr);
  if (!text.includes("EBADENGINE")) return [];
  const pkg = text.match(/package: '([^']+)'/)?.[1] ?? "unknown";
  const required = text.match(/required: \{ node: '([^']+)'/)?.[1] ?? "unknown";
  const current = text.match(/current: \{ node: '([^']+)'/)?.[1] ?? "unknown";
  return [`EBADENGINE ${pkg} requires node ${required}; current ${current}`];
}

function run(command, args, { cwd = REPO, env = process.env } = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const keep = (prev, chunk) => {
      const next = prev + chunk.toString();
      return next.length > 200_000 ? next.slice(-200_000) : next;
    };
    child.stdout.on("data", (chunk) => {
      stdout = keep(stdout, chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr = keep(stderr, chunk);
    });
    child.on("error", (err) => {
      resolve({ command: [command, ...args].join(" "), cwd, exit: 127, stdout, stderr: `${stderr}\n${err.message}` });
    });
    child.on("close", (code) => {
      resolve({ command: [command, ...args].join(" "), cwd, exit: code ?? 1, stdout, stderr });
    });
  });
}

function commandRecord(result) {
  const record = {
    command: result.command,
    cwd: result.cwd,
    exit: result.exit,
    engineWarnings: engineWarningLines(result.stderr),
  };
  if (result.exit !== 0) record.stderrTail = sanitize(result.stderr).slice(-500);
  return record;
}

function sha256File(file) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function inside(root, file) {
  const realRoot = realpathSync(root);
  const realFile = realpathSync(file);
  return realFile === realRoot || realFile.startsWith(realRoot + path.sep);
}

function readJson(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

function installedPackageJson(consumerRoot, packageRoot, name) {
  const candidates = [
    path.join(consumerRoot, "node_modules", name, "package.json"),
    path.join(packageRoot, "node_modules", name, "package.json"),
  ];
  return candidates.find((file) => existsSync(file)) ?? null;
}

function exportTarget(exp) {
  if (typeof exp === "string") return exp;
  if (!exp || typeof exp !== "object") return null;
  const branch = exp.import ?? exp.default ?? exp.require;
  if (typeof branch === "string") return branch;
  if (branch && typeof branch === "object") {
    if (typeof branch.default === "string") return branch.default;
    if (typeof branch.import === "string") return branch.import;
  }
  if (typeof exp.default === "string") return exp.default;
  return null;
}

function resolveInstalled(consumerRoot, packageRoot, spec) {
  const slash = spec.startsWith("@") ? spec.indexOf("/", spec.indexOf("/") + 1) : spec.indexOf("/");
  const name = slash === -1 ? spec : spec.slice(0, slash);
  const sub = slash === -1 ? "." : `.${spec.slice(slash)}`;
  const pkgJson = installedPackageJson(consumerRoot, packageRoot, name);
  if (!pkgJson) throw new Error(`missing installed dependency ${name}`);
  const pkg = readJson(pkgJson);
  const target = exportTarget(pkg.exports?.[sub] ?? (sub === "." ? pkg.module ?? pkg.main : null));
  if (!target) throw new Error(`missing export ${sub} from ${name}`);
  const file = path.resolve(path.dirname(pkgJson), target);
  if (!existsSync(file)) throw new Error(`export file missing for ${spec}: ${file}`);
  if (!inside(consumerRoot, file)) throw new Error(`dependency ${spec} resolved outside the consumer`);
  if (inside(REPO, file)) throw new Error(`dependency ${spec} resolved inside the source repo`);
  return realpathSync(file);
}

function resolvePublicEntry(packageRoot) {
  const pkg = readJson(path.join(packageRoot, "package.json"));
  const target = exportTarget(pkg.exports?.["."]) ?? pkg.main;
  if (target !== `./${ENTRY_TARGET}` && target !== ENTRY_TARGET) {
    throw new Error(`public entry target is ${target}, expected ${ENTRY_TARGET}`);
  }
  const file = path.resolve(packageRoot, target);
  if (!existsSync(file)) throw new Error(`public entry file missing: ${file}`);
  if (!inside(packageRoot, file)) throw new Error("public entry escaped the installed package");
  if (inside(REPO, file)) throw new Error("public entry resolved inside the source repo");
  return { version: pkg.version, dependencies: pkg.dependencies ?? {}, file: realpathSync(file), target };
}

function dependencyReport(consumerRoot, packageRoot, declared) {
  const resolved = {};
  const mismatches = [];
  for (const [name, pinned] of Object.entries(declared)) {
    const pkgJson = installedPackageJson(consumerRoot, packageRoot, name);
    if (!pkgJson) {
      mismatches.push(`${name} missing`);
      continue;
    }
    const version = readJson(pkgJson).version;
    resolved[name] = version;
    if (version !== pinned) mismatches.push(`${name} resolved ${version}, pinned ${pinned}`);
  }
  return { resolved, mismatches };
}

function memoryFs() {
  const files = new Map();
  const mtimes = new Map();
  let seq = 1;
  const touch = (file) => mtimes.set(file, seq++);
  const asText = (value) => {
    if (value === undefined) return null;
    return typeof value === "string" ? value : new TextDecoder().decode(value);
  };
  return {
    ensureDir() {},
    readText(file) {
      return asText(files.get(file));
    },
    writeText(file, data) {
      files.set(file, data);
      touch(file);
    },
    writeBytes(file, data) {
      files.set(file, Uint8Array.from(data));
      touch(file);
    },
    appendLine(file, line) {
      const prev = asText(files.get(file)) ?? "";
      files.set(file, prev + (line.endsWith("\n") ? line : `${line}\n`));
      touch(file);
    },
    statMtimeMs(file) {
      return mtimes.get(file) ?? null;
    },
    listDir(dir) {
      const prefix = dir.endsWith("/") ? dir : `${dir}/`;
      const names = new Set();
      for (const key of files.keys()) {
        if (key.startsWith(prefix)) names.add(key.slice(prefix.length).split("/")[0]);
      }
      return [...names];
    },
    tryCreateExclusive(file, contents) {
      if (files.has(file)) return false;
      files.set(file, contents);
      touch(file);
      return true;
    },
    remove(file) {
      files.delete(file);
      mtimes.delete(file);
    },
  };
}

function syntheticSigner() {
  const signer = {
    kind: "local_key",
    signCount: 0,
    async address() {
      return "0x00000000000000000000000000000000000000a1";
    },
    async signTypedData() {
      signer.signCount += 1;
      return `0x${"1".repeat(130)}`;
    },
  };
  return signer;
}

function scriptedFetch(routes, decode) {
  const cursors = new Map();
  const calls = [];
  const fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const method = (init?.method ?? "GET").toUpperCase();
    const headers = new Headers(init?.headers ?? {});
    const names = [];
    const paymentHeaderNames = [];
    let decodedX402Version = null;
    let callerReservedPresent = false;
    let customKept = false;
    headers.forEach((value, key) => {
      names.push(key);
      if (key === "x-custom" && value === "keep") customKept = true;
      if (key !== V1_HEADER && key !== V2_HEADER) return;
      paymentHeaderNames.push(key);
      if (value === "caller-reserved") callerReservedPresent = true;
      const version = decodeVersion(value, decode);
      if (version !== null) decodedX402Version = version;
    });
    calls.push({
      headerNames: names.sort(),
      paymentHeaderNames: paymentHeaderNames.sort(),
      decodedX402Version,
      callerReservedPresent,
      customKept,
    });
    const key = `${method} ${url}`;
    const sequence = routes.get(key);
    if (!sequence) throw new Error(`scripted fetch has no route for ${method} ${url}`);
    const index = cursors.get(key) ?? 0;
    cursors.set(key, index + 1);
    return sequence[Math.min(index, sequence.length - 1)]();
  };
  return { fetch, calls };
}

function decodeVersion(value, decode) {
  try {
    const parsed = JSON.parse(decode(value));
    return parsed && typeof parsed.x402Version === "number" ? parsed.x402Version : null;
  } catch {
    return null;
  }
}

function b64(encode, value) {
  return encode(JSON.stringify(value));
}

function responseOf(encode, spec) {
  const headers = new Headers();
  if (spec.challenge) headers.set("PAYMENT-REQUIRED", b64(encode, spec.challenge));
  if (spec.settlement) headers.set("PAYMENT-RESPONSE", b64(encode, spec.settlement));
  let body = null;
  if (spec.json !== undefined) {
    body = JSON.stringify(spec.json);
    headers.set("content-type", "application/json");
  }
  return () => new Response(body, { status: spec.status, headers });
}

function v1Challenge() {
  return {
    x402Version: 1,
    error: "X-PAYMENT header is required",
    accepts: [
      {
        scheme: "exact",
        network: "base",
        maxAmountRequired: "10000",
        resource: URL1,
        description: "Example paid resource",
        mimeType: "application/json",
        payTo: "0x000000000000000000000000000000000000bEEF",
        maxTimeoutSeconds: 60,
        asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        extra: { name: "USD Coin", version: "2" },
      },
    ],
  };
}

function v2Challenge() {
  return {
    x402Version: 2,
    error: "payment required",
    resource: { url: "https://api.example.com/v1/hello" },
    accepts: [
      {
        scheme: "exact",
        network: "eip155:84532",
        amount: "1000",
        asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        payTo: "0xffa3e5fa7AE5F0DD1fd196Cbd41d40325E4Aa831",
        maxTimeoutSeconds: 60,
        extra: { name: "USDC", version: "2" },
      },
    ],
  };
}

function settlement() {
  return { success: true, transaction: "0xtx" };
}

function safeNotes(notes) {
  if (!Array.isArray(notes)) return [];
  return notes.filter((note) => typeof note === "string" && /^[a-z0-9_:-]+$/i.test(note));
}

function summarize(receipt, signer, calls) {
  return {
    outcome: receipt?.outcome ?? null,
    denyCode: receipt?.denyCode ?? null,
    quoteX402Version: typeof receipt?.quote?.x402Version === "number" ? receipt.quote.x402Version : null,
    rejectedQuotes: receipt?.rejectedQuotes && typeof receipt.rejectedQuotes === "object" ? receipt.rejectedQuotes : null,
    notes: safeNotes(receipt?.notes),
    signCount: signer.signCount,
    callCount: calls.length,
    calls,
  };
}

async function runCase(mod, encode, decode, sentinel, spec) {
  const routes = new Map([[`GET ${URL1}`, spec.responses.map((item) => responseOf(encode, item))]]);
  const transport = scriptedFetch(routes, decode);
  const signer = syntheticSigner();
  let randomCount = 0;
  const client = mod.createPayfetch({
    deps: {
      fetch: transport.fetch,
      signer,
      now: () => NOW,
      random: () => {
        randomCount += 1;
        return Uint8Array.from({ length: 32 }, (_, i) => (randomCount + i) & 0xff);
      },
      dataDir: path.join(sentinel, "data"),
      log() {},
      elicit: null,
    },
    fs: memoryFs(),
    httpClient: mod.adaptFetch(transport.fetch),
    resolve: async () => [RESOLVE_IP],
    delay: async () => {},
    testMode: spec.testMode,
    guards: [],
  });
  try {
    const result = await client.fetch(URL1, spec.init, spec.opts);
    return summarize(result.receipt, signer, transport.calls);
  } finally {
    client.close();
  }
}

function casePlan() {
  const paid = { status: 200, settlement: settlement(), json: { ok: true } };
  return [
    {
      id: "v1_pay",
      testMode: false,
      responses: [{ status: 402, json: v1Challenge() }, paid],
    },
    {
      id: "v2_pay",
      testMode: true,
      responses: [{ status: 402, challenge: v2Challenge() }, paid],
    },
    {
      id: "unsupported_version",
      testMode: false,
      responses: [{ status: 402, json: { ...v1Challenge(), x402Version: 3 } }],
    },
    {
      id: "reserved_headers",
      testMode: true,
      init: { headers: { "X-PAYMENT": "caller-reserved", "PAYMENT-SIGNATURE": "caller-reserved", "X-Custom": "keep" } },
      responses: [{ status: 402, challenge: v2Challenge() }, paid],
    },
    {
      id: "dry_run",
      testMode: false,
      opts: { dryRun: true },
      responses: [{ status: 402, json: v1Challenge() }],
    },
  ];
}

function installFailClosed(sentinel) {
  const names = ["lookup", "resolve", "resolve4", "resolve6", "resolveAny", "resolveCname", "resolveMx", "resolveNs", "resolvePtr", "resolveSoa", "resolveSrv", "resolveTxt", "reverse"];
  for (const name of names) {
    if (typeof dns[name] === "function") dns[name] = blocked("dns");
    if (typeof dns.promises?.[name] === "function") dns.promises[name] = blocked("dns");
    if (typeof dns.Resolver?.prototype?.[name] === "function") dns.Resolver.prototype[name] = blocked("dns");
  }
  syncBuiltinESMExports();
  net.Socket.prototype.connect = blocked("connect");
  tls.connect = blocked("connect");
  http.request = blocked("connect");
  http.get = blocked("connect");
  https.request = blocked("connect");
  https.get = blocked("connect");
  globalThis.fetch = async () => blocked("fetch")();

  const under = (file) => {
    const abs = path.resolve(String(file));
    return abs === sentinel || abs.startsWith(sentinel + path.sep);
  };
  const wrap = (original) =>
    function sealed(file, ...args) {
      if (under(file)) {
        hits.fs += 1;
        const err = new Error("payfetch_packaged_entry_fs_blocked");
        err.code = "PAYFETCH_FS_BLOCKED";
        throw err;
      }
      return original.call(this, file, ...args);
    };
  fs.mkdirSync = wrap(fs.mkdirSync);
  fs.writeFileSync = wrap(fs.writeFileSync);
  fs.appendFileSync = wrap(fs.appendFileSync);
  fs.openSync = wrap(fs.openSync);
  fs.renameSync = wrap(fs.renameSync);
  fs.rmSync = wrap(fs.rmSync);
  fsp.mkdir = wrap(fsp.mkdir);
  fsp.writeFile = wrap(fsp.writeFile);
  syncBuiltinESMExports();
}

async function probeFailClosed(consumerRoot, packageRoot, sentinel) {
  const probe = {};
  const dnsMod = await import("node:dns/promises");
  if (!esmLookup.payfetchBlocked || !dnsMod.lookup.payfetchBlocked) probe.dns = "patch_missed";
  else {
    try {
      await dnsMod.lookup("example.com");
      probe.dns = "reached";
    } catch (err) {
      probe.dns = err.code || "threw";
    }
  }
  try {
    net.connect({ port: 9, host: RESOLVE_IP });
    probe.connect = "reached";
  } catch (err) {
    probe.connect = err.code || "threw";
  }
  try {
    await globalThis.fetch(`http://${RESOLVE_IP}/`);
    probe.fetch = "reached";
  } catch (err) {
    probe.fetch = err.code || "threw";
  }
  try {
    const fsMod = await import("node:fs");
    fsMod.mkdirSync(sentinel);
    probe.fs = "reached";
  } catch (err) {
    probe.fs = err.code || "threw";
  }
  try {
    const undici = await import(pathToFileURL(resolveInstalled(consumerRoot, packageRoot, "undici")).href);
    const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error("undici_probe_timeout")), 2000));
    await Promise.race([undici.request(`http://${RESOLVE_IP}/`, { method: "GET" }), timeout]);
    probe.undici = "reached";
  } catch (err) {
    probe.undici = err.code || (String(err.message).includes("payfetch_packaged_entry_network_blocked") ? "PAYFETCH_NETWORK_BLOCKED" : sanitize(err.message));
  }
  return probe;
}

async function runRuntime() {
  const packageRoot = process.env.PAYFETCH_PACKAGED_ENTRY_PACKAGE_ROOT;
  const consumerRoot = process.env.PAYFETCH_PACKAGED_ENTRY_CONSUMER_ROOT;
  const resultFile = process.env.PAYFETCH_PACKAGED_ENTRY_RESULT;
  const sentinel = process.env.PAYFETCH_PACKAGED_ENTRY_SENTINEL;
  const result = {
    label: process.env.PAYFETCH_PACKAGED_ENTRY_LABEL ?? null,
    specifier: SPECIFIER,
    error: null,
    confined: false,
    cases: {},
  };
  try {
    if (!packageRoot || !consumerRoot || !resultFile || !sentinel) throw new Error("runtime env is incomplete");
    installFailClosed(sentinel);
    result.probe = await probeFailClosed(consumerRoot, packageRoot, sentinel);
    resetHits();
    const entry = resolvePublicEntry(packageRoot);
    const utilsFile = resolveInstalled(consumerRoot, packageRoot, "@x402/core/utils");
    const publicProbe = await import(pathToFileURL(path.join(consumerRoot, "entry-probe.mjs")).href);
    const actualEntry = realpathSync(fileURLToPath(publicProbe.resolvedEntry));
    if (actualEntry !== entry.file) throw new Error("Node bare import resolved a different public entry");
    const mod = publicProbe.entry;
    result.resolution = "node-esm-bare-specifier";
    const utils = await import(pathToFileURL(utilsFile).href);
    result.importHits = { ...hits };
    resetHits();
    result.importPath = pathToFileURL(entry.file).href;
    result.exportTarget = entry.target;
    result.packageVersion = entry.version;
    result.declaredDependencies = entry.dependencies;
    const deps = dependencyReport(consumerRoot, packageRoot, entry.dependencies);
    result.resolvedDependencies = deps.resolved;
    result.dependencyMismatches = deps.mismatches;
    result.exportsPresent = {
      createPayfetch: typeof mod.createPayfetch === "function",
      adaptFetch: typeof mod.adaptFetch === "function",
    };
    result.confined = !inside(REPO, entry.file) && inside(consumerRoot, entry.file) && inside(packageRoot, entry.file);
    if (!result.exportsPresent.createPayfetch || !result.exportsPresent.adaptFetch) {
      throw new Error("public entry is missing createPayfetch or adaptFetch");
    }
    if (!result.confined) throw new Error("public entry was not confined to the installed package");
    if (deps.mismatches.length > 0) throw new Error(`pinned dependency mismatch: ${deps.mismatches.join("; ")}`);
    if (typeof utils.safeBase64Encode !== "function" || typeof utils.safeBase64Decode !== "function") {
      throw new Error("installed @x402/core/utils is missing safeBase64Encode or safeBase64Decode");
    }
    for (const spec of casePlan()) {
      try {
        result.cases[spec.id] = await runCase(mod, utils.safeBase64Encode, utils.safeBase64Decode, sentinel, spec);
      } catch (err) {
        result.cases[spec.id] = { error: sanitize(err.message) };
      }
    }
    result.caseHits = { ...hits };
    result.sentinelExists = existsSync(sentinel);
  } catch (err) {
    result.error = sanitize(err.message);
    result.caseHits = { ...hits };
    result.sentinelExists = sentinel ? existsSync(sentinel) : null;
  }
  const text = JSON.stringify(result);
  if (text.includes(SIG_MARK)) {
    result.error = result.error ?? "result contained synthetic signature material";
    writeFileSync(resultFile, JSON.stringify({ ...result, cases: {} }));
    process.exitCode = 1;
    return;
  }
  writeFileSync(resultFile, JSON.stringify(result));
  process.exitCode = result.error ? 1 : 0;
}

function namesOf(summary, index) {
  return summary?.calls?.[index]?.paymentHeaderNames ?? null;
}

function versionOf(summary, index) {
  return summary?.calls?.[index]?.decodedX402Version ?? null;
}

function wireOk(summary, header, version) {
  const names = namesOf(summary, 1);
  return (
    summary?.error == null &&
    summary?.outcome === "paid_delivered" &&
    summary?.signCount === 1 &&
    summary?.callCount === 2 &&
    summary?.quoteX402Version === version &&
    Array.isArray(names) &&
    names.length === 1 &&
    names[0] === header &&
    versionOf(summary, 1) === version &&
    (summary.calls[0]?.paymentHeaderNames?.length ?? 1) === 0
  );
}

function evaluateCandidate(runtime) {
  const failures = [];
  const v1 = runtime.cases?.v1_pay;
  const v2 = runtime.cases?.v2_pay;
  const unsupported = runtime.cases?.unsupported_version;
  const reserved = runtime.cases?.reserved_headers;
  const dry = runtime.cases?.dry_run;
  if (runtime.error) failures.push(`runtime ${runtime.error}`);
  if (!runtime.confined) failures.push("import was not confined to the packed install");
  if (runtime.probe?.dns !== "PAYFETCH_NETWORK_BLOCKED") failures.push(`dns probe ${runtime.probe?.dns}`);
  if (runtime.probe?.connect !== "PAYFETCH_NETWORK_BLOCKED") failures.push(`connect probe ${runtime.probe?.connect}`);
  if (runtime.probe?.fetch !== "PAYFETCH_NETWORK_BLOCKED") failures.push(`fetch probe ${runtime.probe?.fetch}`);
  if (runtime.probe?.fs !== "PAYFETCH_FS_BLOCKED") failures.push(`fs probe ${runtime.probe?.fs}`);
  if (runtime.probe?.undici !== "PAYFETCH_NETWORK_BLOCKED") failures.push(`undici probe ${runtime.probe?.undici}`);
  const importHits = runtime.importHits ?? {};
  const caseHits = runtime.caseHits ?? {};
  for (const [label, bag] of [["import", importHits], ["cases", caseHits]]) {
    for (const key of ["dns", "connect", "fetch", "fs"]) {
      if ((bag[key] ?? 0) !== 0) failures.push(`${label} ${key} hits ${bag[key]}`);
    }
  }
  if (runtime.sentinelExists) failures.push("real filesystem sentinel was created");
  if (!wireOk(v1, V1_HEADER, 1)) failures.push("candidate v1 wire failed");
  if (!wireOk(v2, V2_HEADER, 2)) failures.push("candidate v2 wire failed");
  if (
    unsupported?.outcome !== "policy_denied" ||
    unsupported?.denyCode !== "unsupported_terms" ||
    unsupported?.rejectedQuotes?.unsupported_x402_version !== 1 ||
    unsupported?.signCount !== 0 ||
    unsupported?.callCount !== 1 ||
    (unsupported?.calls?.[0]?.paymentHeaderNames?.length ?? 1) !== 0
  ) {
    failures.push("candidate unsupported-version control failed");
  }
  if (
    reserved?.outcome !== "paid_delivered" ||
    reserved?.signCount !== 1 ||
    reserved?.callCount !== 2 ||
    reserved?.calls?.[0]?.customKept !== true ||
    (reserved?.calls?.[0]?.paymentHeaderNames?.length ?? 1) !== 0 ||
    reserved?.calls?.[1]?.callerReservedPresent !== false ||
    namesOf(reserved, 1)?.join(",") !== V2_HEADER ||
    versionOf(reserved, 1) !== 2
  ) {
    failures.push("candidate reserved-header control failed");
  }
  if (
    dry?.outcome !== "dry_run" ||
    dry?.signCount !== 0 ||
    dry?.callCount !== 1 ||
    dry?.quoteX402Version !== 1 ||
    (dry?.calls?.[0]?.paymentHeaderNames?.length ?? 1) !== 0
  ) {
    failures.push("candidate dry-run control failed");
  }
  return { pass: failures.length === 0, failures };
}

function evaluateReleased(runtime) {
  const failures = [];
  if (runtime.error) failures.push(`runtime ${runtime.error}`);
  if (!runtime.confined) failures.push("released import was not confined");
  const caseHits = runtime.caseHits ?? {};
  for (const key of ["dns", "connect", "fetch", "fs"]) {
    if ((caseHits[key] ?? 0) !== 0) failures.push(`released case ${key} hits ${caseHits[key]}`);
  }
  if (runtime.sentinelExists) failures.push("released run wrote the real filesystem sentinel");
  const v1Pass = wireOk(runtime.cases?.v1_pay, V1_HEADER, 1);
  if (!v1Pass) failures.push("released v1 did not complete on the shared public entry");
  const v2Pass = wireOk(runtime.cases?.v2_pay, V2_HEADER, 2);
  const v2LegacyPass = wireOk(runtime.cases?.v2_pay, V1_HEADER, 2);
  if (!v2Pass && !v2LegacyPass) failures.push("released v2 comparison is inconclusive");
  return { pass: failures.length === 0, failures, v1Pass, v2Pass, v2LegacyPass };
}

async function installConsumer(dir, spec, commands) {
  mkdirSync(dir, { recursive: false });
  writeFileSync(
    path.join(dir, "package.json"),
    `${JSON.stringify({ name: "payfetch-packaged-entry-consumer", private: true, version: "0.0.0" }, null, 2)}\n`,
  );
  const env = { ...process.env, NO_UPDATE_NOTIFIER: "1", npm_config_fund: "false", npm_config_audit: "false" };
  delete env.NO_COLOR;
  const installed = await run("npm", ["install", "--ignore-scripts", "--omit=dev", "--no-audit", "--no-fund", spec], { cwd: dir, env });
  if (installed.exit === 0) writeFileSync(path.join(dir, "entry-probe.mjs"), `import * as entry from "@forum-labs/payfetch";
export { entry };
export const resolvedEntry = import.meta.resolve("@forum-labs/payfetch");
`, { flag: "wx" });
  commands.push(commandRecord(installed));
  return installed.exit === 0;
}

async function spawnRuntime(label, consumerRoot, commands) {
  const packageRoot = path.join(consumerRoot, "node_modules", SPECIFIER);
  const resultFile = path.join(STAGING, `runtime-${label}.json`);
  const sentinel = path.join(consumerRoot, "real-fs-sentinel");
  const env = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    TMPDIR: process.env.TMPDIR || tmpdir(),
    LANG: process.env.LANG || "C",
    PAYFETCH_PACKAGED_ENTRY_LABEL: label,
    PAYFETCH_PACKAGED_ENTRY_PACKAGE_ROOT: packageRoot,
    PAYFETCH_PACKAGED_ENTRY_CONSUMER_ROOT: consumerRoot,
    PAYFETCH_PACKAGED_ENTRY_RESULT: resultFile,
    PAYFETCH_PACKAGED_ENTRY_SENTINEL: sentinel,
  };
  const child = await run(process.execPath, [HEAP_FLAG, SCRIPT_PATH, "--runtime"], { cwd: consumerRoot, env });
  commands.push(commandRecord(child));
  const runtime = existsSync(resultFile) ? readJson(resultFile) : { error: "runtime wrote no result", confined: false, cases: {} };
  runtime.exit = child.exit;
  return runtime;
}

async function runOrchestrator() {
  const commands = [];
  const output = {
    schema: "payfetch.packaged-public-entry.v1",
    ok: false,
    staging: STAGING,
    specifier: SPECIFIER,
    publicEntry: ENTRY_TARGET,
    commands: [],
    limits: [
      `node ${process.version}; test runtime ${HEAP_FLAG}`,
      "Dependency engine warnings, if any, are recorded with each install command.",
      "No coverage instrumentation. The hermetic source suite stays npm test.",
      "Synthetic signatures are not payment authority. Header values are not stored.",
      "A local pack is not an npm publish, maintainer release, or outside install.",
    ],
  };
  const finish = (ok) => {
    output.ok = ok;
    output.commands = commands;
    process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
    process.exitCode = ok ? 0 : 1;
  };
  try {
    if (STAGING === REPO || STAGING.startsWith(REPO + path.sep)) {
      throw new Error("staging directory must stay outside the source repo");
    }
    // STAGING was exclusively allocated for this run; prior evidence is retained.
    const head = await run("git", ["rev-parse", "HEAD"]);
    const status = await run("git", ["status", "--porcelain"]);
    commands.push(commandRecord(head), commandRecord(status));
    output.source = {
      commit: head.stdout.trim(),
      dirty: status.stdout.split("\n").map((line) => line.trim()).filter(Boolean),
    };

    const viewed = await run("npm", ["view", SPECIFIER, "--json"]);
    commands.push(commandRecord(viewed));
    if (viewed.exit !== 0) throw new Error("npm view of the published package failed");
    const meta = parseJsonText(viewed.stdout);
    const publishedVersion = meta["dist-tags"]?.latest ?? meta.version;
    output.registry = {
      name: meta.name,
      version: meta.version,
      latest: publishedVersion,
      gitHead: meta.gitHead ?? null,
      integrity: meta.dist?.integrity ?? null,
      tarball: meta.dist?.tarball ?? null,
      engines: meta.engines ?? null,
      dependencies: meta.dependencies ?? null,
    };

    const built = await run("npm", ["run", "build"]);
    commands.push(commandRecord(built));
    if (built.exit !== 0) throw new Error("build failed");
    const packed = await run("npm", ["pack", "--json", "--pack-destination", STAGING]);
    commands.push(commandRecord(packed));
    if (packed.exit !== 0) throw new Error("npm pack failed");
    const packMeta = parseJsonText(packed.stdout);
    const packRow = Array.isArray(packMeta) ? packMeta[0] : packMeta;
    const tarball = path.join(STAGING, packRow.filename);
    const listed = await run("tar", ["-tzf", tarball]);
    commands.push(commandRecord(listed));
    const files = listed.stdout.split("\n").map((line) => line.replace(/^package\//, "")).filter(Boolean);
    output.candidatePack = {
      filename: packRow.filename,
      integrity: packRow.integrity ?? null,
      shasum: packRow.shasum ?? null,
      sha256: sha256File(tarball),
      fileCount: files.length,
      hasPublicEntry: files.includes(ENTRY_TARGET),
      hasTypeScriptSource: files.some((file) => file.startsWith("src/") && file.endsWith(".ts")),
      hasNodeModules: files.some((file) => file.startsWith("node_modules/")),
    };
    if (!output.candidatePack.hasPublicEntry || output.candidatePack.hasTypeScriptSource || output.candidatePack.hasNodeModules) {
      throw new Error("pack contents did not match the public entry boundary");
    }

    const releasedDir = path.join(STAGING, "released");
    const candidateDir = path.join(STAGING, "candidate");
    const releasedInstalled = await installConsumer(releasedDir, `${SPECIFIER}@${publishedVersion}`, commands);
    const candidateInstalled = await installConsumer(candidateDir, tarball, commands);
    if (!releasedInstalled || !candidateInstalled) throw new Error("isolated install failed");

    output.released = await spawnRuntime("released", releasedDir, commands);
    output.candidate = await spawnRuntime("candidate", candidateDir, commands);
    const releasedEval = evaluateReleased(output.released);
    const candidateEval = evaluateCandidate(output.candidate);
    output.releasedEvaluation = {
      comparable: releasedEval.pass,
      failures: releasedEval.failures,
      v1Pass: releasedEval.v1Pass,
      v2Pass: releasedEval.v2Pass,
    };
    output.candidateEvaluation = { pass: candidateEval.pass, failures: candidateEval.failures };
    output.discrimination = {
      publishedDefectObserved: releasedEval.pass && releasedEval.v2LegacyPass,
      candidateV1Pass: wireOk(output.candidate.cases?.v1_pay, V1_HEADER, 1),
      candidateV2Pass: wireOk(output.candidate.cases?.v2_pay, V2_HEADER, 2),
      releasedV1Pass: releasedEval.v1Pass,
      releasedV2Pass: releasedEval.v2Pass,
      releasedV2LegacyHeader: releasedEval.v2LegacyPass,
      distinctImports:
        Boolean(output.released.importPath) &&
        Boolean(output.candidate.importPath) &&
        output.released.importPath !== output.candidate.importPath,
      contrast: !releasedEval.pass
        ? "released_comparison_incomplete"
        : releasedEval.v2Pass
          ? "published_artifact_already_emits_v2_header"
          : releasedEval.v2LegacyPass
            ? "released_v2_misses_payment_signature_candidate_required"
            : "released_comparison_incomplete",
    };
    const contrastHolds =
      candidateEval.pass &&
      releasedEval.pass &&
      output.discrimination.distinctImports &&
      (output.discrimination.contrast === "released_v2_misses_payment_signature_candidate_required" ||
        output.discrimination.contrast === "published_artifact_already_emits_v2_header");
    finish(contrastHolds);
  } catch (err) {
    output.error = sanitize(err.message);
    finish(false);
  }
}


async function classificationSelfTest() {
  const { default: assert } = await import("node:assert/strict");
  const wire = (header, version) => ({ outcome: "paid_delivered", signCount: 1, callCount: 2, quoteX402Version: version, calls: [{paymentHeaderNames: []}, {paymentHeaderNames: [header], decodedX402Version: version}] });
  const runtime = v2 => ({ confined: true, cases: {v1_pay: wire(V1_HEADER, 1), v2_pay: v2} });
  const legacy = evaluateReleased(runtime(wire(V1_HEADER, 2)));
  assert.equal(legacy.pass && legacy.v2LegacyPass && !legacy.v2Pass, true);
  const corrected = evaluateReleased(runtime(wire(V2_HEADER, 2)));
  assert.equal(corrected.pass && corrected.v2Pass && !corrected.v2LegacyPass, true);
  for (const v2 of [{error: "exception"}, {outcome: "policy_denied", signCount: 0}, undefined, wire(V1_HEADER, 1)]) {
    const result = evaluateReleased(runtime(v2));
    assert.equal(result.pass, false);
    assert.equal(result.v2LegacyPass, false);
  }
  process.stdout.write(JSON.stringify({ok: true, classificationCases: 6}) + "\n");
}
