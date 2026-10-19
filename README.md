# payfetch

[![smithery badge](https://smithery.ai/badge/forum-labs/payfetch)](https://smithery.ai/servers/forum-labs/payfetch)

payfetch lets an AI agent fetch a URL and, when the server answers HTTP 402 (the
x402 payment protocol), pay for it automatically, but only within a spending policy
you control. It is non-custodial: you bring your own wallet, the key stays on your
machine, and no MCP tool can raise the limits. It ships as a local stdio MCP server
with a small library and CLI alongside it.

The reference x402 clients pay whatever a 402 asks for. payfetch is the opposite:
the policy and safety surface is the point. Per-call, per-day, and per-host spend
caps; host allow and deny lists; a human-approval threshold; optional pre-payment
trust and safety checks; and an append-only local receipt for every attempt,
whether it paid, was denied, was a dry run, or failed.

- Website: https://forum-labs.com
- Source: https://github.com/forum-labs/payfetch

## Status and scope

- Version 1.0.0. Policy schema `p3f.policy.v1`, client schema `p3f-1.0.0`.
- x402 only, Base USDC, the `exact` scheme. Solana-settled x402, the `upto` scheme,
  and MPP are parsed and then refused with a reason recorded in your receipts.
- Requires Node 22 or newer. Windows is not supported.
- USD is treated as USDC at 1.00. Budgets are denominated in USD and settle in USDC,
  so a depeg makes the caps wrong by the depeg factor.

## Install

The package ships compiled JavaScript, so there is no build step and no `tsx` for
consumers. Run it on demand with `npx`:

```bash
# Operator CLI (status, verify, clear-autodeny, report):
npx @forum-labs/payfetch status

# MCP server (what an MCP client launches):
npx -p @forum-labs/payfetch payfetch-mcp
```

The package exposes two binaries: `payfetch` (the operator CLI) and `payfetch-mcp`
(the stdio MCP server). Because there are two, the server is launched with
`npx -p @forum-labs/payfetch payfetch-mcp`; the `-p` flag selects the named binary.

## Quickstart

### 1. Configure a wallet (pick exactly one signer)

payfetch refuses to start if zero or more than one signer source is set. It never
guesses which wallet to spend from.

Raw private key, the simplest option. Use a dedicated low-balance wallet:

```bash
export PAYFETCH_PRIVATE_KEY=0xabc...
```

Key file, which must be mode 600 (payfetch refuses to start otherwise):

```bash
printf '0xabc...' > ~/.payfetch-wallet.key && chmod 600 ~/.payfetch-wallet.key
export PAYFETCH_KEY_FILE=~/.payfetch-wallet.key
```

Coinbase CDP server wallet, where the keys are managed by CDP under your account
instead of being pasted into an environment variable:

```bash
export PAYFETCH_CDP_API_KEY_ID=...
export PAYFETCH_CDP_API_KEY_SECRET=...
export PAYFETCH_CDP_WALLET_SECRET=...
export PAYFETCH_CDP_ACCOUNT_NAME=payfetch   # optional; stable name across restarts
```

### 2. Wire it into an MCP client

Claude Desktop, in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "payfetch": {
      "command": "npx",
      "args": ["-y", "-p", "@forum-labs/payfetch", "payfetch-mcp"],
      "env": {
        "PAYFETCH_PRIVATE_KEY": "0xabc...",
        "PAYFETCH_TEST_MODE": "1"
      }
    }
  }
}
```

Claude Code:

```bash
claude mcp add payfetch \
  --env PAYFETCH_PRIVATE_KEY=0xabc... \
  --env PAYFETCH_TEST_MODE=1 \
  -- npx -y -p @forum-labs/payfetch payfetch-mcp
```

The examples set `PAYFETCH_TEST_MODE=1` so your first runs settle on Base Sepolia
and never touch mainnet. Drop it when you are ready to spend real USDC.

### 3. First paid fetch

Quote before you pay. `payment_quote` returns the terms, the selected quote, the
trust-check result, your remaining budgets, and the policy decision (`would_pay` or
`would_deny`). It signs nothing and reserves nothing:

```json
{ "url": "https://api.example.com/paid-endpoint" }
```

Dry run the whole pipeline. `paid_fetch` with `"dryRun": true` runs the exact code
path a real payment takes, up to but not including the signature.

Pay for real with `paid_fetch`:

```json
{ "url": "https://api.example.com/paid-endpoint", "maxAmountUsd": 0.25 }
```

`maxAmountUsd` tightens the per-call cap for this one call. It can only lower the
limit, never raise it. If the price is above your approval threshold, approval is
required first (see Approvals). The result carries the response body, the payment
outcome and transaction reference, any warnings, and a `receiptId`.

## The spending policy

Policy lives in `{dataDir}/config.json` (the data dir defaults to `~/.payfetch`).
On first run payfetch writes the defaults there so you can read and edit exactly
what you are running. A missing file falls back to the defaults. An invalid file
fails closed: every paying tool returns `policy_config_invalid` until you fix it, so
a typo never silently restores a cap you lowered. The file is re-read when its mtime
changes.

Only you can change the policy. No MCP tool mutates it and no tool clears an
auto-deny. Agent-supplied parameters such as `maxAmountUsd` can only tighten, never
loosen. Every denied `paid_fetch` result repeats this back to the agent so a
prompt-injected model cannot mistake the boundary for something negotiable.

### Caps

- `caps.perCallUsd` (default 1.00): maximum for a single payment.
- `caps.dailyUsd` (default 2.00): maximum per UTC day.
- `caps.perHostDailyUsd` (default 1.00): maximum per host per UTC day.
- `caps.totalUsd` (default null): optional lifetime cap.

Caps are hard and reserve before paying. A signed authorization is held against the
budget until it provably expires, so budgets can over-count but never under-count.
At most one payment attempt happens per request, so a retry loop cannot drain the
wallet.

There is deliberately no default lifetime cap. The dedicated wallet's balance
already bounds lifetime spend on-chain (see Security), so a software lifetime ceiling
would be one more field to forget. Set `totalUsd` only if you want a software
ceiling on top of a larger-balance wallet.

### Allow and deny lists

`mode` is `open` by default. Set it to `allowlist` to pay only hosts listed in
`allow`. Patterns in `deny` are always refused and win over `allow`. A pattern like
`*.example.com` matches subdomains, not the apex.

### Approvals

A payment whose price is strictly above `approval.thresholdUsd` (default 0.10)
triggers approval. An approval authorizes one payment only. There is no "always
allow", and it never widens future authority.

- `elicit` (default): the client prompts a human with the host, resource, amount,
  network and asset, guard results, and today's remaining budgets. They approve once
  or deny. The prompt times out after 120 seconds and is then treated as a denial.
  Some MCP clients cannot service an elicitation prompt: as of Claude Code v2.1.198
  and current Claude Desktop, neither does (Claude Code does not advertise the
  elicitation capability; Claude Desktop advertises it but cancels the prompt
  immediately). When a client adds elicitation support, the prompt works with no
  payfetch change. payfetch tells apart a real human "deny"
  from a client that simply cannot ask, and it never treats "cannot ask" as a silent
  denial. When a payment is blocked only because the client cannot elicit, the tool
  result says so and names the ways to allow it.
- `queue`: the payment is not executed. The result returns an `approvalId`. A human
  with approval authority resolves it with the `approve_pending` tool. An approved
  entry is a grant to re-run: the follow-up `paid_fetch` runs the full pipeline again
  and matches on host and exact amount. It expires after one hour, and drifted terms
  require a fresh approval.
- `deny`: anything above the threshold is refused, for unattended fleets.

For clients that cannot prompt a human, two config-only settings let above-threshold
payments through without a dialog. Both are explicit operator authorization, not the
agent's, and neither is reachable from a tool. `approval.preApprovedUpToUsd` (default
null) auto-approves above-threshold payments up to a ceiling.
`approval.preApprovedHosts` (default empty) auto-approves specific hosts. Both still
pass through every cap and every guard.

Approval never bypasses caps. An approved payment that fails budget reservation is
still denied.

`approve_pending` with `{"action":"list"}` is always allowed and shows the queue.
Approving or denying an entry requires `PAYFETCH_APPROVER=1` in the server's
environment; without it the tool returns `approver_not_enabled`. An agent must not
approve its own payments, so the server refuses to start if `PAYFETCH_APPROVER=1` is
combined with a queue-capable approval mode.

### Receipts

Every outcome, including free fetches, dry runs, denials, and unknown-settlement
cases, appends one immutable JSON line to the ledger:

```
{dataDir}/ledger/{yyyy-mm}.jsonl   # append-only, monthly rotation, fsync on payments
{dataDir}/state.json               # disposable cache, rebuildable from the ledger
{dataDir}/downloads/{receiptId}    # response bodies when responseMode is "file"
```

A receipt records the URL, method, and host; the outcome and deny code; the pipeline
steps traversed; the selected quote and a tally of rejected quotes; guard results;
approval info; the payment (payer address, nonce, validBefore, settled amount,
transaction reference, and whether it confirmed); the budgets at decision time; and
an HTTP summary. Key material, signatures, full payment payloads, response bodies,
and request header values are never stored. Response bodies are recorded as a
SHA-256 hash plus a byte count. URL query strings are stored, because this is your
own audit trail on your own disk; guard calls, by contrast, strip the query (see
Security). Nothing is rewritten. Corrections append `p3f.adjust.v1` records.

Query receipts with the `list_receipts` tool (filter by time, host, or outcome) or
`spend_status` (today's totals, holds, and recent payments). After repeated
paid-but-bad outcomes a host is auto-denied for 7 days; clear it out of band with
`payfetch clear-autodeny <host>`, never from a tool.

## Trust and safety checks

payfetch can consult two checks before it pays. Both call paid Forum Labs APIs at
`https://api.forum-labs.com`, and both are self-dealing that is disclosed here rather
than buried: the guards call our own products. The default guard budget is 0, so by
default the client uses only those products' free tier. Any paid guard usage is
opt-in, budgeted with `guards.*.dailyBudgetUsd > 0`, and produces a receipt like any
other spend.

The trust check is on by default in advisory mode. Before paying, it asks whether the
target endpoint has a reliable history. In advisory mode it warns; in enforce mode it
blocks on the configured verdicts (`unreliable` by default). New endpoints without
enough history come back `unrated` and pass by default, so the check does not
strangle them. This check is the client's only outbound call to us; see Security for
exactly what it sends and how to turn it off.

The safety check is off by default. When enabled it screens a token mint you pass in
(`tokenAddress`) against the Forum Labs token safety API and blocks on a `danger`
verdict, or on a `serial_rugger` deployer verdict in `deep` mode. `deep` is always a
paid screen, so it needs `dailyBudgetUsd > 0`.

## Security and disclosure

Read this before pointing payfetch at a funded wallet.

### The wallet balance is your real limit

The primary control on how much a bug or a prompt-injected agent can spend is the
balance of the wallet you point payfetch at, not the software caps. A wallet's
balance is a hard on-chain bound: payfetch cannot spend a dollar that is not in the
wallet, whatever the config says or the agent is told to do. So the first thing to
get right is the wallet.

Create a fresh wallet, fund it with only the amount you are willing to lose entirely
(a few dollars for a trial, a capped top-up for production), and give payfetch that
wallet. Never your main wallet. Refill it deliberately rather than by standing order.

The caps, lists, approval threshold, and guards are the fine-grained layer on top.
They shape rate, per-target exposure, and detection within that balance. They are
real and enforced, but the wallet balance is the circuit breaker and the caps are
the scalpel. Set both.

### Key custody

Your key is never transmitted to us, never logged, and never written to the receipt
ledger. The ledger stores addresses and amounts, not keys, and that is asserted by a
test. Keys are read from the environment in-process to sign EIP-3009 payment
authorizations. A signed authorization is bounded to one asset, one amount, one
recipient, and one time window. If you use `PAYFETCH_KEY_FILE`, payfetch refuses to
start when the file is group- or world-readable, so `chmod 600` it.

### What the trust guard sends, and the off switch

While the trust guard is on, it makes one call to the Forum Labs trust API on every
paid fetch. That call is the client's only egress to us. It sends the target endpoint
with the query string stripped, plus a random per-install id. The query is stripped
because a target URL's query can carry your own secrets; server-side we store a hash
of the input, never the raw target, and the install id is used for aggregate counting
only, never per-install profiling or resale. The install id is a random 32-hex value
generated on first run and stored in your state file; delete the state file and it
regenerates.

Turn the guard off with `guards.trust.enabled: false`. With it off, payfetch makes no
external call at all: no guard result, no network request, nothing dialed. That is
the complete off switch, and the honest cost of it is that operators who disable the
guard are invisible to our adoption instrument.

### Optional outcome reporting (off by default)

Reporting is off by default and changes nothing unless you turn it on. When you report
an outcome, currently only per-incident with `payfetch report <receiptId>`, the client
reports the outcome of a completed payment attempt (paid and delivered, or paid and
not delivered), signed by your payment wallet and tied to the on-chain settlement, to
the trust API. This is a fact about the seller's conduct that you are reporting. It is
never a record of what you looked at. Lookups (guard checks, quotes, dry runs) are
never retained per consumer.

A report sends exactly these fields and nothing else: the endpoint `{method, url}`
with the query stripped; the `outcome`, derived from the receipt and never
agent-supplied; structural `checks` (`settlementConfirmed`, a coarse HTTP status
class, `contentTypeOk`, `nonEmpty`); the `termsHash` you paid under; the seller's
`payTo` address, which is already on-chain; a coarse `amountBand` rather than the
exact amount; the UTC day rather than an exact timestamp; and your payment wallet
address plus an EIP-712 signature over the payload. A report never carries the query
string, request headers or bodies, the response body, the receiptId, the exact
amount, or the exact timestamp. The install id never rides on the report path, so the
report wallet and the guard install id are never joined.

A settled x402 payment is already public (payer, payee, amount, and time are on the
chain). What a report adds is the outcome bit. On very-low-traffic endpoints a seller
may be able to infer that a report came from you, since the anonymity set is small; we
mitigate with day granularity and bucketed publication, and we state the residual here
rather than hide it. In this version the trust API verifies the signature
(`recover(sig) === payer`), so a stranger cannot report on your behalf, but it does
not yet prove the settlement, so reports are shown as unverified until they are
settlement-matched in a later version. We will not monetize, publish, or attempt to
deanonymize reporter wallets.

### SSRF and private targets

Unless you set `allowPrivateTargets: true`, payfetch refuses non-http(s) schemes and
any host that resolves to loopback, RFC1918, link-local `169.254/16`, CGNAT, or ULA.
A paying-fetch must not become the tool that exfiltrates `169.254.169.254`. DNS is
pinned, so the vetted IP is the one dialed; every redirect hop is re-checked; and an
`https` to `http` downgrade aborts.

### What payfetch does not protect against

Fetched content is untrusted input to your agent. A malicious page can tell the agent
to fetch or pay somewhere else. payfetch bounds the damage with the dedicated wallet's
balance and the caps, lists, approval threshold, receipts, and SSRF block, but it
cannot make the agent wise. It cannot stop an injected agent from spending within
policy, so keep the wallet balance small. For untrusted-content workloads, tighten the
defaults:

```jsonc
{
  "mode": "allowlist",
  "allow": ["api.trusted-vendor.com"],
  "caps": { "perCallUsd": 0.05, "dailyUsd": 0.50, "perHostDailyUsd": 0.25 },
  "approval": { "thresholdUsd": 0.0, "mode": "elicit", "elicitFallback": "deny" },
  "guards": { "trust": { "enabled": true, "mode": "enforce" } }
}
```

`thresholdUsd: 0.0` sends every payment to a human. `mode: "enforce"` blocks on an
`unreliable` verdict instead of only warning.

Two more limits worth stating plainly. There is no on-chain settlement verification
yet: settlement facts come from the server's payment-response header, so a lying
server can misreport. Both error directions over-count, which is the safe direction,
and on-chain verification is planned. And the ledger is single-instance: one lockfile,
one process, one machine. A fleet needs a policy plane that is not built here.

## Configuration reference

Defaults, from `{dataDir}/config.json`, schema `p3f.policy.v1`:

| Field | Default | Meaning |
|---|---|---|
| `mode` | `"open"` | `"allowlist"` pays only hosts in `allow`. |
| `allow` | `[]` | Host patterns permitted in allowlist mode. |
| `deny` | `[]` | Host patterns always refused (wins over `allow`). |
| `caps.perCallUsd` | `1.00` | Max per single payment. |
| `caps.dailyUsd` | `2.00` | Max per UTC day. |
| `caps.perHostDailyUsd` | `1.00` | Max per host per UTC day. |
| `caps.totalUsd` | `null` | Optional lifetime cap. |
| `approval.thresholdUsd` | `0.10` | Above this, approval is required. |
| `approval.mode` | `"elicit"` | `elicit`, `queue`, or `deny`. |
| `approval.elicitFallback` | `"deny"` | Used when the client cannot elicit. Fail-closed. |
| `approval.preApprovedUpToUsd` | `null` | No-dialog ceiling for above-threshold payments. |
| `approval.preApprovedHosts` | `[]` | Hosts pre-approved to auto-pay above threshold. |
| `guards.trust.enabled` | `true` | The default-on trust check. |
| `guards.trust.mode` | `"advisory"` | `advisory` warns; `enforce` blocks. |
| `guards.trust.minScore` | `null` | Minimum acceptable TrustScore; below it the guard blocks or warns. `null` uses verdict-based blocking only, and it is ignored when the API returns a null score. |
| `guards.trust.blockVerdicts` | `["unreliable"]` | Verdicts that block or warn. |
| `guards.trust.blockUnrated` | `false` | `unrated` passes by default. |
| `guards.trust.onUnavailable` | `"block"` | Enforce-mode behavior when the guard cannot answer. |
| `guards.trust.dailyBudgetUsd` | `0` | 0 means free tier only. |
| `guards.safety.enabled` | `false` | Token safety screen; needs `tokenAddress`. |
| `guards.safety.mode` | `"enforce"` | `advisory` warns; `enforce` blocks. Applies only when the safety guard is enabled. |
| `guards.safety.depth` | `"basic"` | `deep` is always paid. |
| `guards.safety.blockVerdicts` | `["danger"]` | Token verdicts that block. |
| `guards.safety.blockDeployerVerdicts` | `["serial_rugger"]` | Deployer verdicts, deep only. |
| `guards.safety.onUnavailable` | `"block"` | Enforce behavior when the safety guard is dead. |
| `guards.safety.onDegraded` | `"block"` | Enforce behavior on a degraded screen. |
| `allowPrivateTargets` | `false` | SSRF guard. Keep `false`. |
| `autoDeny.enabled` | `true` | Per-host circuit breaker. |

Environment variables read by both the server and the CLI:

| Variable | Meaning |
|---|---|
| `PAYFETCH_PRIVATE_KEY` | 0x-hex EVM private key. One of three signer sources. |
| `PAYFETCH_KEY_FILE` | Path to a mode-600 file holding a 0x-hex key. |
| `PAYFETCH_CDP_API_KEY_ID` / `_SECRET`, `PAYFETCH_CDP_WALLET_SECRET` | Coinbase CDP server-wallet credentials (all three required together). |
| `PAYFETCH_CDP_ACCOUNT_NAME` | Optional named CDP EVM account. Defaults to a stable name. |
| `PAYFETCH_DATA_DIR` | Ledger, state, and config root. Default `~/.payfetch`. |
| `PAYFETCH_TEST_MODE` | Any value marks receipts `test:true` and refuses Base mainnet quotes (Sepolia only). |
| `PAYFETCH_APPROVER` | `1` grants approval authority. Refused with a queue-capable mode. |
| `PAYFETCH_VIA` | Optional `via=` attribution slug sent on guard calls only. |

## Test mode

Set `PAYFETCH_TEST_MODE` to any value. Then every receipt is stamped `test: true` and
excluded from metrics, and Base mainnet quotes are refused so a self-test can never
touch mainnet spend. Only Base Sepolia settles. Use it to run the end-to-end Base
Sepolia path before spending real USDC.

## CLI

The `payfetch` CLI reads the same environment as the MCP server.

```bash
# Reset a host's auto-deny circuit breaker (an operator action, not a tool).
npx @forum-labs/payfetch clear-autodeny api.example.com

# Print today's spend status as JSON.
npx @forum-labs/payfetch status

# Verify the ledger tamper-evidence sidecar (exits non-zero on any integrity gap).
npx @forum-labs/payfetch verify

# Report a paid outcome for a receipt (opt-in, off by default). Prints the exact
# wallet-signed payload, asks for confirmation, then submits. Never an MCP tool, so
# the agent can neither file nor suppress a report. Use --yes to skip the prompt.
npx @forum-labs/payfetch report <receiptId>
```

`status` builds the engine and takes the single-writer lock. If the MCP server is
already running, use the `spend_status` tool instead, or stop the server first.

## Manual .mcpb install

Directory submission is not offered for payment connectors, so payfetch is packaged
for manual install. Build the bundle:

```bash
npm run build:mcpb        # produces dist-mcpb/payfetch.mcpb
```

This runs `tsc`, then esbuild-bundles the built server entry and its runtime
dependencies into a single self-contained ESM file, and packs it with the mcpb tool.
The result is a small `.mcpb` zip holding `manifest.json` alongside the bundled
server. No `node_modules` is shipped, so Claude Desktop installs it without running
`npm install`. In Claude Desktop, go to Settings, Extensions, Install from file,
choose the `.mcpb`, then fill in exactly one signer option. The bundling logic is in
`mcpb/build.mjs` and the manifest is `mcpb/manifest.json`.

## From source

```bash
npm install         # dev dependencies, including tsx for the from-source flow
npm run typecheck   # tsc --noEmit
npm test            # vitest, hermetic, no network
npm run build       # emit dist/, the compiled JS the package ships
npm run test:packaged-entry
```

`npm test` imports the TypeScript source. `test:packaged-entry` builds and packs
this checkout, installs that tarball and the published package in isolated
directories, and imports each public entry (`dist/src/index.js`). The packed
client must send `X-PAYMENT` for an x402 v1 payload and `PAYMENT-SIGNATURE` for
v2. Its process injects transport, DNS, filesystem, and a synthetic signer, and
blocks its own DNS, sockets, and fetch. Installing the two artifacts uses the
npm registry. A passing local pack is not a release.

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 Forum Labs.
