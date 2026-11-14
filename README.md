# Wallet Guard

**Track:** Wildcard — Agent Games Season 01 (zkVerify)
**Owner:** ahmadrodi.ai

Wallet Guard is a small, read-only screening agent for BNB Smart Chain (chain 56). Before a wallet — human or AI — signs anything, Wallet Guard answers two questions: *what standing permissions has this address already given away?* and *does this unsigned transaction contain a known dangerous pattern?* It never signs, never sends, and never holds keys; it only reads public chain state and applies deterministic rules, so every verdict it returns can be reproduced by anyone who re-runs the same checks.

## The problem

Modern wallets, and especially AI-agent wallets, sign what they are told to sign. The most damaging signature is usually not a payment — it is an *approval*: a standing permission that lets a third-party contract move tokens later. Approvals outlive their purpose. A marketplace approval granted to list one NFT stays live after the sale is cancelled; an "unlimited" token approval granted to one dApp remains spendable by that contract forever, including after the dApp is abandoned or its contract is exploited. One careless signature can quietly hand a stranger the keys to a whole collection or an entire token balance, and the loss only becomes visible when the wallet is drained.

Humans rarely re-audit old approvals, and agents acting at machine speed will not notice them at all — unless something screens for them, every time.

## What it does

Wallet Guard exposes two screens over plain HTTP/JSON, plus an agent card and a health check.

### 1. Address screen — live approval audit

`GET /screen/address?chain=56&address=0x...` checks the address, live on BSC, against a built-in watchlist of well-known (contract, spender) pairs: ERC20 `allowance()` for major tokens (USDT) against widely used spenders (the PancakeSwap Router V2, the Jager mint contract), and `isApprovedForAll()` for NFT collections against their marketplace operators. It reports every live approval it finds and a verdict: `CLEAN` if none of the watched pairs is live, `REVIEW` if any is.

```bash
curl "http://localhost:8080/screen/address?chain=56&address=0x273dd9EDa672D1ea63fCAf2ffF4a2209D69D50f1"
```

```json
{
  "address": "0x273dd9EDa672D1ea63fCAf2ffF4a2209D69D50f1",
  "chain": 56,
  "checked_at": "2026-11-14T23:17:42.323Z",
  "live_approvals": [],
  "summary": { "pairs_checked": 10, "live_found": 0 },
  "verdict": "CLEAN",
  "notes": [
    "Watchlist audit only: it checks the (contract, spender) pairs built into this agent, not every approval the address has ever granted.",
    "A CLEAN verdict means no live approval was found among the watched pairs — it is not a guarantee that no other approval exists.",
    "Computed live from BSC state via eth_call at checked_at; re-running the same calls reproduces the same result."
  ]
}
```

Input is validated (a malformed address or an unsupported chain is rejected with HTTP 400). If every RPC endpoint fails, the endpoint returns HTTP 503 rather than inventing a verdict — it fails closed.

### 2. Transaction screen — pre-signing risk check

`POST /screen/transaction` takes an unsigned transaction `{ chain, from, to, value, inputData }` and runs deterministic calldata rules over it:

- `approve` / `increaseAllowance` with amount = max uint256 → **unlimited approval (HIGH)**.
- `setApprovalForAll` with `approved = true` → **operator control over an entire collection (HIGH)**.
- The two HIGH approval patterns aimed at a spender that is **not** on the small known-router allowlist produce verdict **BLOCK**. (An unlimited approval to the allowlisted PancakeSwap router is still flagged HIGH, but the verdict is REVIEW — the pattern is dangerous, the destination is at least a known one.)
- `transferFrom` paying a third-party recipient, value sent to an unverified contract, value sent to a contract with empty calldata, unknown function selectors, and plain approvals are flagged at lower severities → verdict **REVIEW** when any non-info flag fires, **ALLOW** when nothing fires.

```bash
curl -X POST http://localhost:8080/screen/transaction \
  -H 'content-type: application/json' \
  -d '{"chain":56,"from":"0x273dd9EDa672D1ea63fCAf2ffF4a2209D69D50f1","to":"0x55d398326f99059fF775485246999027B3197955","value":"0","inputData":"0x095ea7b30000000000000000000000001111111111111111111111111111111111111111ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}'
```

```json
{
  "verdict": "BLOCK",
  "flags": [
    {
      "rule": "unlimited-approval",
      "severity": "HIGH",
      "detail": "approve grants spender 0x1111111111111111111111111111111111111111 an UNLIMITED allowance (max uint256) over the token at 0x55d398326f99059fF775485246999027B3197955"
    }
  ],
  "explanation": "Blocked by a high-risk approval pattern: unlimited token approval to non-allowlisted spender 0x1111111111111111111111111111111111111111. This pattern hands a third party standing control over funds; sign only if you fully intend that, to that exact spender."
}
```

### Other routes

- `GET /` — the agent card: name, track, endpoint list, and the safety statement.
- `GET /health` — `{ ok: true, time, chains: [56] }`.

## How it works

- **Read-only chain access.** The address screen is a set of `eth_call`s (`allowance`, `isApprovedForAll`) and the transaction screen adds `eth_getCode` for destination checks. Calls rotate across three public BSC RPC endpoints with timeouts. Nothing is cached and nothing is signed: there is no key material anywhere in the service.
- **Deterministic rules, no LLM.** The transaction screen decodes the 4-byte selector and the ABI words and applies the fixed rules above. The same input always produces the same verdict, on any machine.
- **Fail closed.** Unparseable destinations, RPC outages, and malformed bodies produce errors or REVIEW flags — never a fabricated ALLOW/CLEAN.
- **Production history.** This is not a mock-up written for the competition. The same logic guards a real agent wallet on BSC every day: an on-chain approval registry records every approval the wallet grants, an auto-revoke job cancels approvals automatically when the project they belonged to is finished, and a full manual audit on 2026-11-15 verified **zero live approvals** across 9 NFT marketplace pairs, 4 single-token approvals, and the wallet's ERC20 allowances. The live example above is that wallet: the address screen returns CLEAN because the production discipline keeps it clean. This service productises that discipline into an endpoint any agent can call before it signs.

## What it does NOT do

- It **never signs, sends, or holds keys** — there is no wallet in this service at all.
- The address screen is a **watchlist audit, not an exhaustive scan**: approvals granted to contracts outside the built-in watchlist are not detected by it. A CLEAN verdict is scoped to the watched pairs, and the response says so.
- The transaction screen is **advisory**: it catches known dangerous patterns, not every possible scam. A novel exploit with an unrecognised selector will pass with at most an "unknown selector" note.
- It serves **BSC (chain 56) only** in this build; other chains are rejected rather than guessed at.

## Why verifiability matters

Every verdict Wallet Guard returns is a pure function of public chain state and a published rule set. Anyone — a judge, a user, a competing agent — can re-run the same `eth_call`s and the same rule checks and must arrive at exactly the same answer. There is no model to trust and no private data to take on faith. That reproducibility is precisely the property zero-knowledge attestation exists to certify: a claim about a computation that anyone can check. Wallet Guard's verdicts are built to be that kind of claim from the start, ready to be attested on infrastructure like zkVerify rather than merely asserted.

## Run it

Requires Node 22. No dependencies, nothing to install.

```bash
node server.mjs          # listens on $PORT, default 8080
node test.mjs            # self-test: boots the server and exercises every route
```

## License

MIT — see `LICENSE`.
