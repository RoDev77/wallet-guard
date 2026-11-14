// Wallet Guard — a read-only wallet-security screening agent.
//
// Plain node:http server, zero npm dependencies, Node 22.
// It NEVER signs, sends, or holds keys. It only reads public chain state
// (eth_call / eth_getCode) and applies deterministic rules to transaction
// payloads it is shown. Every failure is closed: when chain state cannot be
// read, the address screen answers 503 instead of inventing a verdict.

import { createServer } from 'node:http';

// ---------------------------------------------------------------------------
// Configuration / watchlist (data, easy to extend)
// ---------------------------------------------------------------------------

const PORT = process.env.PORT || 8080;
const CHAIN_ID = 56; // BNB Smart Chain — the only chain this build serves.

const RPC_ENDPOINTS = [
  'https://rpc.48.club',
  'https://bsc-dataseed.binance.org',
  'https://bsc-dataseed1.defibit.io',
];
const RPC_TIMEOUT_MS = 12000;
const USER_AGENT = 'Mozilla/5.0 (WalletGuard/1.0; +read-only-screening-agent)';

const MAX_BODY_BYTES = 64 * 1024;

// Well-known spenders. The PancakeSwap router is also the transaction
// screen's known-router allowlist: an unlimited approval TO it is still
// flagged HIGH, but it is not auto-BLOCKed the way an unknown spender is.
const PANCAKE_ROUTER = '0x10ED43C718714eb63d5aA57B78B54704E256024E';
const KNOWN_ROUTERS = [PANCAKE_ROUTER];

// ERC20 allowance watchlist: token -> spenders checked via allowance().
// Addresses are public, well-known BSC contracts.
const ERC20_WATCHLIST = [
  {
    token: '0x55d398326f99059fF775485246999027B3197955',
    tokenName: 'USDT (BSC)',
    spenders: [
      { address: PANCAKE_ROUTER, name: 'PancakeSwap Router V2' },
      { address: '0x3643A907f875fA9B740e1C0747E91b5aA5222aB8', name: 'Jager mint contract' },
    ],
  },
];

// NFT setApprovalForAll watchlist: collection -> marketplace operators
// checked via isApprovedForAll(). These are the marketplace contracts of the
// production wallet-guard registry this agent is productised from, listed
// generically as known marketplace spenders.
const NFT_WATCHLIST = [
  { contract: '0x51D87A14B0c0736608e71AEfe8c571faE5Cf19ca', contractName: 'Agentic Pixels (AGPX)', spender: '0x1789d6a78EfaB3DE17885843289A8c16647ced71', spenderName: 'Agentic Pixels Market' },
  { contract: '0x2ED9E0a6992BA22B48c2fc2def6bB2365301A0D0', contractName: 'Worldygg Tree', spender: '0xB81324e14319712De43E560111452b73834cd72A', spenderName: 'Worldygg Market' },
  { contract: '0xdEAa9aaec224c7429dA2501b159aaf8D79019Ba3', contractName: 'Flaggies', spender: '0x31b80FA97185625F5B95cCC3F5244F030c396Ee1', spenderName: 'Flaggies Market' },
  { contract: '0xea404392Be487B90F45b8436a52623BC7dBd8515', contractName: 'DogePunk', spender: '0xe40659260eC44744bF587Dd6380118Aafd51633e', spenderName: 'DogePunkMarket v2' },
  { contract: '0x828e7073Ef57Ed778E4acF82cC45BC43eF760b54', contractName: 'HashOre', spender: '0x8f111fdbeD012DdBF18175E5Afa58A1D579c4916', spenderName: 'HashOre Market' },
  { contract: '0x439643cfd023c247519518B7F73d06823E1F2fCe', contractName: 'AgentsEstates (AGENTS)', spender: '0x1EeA3629C7505Dcf8c8d247558F6E244D19C60dE', spenderName: 'AgentsEstates Market' },
  { contract: '0x6C90D2302bF0a9DaaF453f3Af2CD79f3C9B79CF8', contractName: 'Emberforge', spender: '0x4b9B8fd6361A9E1BaA0705fa77252F14dC54C10A', spenderName: 'Emberforge Native Market' },
  { contract: '0x4EF929aF00cB93993c3D01834C4DA79200d31e32', contractName: 'Pokechain', spender: '0x3399E3AC0D6aA973a00D47Ff52072906841ee1a7', spenderName: 'Pokechain Market (escrow)' },
];

// Contracts the transaction screen recognises as known destinations
// (routers + every contract/spender named above).
const KNOWN_CONTRACTS = new Set(
  [
    ...KNOWN_ROUTERS,
    ...ERC20_WATCHLIST.flatMap((t) => [t.token, ...t.spenders.map((s) => s.address)]),
    ...NFT_WATCHLIST.flatMap((n) => [n.contract, n.spender]),
  ].map((a) => a.toLowerCase()),
);

// Function selectors the transaction screen understands.
const SELECTORS = {
  approve: '0x095ea7b3',
  transfer: '0xa9059cbb',
  transferFrom: '0x23b872dd',
  setApprovalForAll: '0xa22cb465',
  increaseAllowance: '0x39509351',
};
const KNOWN_SELECTORS = new Set(Object.values(SELECTORS));

const MAX_UINT256 = (1n << 256n) - 1n;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const isAddress = (a) => typeof a === 'string' && ADDRESS_RE.test(a);
const lc = (a) => (typeof a === 'string' ? a.toLowerCase() : '');
const padAddress = (a) => '000000000000000000000000' + a.slice(2).toLowerCase();
const wordToAddress = (word) => '0x' + word.slice(-40).toLowerCase();

function parseValueWei(v) {
  if (v === undefined || v === null) return 0n;
  try {
    if (typeof v === 'number') return BigInt(Math.trunc(v));
    if (typeof v === 'string') {
      const s = v.trim();
      if (s === '') return 0n;
      return BigInt(s); // handles decimal and 0x-prefixed hex
    }
  } catch {
    return null; // unparseable
  }
  return null;
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
  });
  res.end(body);
}

// ---------------------------------------------------------------------------
// Minimal JSON-RPC client with endpoint rotation (fail-closed)
// ---------------------------------------------------------------------------

let rpcId = 0;

async function rpcCall(method, params) {
  let lastError = null;
  for (const url of RPC_ENDPOINTS) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), RPC_TIMEOUT_MS);
    try {
      const resp = await fetch(url, {
        method: 'POST',
        signal: controller.signal,
        headers: { 'content-type': 'application/json', 'user-agent': USER_AGENT },
        body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      if (data.error) throw new Error(`RPC error ${data.error.code ?? ''}: ${data.error.message ?? 'unknown'}`);
      return data.result;
    } catch (err) {
      lastError = err;
    } finally {
      clearTimeout(timer);
    }
  }
  throw lastError ?? new Error('all RPC endpoints failed');
}

const ethCall = (to, data) => rpcCall('eth_call', [{ to, data }, 'latest']);
const ethGetCode = (address) => rpcCall('eth_getCode', [address, 'latest']);

// Returns true/false, or null when the call itself could not be completed
// on ANY endpoint (caller decides how to treat unknowns — fail closed).
async function callIsApprovedForAll(contract, owner, spender) {
  const data = '0xe985e9c5' + padAddress(owner) + padAddress(spender);
  const result = await ethCall(contract, data);
  return BigInt(result) === 1n;
}

async function callAllowance(token, owner, spender) {
  const data = '0xdd62ed3e' + padAddress(owner) + padAddress(spender);
  const result = await ethCall(token, data);
  return BigInt(result);
}

async function hasCode(address) {
  const code = await ethGetCode(address);
  return typeof code === 'string' && code !== '0x' && code !== '0x0';
}

// ---------------------------------------------------------------------------
// GET /screen/address — live watchlist approval audit
// ---------------------------------------------------------------------------

async function screenAddress(res, url) {
  const chainRaw = url.searchParams.get('chain');
  const address = url.searchParams.get('address');

  if (chainRaw !== null && chainRaw !== String(CHAIN_ID)) {
    return sendJson(res, 400, { error: `unsupported chain "${chainRaw}": this build serves chain ${CHAIN_ID} (BSC) only` });
  }
  if (!isAddress(address ?? '')) {
    return sendJson(res, 400, { error: 'invalid or missing "address": expected a 0x-prefixed 20-byte hex address' });
  }

  const live = [];
  let checked = 0;
  try {
    // ERC20 allowances.
    for (const entry of ERC20_WATCHLIST) {
      for (const spender of entry.spenders) {
        const amount = await callAllowance(entry.token, address, spender.address);
        checked += 1;
        if (amount > 0n) {
          live.push({
            contract: entry.token,
            spender: spender.address,
            type: 'erc20-allowance',
            detail: `${entry.tokenName}: allowance of ${amount.toString()} base units granted to ${spender.name}`,
          });
        }
      }
    }
    // NFT operator approvals.
    for (const entry of NFT_WATCHLIST) {
      const approved = await callIsApprovedForAll(entry.contract, address, entry.spender);
      checked += 1;
      if (approved) {
        live.push({
          contract: entry.contract,
          spender: entry.spender,
          type: 'erc721-setApprovalForAll',
          detail: `${entry.contractName}: operator approval (ALL tokens of the collection) is live for ${entry.spenderName}`,
        });
      }
    }
  } catch (err) {
    // Fail closed: never report CLEAN when the chain could not be read.
    return sendJson(res, 503, {
      error: 'approval audit could not be completed: all BSC RPC endpoints failed',
      detail: String(err?.message ?? err),
      verdict: null,
    });
  }

  return sendJson(res, 200, {
    address,
    chain: CHAIN_ID,
    checked_at: new Date().toISOString(),
    live_approvals: live,
    summary: { pairs_checked: checked, live_found: live.length },
    verdict: live.length > 0 ? 'REVIEW' : 'CLEAN',
    notes: [
      'Watchlist audit only: it checks the (contract, spender) pairs built into this agent, not every approval the address has ever granted.',
      'A CLEAN verdict means no live approval was found among the watched pairs — it is not a guarantee that no other approval exists.',
      'Computed live from BSC state via eth_call at checked_at; re-running the same calls reproduces the same result.',
    ],
  });
}

// ---------------------------------------------------------------------------
// POST /screen/transaction — deterministic pre-signing risk screen
// ---------------------------------------------------------------------------

function screenTransaction(body) {
  const flags = [];
  const flag = (rule, severity, detail) => flags.push({ rule, severity, detail });

  const chain = body.chain ?? CHAIN_ID;
  const from = body.from;
  const to = body.to;
  const inputData = typeof body.inputData === 'string' && body.inputData !== '' ? body.inputData : '0x';
  const value = parseValueWei(body.value);

  if (chain !== CHAIN_ID && String(chain) !== String(CHAIN_ID)) {
    flag('unsupported-chain', 'MEDIUM', `chain ${chain} is not served by this build (BSC ${CHAIN_ID} only); verdict is advisory only`);
  }
  if (!isAddress(to ?? '')) {
    return { verdict: 'REVIEW', flags: [{ rule: 'invalid-destination', severity: 'HIGH', detail: '"to" is missing or is not a valid address; the transaction cannot be screened properly' }], explanation: 'Destination address missing or malformed — a human should review before signing.' };
  }
  if (value === null) {
    flag('unparseable-value', 'MEDIUM', '"value" could not be parsed as an integer amount of wei');
  }
  const wei = value ?? 0n;
  const data = inputData.toLowerCase();
  const hasCalldata = data !== '0x' && data.length >= 10;
  const selector = hasCalldata ? data.slice(0, 10) : null;
  const argsHex = hasCalldata ? data.slice(10) : '';
  const word = (i) => argsHex.slice(i * 64, i * 64 + 64).padEnd(64, '0');

  let blockReason = null;

  // --- Calldata rules -------------------------------------------------------
  if (selector === SELECTORS.approve || selector === SELECTORS.increaseAllowance) {
    const spender = wordToAddress(word(0));
    const amount = argsHex.length >= 128 ? BigInt('0x' + word(1)) : 0n;
    const isRouter = KNOWN_ROUTERS.map(lc).includes(lc(spender));
    if (amount === MAX_UINT256) {
      flag('unlimited-approval', 'HIGH', `${selector === SELECTORS.approve ? 'approve' : 'increaseAllowance'} grants spender ${spender} an UNLIMITED allowance (max uint256) over the token at ${to}`);
      if (!isRouter) blockReason = `unlimited token approval to non-allowlisted spender ${spender}`;
    } else if (amount >= (1n << 200n)) {
      flag('very-large-approval', 'MEDIUM', `approval amount for spender ${spender} is extremely large (${amount.toString()} base units) though not the max-uint256 pattern`);
    } else {
      flag('token-approval', 'LOW', `approval of ${amount.toString()} base units to spender ${spender}; approvals outlive their purpose — revoke when done`);
    }
  }

  if (selector === SELECTORS.setApprovalForAll) {
    const operator = wordToAddress(word(0));
    const approved = argsHex.length >= 128 ? BigInt('0x' + word(1)) !== 0n : false;
    if (approved) {
      flag('operator-approval-all', 'HIGH', `setApprovalForAll grants operator ${operator} control over EVERY token of the collection at ${to}`);
      if (!KNOWN_ROUTERS.map(lc).includes(lc(operator))) {
        blockReason = `setApprovalForAll(true) to non-allowlisted operator ${operator}`;
      }
    } else {
      flag('operator-approval-revoke', 'INFO', `setApprovalForAll(false) for operator ${operator} — this REMOVES an operator approval`);
    }
  }

  if (selector === SELECTORS.transferFrom) {
    const recipient = wordToAddress(word(1));
    flag('transfer-from-third-party', 'MEDIUM', `transferFrom moves tokens from ${wordToAddress(word(0))} to third-party recipient ${recipient}, which is not the transaction destination (${to} is the token contract) — verify the recipient before signing`);
  }

  if (selector === SELECTORS.transfer) {
    const recipient = wordToAddress(word(0));
    if (isAddress(from ?? '') && lc(recipient) === lc(from)) {
      flag('self-transfer', 'INFO', `transfer recipient ${recipient} is the sender itself`);
    } else {
      flag('token-transfer', 'LOW', `plain token transfer to recipient ${recipient} via token contract ${to}`);
    }
  }

  if (hasCalldata && selector && !KNOWN_SELECTORS.has(selector)) {
    flag('unknown-selector', 'LOW', `function selector ${selector} is not one this screen recognises; the call's effect was not analysed beyond this`);
  }

  return { flags, blockReason, wei, hasCalldata };
}

async function handleScreenTransaction(req, res) {
  let raw;
  try {
    raw = await readBody(req, MAX_BODY_BYTES);
  } catch (err) {
    return sendJson(res, err.code === 'TOO_LARGE' ? 413 : 400, { error: err.message });
  }
  let body;
  try {
    body = JSON.parse(raw || '{}');
  } catch {
    return sendJson(res, 400, { error: 'request body is not valid JSON' });
  }
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return sendJson(res, 400, { error: 'request body must be a JSON object { chain, from, to, value, inputData }' });
  }

  const { flags, blockReason, wei, hasCalldata } = screenTransaction(body);
  const to = body.to;

  // --- Destination rules (need live chain state) ----------------------------
  let codeKnown = false;
  let contract = false;
  try {
    contract = await hasCode(to);
    codeKnown = true;
  } catch {
    flags.push({ rule: 'destination-unverified-rpc', severity: 'MEDIUM', detail: 'the destination could not be checked on-chain (all RPC endpoints failed), so contract/EOA status is unknown' });
  }
  if (codeKnown) {
    if (wei > 0n && contract && !KNOWN_CONTRACTS.has(lc(to))) {
      flags.push({ rule: 'unverified-destination', severity: 'MEDIUM', detail: `value of ${wei.toString()} wei goes to contract ${to}, which is not in this screen's known-contract set and cannot be verified` });
    }
    if (wei > 0n && contract && !hasCalldata) {
      flags.push({ rule: 'value-to-contract-empty-calldata', severity: 'MEDIUM', detail: `value of ${wei.toString()} wei is sent to contract ${to} with empty calldata; many contracts reject or strand such transfers` });
    }
  }

  let verdict;
  if (blockReason) verdict = 'BLOCK';
  else if (flags.some((f) => f.severity !== 'INFO')) verdict = 'REVIEW';
  else verdict = 'ALLOW';

  const explanation =
    verdict === 'BLOCK'
      ? `Blocked by a high-risk approval pattern: ${blockReason}. This pattern hands a third party standing control over funds; sign only if you fully intend that, to that exact spender.`
      : verdict === 'REVIEW'
        ? 'One or more risk flags fired (see flags). A human should review each flag before signing; the screen does not clear this transaction.'
        : 'No risk rules fired. This is an advisory screen, not a guarantee of safety.';

  return sendJson(res, 200, { verdict, flags, explanation });
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

function readBody(req, cap) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > cap) {
        const err = new Error(`request body exceeds ${cap} bytes`);
        err.code = 'TOO_LARGE';
        reject(err);
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', () => {
      const err = new Error('failed to read request body');
      err.code = 'READ_ERROR';
      reject(err);
    });
  });
}

const AGENT_CARD = {
  name: 'Wallet Guard',
  track: 'Wildcard — Agent Games Season 01',
  description:
    'A read-only wallet-security screening agent for BNB Smart Chain. It audits an address for live token/NFT approvals against a watchlist of well-known spenders, and screens unsigned transactions with deterministic risk rules before a wallet is asked to sign them.',
  owner: 'ahmadrodi.ai',
  version: '1.0.0',
  chains: [CHAIN_ID],
  endpoints: [
    { method: 'GET', path: '/', description: 'This agent card.' },
    { method: 'GET', path: '/health', description: 'Liveness check.' },
    { method: 'GET', path: '/screen/address?chain=56&address=0x...', description: 'Live watchlist approval audit of an address (eth_call, read-only).' },
    { method: 'POST', path: '/screen/transaction', description: 'Deterministic pre-signing risk screen of { chain, from, to, value, inputData }.' },
  ],
  safety: {
    read_only: true,
    holds_keys: false,
    signs_transactions: false,
    sends_transactions: false,
    fail_closed: 'If chain state cannot be read, the address screen returns 503 instead of a verdict.',
  },
};

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const path = url.pathname;

    if (path === '/') {
      if (req.method !== 'GET') return sendJson(res, 405, { error: 'method not allowed: use GET' });
      return sendJson(res, 200, AGENT_CARD);
    }
    if (path === '/health') {
      if (req.method !== 'GET') return sendJson(res, 405, { error: 'method not allowed: use GET' });
      return sendJson(res, 200, { ok: true, time: new Date().toISOString(), chains: [CHAIN_ID] });
    }
    if (path === '/screen/address') {
      if (req.method !== 'GET') return sendJson(res, 405, { error: 'method not allowed: use GET' });
      return await screenAddress(res, url);
    }
    if (path === '/screen/transaction') {
      if (req.method !== 'POST') return sendJson(res, 405, { error: 'method not allowed: use POST' });
      return await handleScreenTransaction(req, res);
    }
    return sendJson(res, 404, { error: `unknown route: ${req.method} ${path}` });
  } catch {
    // Never leak stack traces.
    return sendJson(res, 500, { error: 'internal error' });
  }
});

server.listen(PORT, () => {
  console.log(`Wallet Guard listening on port ${PORT} (chain ${CHAIN_ID}, read-only)`);
});
