// Wallet Guard self-test.
// Boots server.mjs on an ephemeral port, exercises every route, and prints
// PASS/FAIL per case. Exit code 0 only when every case passes.
// Run: node test.mjs

import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const OWNER = '0x273dd9EDa672D1ea63fCAf2ffF4a2209D69D50f1'; // verified zero live approvals on 2026-11-15
const USDT = '0x55d398326f99059fF775485246999027B3197955';
const PANCAKE_ROUTER = '0x10ED43C718714eb63d5aA57B78B54704E256024E';
const NFT = '0x4EF929aF00cB93993c3D01834C4DA79200d31e32';

const pad = (a) => '000000000000000000000000' + a.slice(2).toLowerCase();
const word = (n) => n.toString(16).padStart(64, '0');
const MAX_UINT = 'f'.repeat(64);

function freePort() {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

async function req(base, path, { method = 'GET', body, rawBody, timeoutMs = 30000 } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(base + path, {
      method,
      signal: controller.signal,
      headers: body !== undefined || rawBody !== undefined ? { 'content-type': 'application/json' } : undefined,
      body: rawBody !== undefined ? rawBody : body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await resp.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* keep null */ }
    return { status: resp.status, json, text };
  } finally {
    clearTimeout(timer);
  }
}

const results = [];
function check(name, cond, detail = '') {
  results.push({ name, pass: !!cond, detail });
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
}

const port = await freePort();
const base = `http://127.0.0.1:${port}`;
const child = spawn(process.execPath, ['server.mjs'], {
  cwd: HERE,
  env: { ...process.env, PORT: String(port) },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let serverLog = '';
child.stdout.on('data', (d) => { serverLog += d; });
child.stderr.on('data', (d) => { serverLog += d; });

try {
  // Wait for the server to answer /health.
  let up = false;
  for (let i = 0; i < 50 && !up; i++) {
    try {
      const r = await req(base, '/health', { timeoutMs: 2000 });
      up = r.status === 200;
    } catch { /* not up yet */ }
    if (!up) await new Promise((r) => setTimeout(r, 200));
  }
  if (!up) throw new Error('server did not come up. Log:\n' + serverLog);

  // 1. Agent card.
  {
    const r = await req(base, '/');
    check('GET / returns the agent card', r.status === 200 && r.json?.name === 'Wallet Guard' && r.json?.safety?.holds_keys === false, `status=${r.status}`);
  }

  // 2. Health.
  {
    const r = await req(base, '/health');
    check('GET /health is ok', r.status === 200 && r.json?.ok === true && Array.isArray(r.json?.chains) && r.json.chains.includes(56), `status=${r.status}`);
  }

  // 3. Address screen rejects a malformed address.
  {
    const r = await req(base, '/screen/address?chain=56&address=0x123');
    check('GET /screen/address rejects invalid address with 400', r.status === 400 && typeof r.json?.error === 'string', `status=${r.status}`);
  }

  // 4. Address screen rejects an unsupported chain.
  {
    const r = await req(base, `/screen/address?chain=1&address=${OWNER}`);
    check('GET /screen/address rejects unsupported chain with 400', r.status === 400, `status=${r.status}`);
  }

  // 5. Live address screen of the owner's Agentic wallet: expected CLEAN.
  {
    const r = await req(base, `/screen/address?chain=56&address=${OWNER}`, { timeoutMs: 120000 });
    const ok = r.status === 200 && r.json?.verdict === 'CLEAN' && r.json?.summary?.live_found === 0 && r.json?.summary?.pairs_checked >= 10;
    check('GET /screen/address live-screens the Agentic wallet as CLEAN', ok, `status=${r.status} verdict=${r.json?.verdict} pairs_checked=${r.json?.summary?.pairs_checked} live_found=${r.json?.summary?.live_found}`);
    if (r.json) console.log('       live result:', JSON.stringify(r.json));
  }

  // 6. Unlimited approve to an unknown spender: expected BLOCK.
  {
    const spender = '0x1111111111111111111111111111111111111111';
    const inputData = '0x095ea7b3' + pad(spender) + MAX_UINT;
    const r = await req(base, '/screen/transaction', { method: 'POST', body: { chain: 56, from: OWNER, to: USDT, value: '0', inputData } });
    check('POST /screen/transaction BLOCKs unlimited approve to unknown spender', r.status === 200 && r.json?.verdict === 'BLOCK' && r.json.flags.some((f) => f.rule === 'unlimited-approval'), `status=${r.status} verdict=${r.json?.verdict}`);
  }

  // 7. Unlimited approve to the known PancakeSwap router: HIGH flag but REVIEW, not BLOCK.
  {
    const inputData = '0x095ea7b3' + pad(PANCAKE_ROUTER) + MAX_UINT;
    const r = await req(base, '/screen/transaction', { method: 'POST', body: { chain: 56, from: OWNER, to: USDT, value: '0', inputData } });
    check('POST /screen/transaction REVIEWs (not BLOCKs) unlimited approve to known router', r.status === 200 && r.json?.verdict === 'REVIEW', `status=${r.status} verdict=${r.json?.verdict}`);
  }

  // 8. setApprovalForAll(true) to an unknown operator: expected BLOCK.
  {
    const operator = '0x2222222222222222222222222222222222222222';
    const inputData = '0xa22cb465' + pad(operator) + word(1);
    const r = await req(base, '/screen/transaction', { method: 'POST', body: { chain: 56, from: OWNER, to: NFT, value: '0', inputData } });
    check('POST /screen/transaction BLOCKs setApprovalForAll(true) to unknown operator', r.status === 200 && r.json?.verdict === 'BLOCK' && r.json.flags.some((f) => f.rule === 'operator-approval-all'), `status=${r.status} verdict=${r.json?.verdict}`);
  }

  // 9. Plain native transfer to an EOA with empty calldata: expected ALLOW.
  {
    const r = await req(base, '/screen/transaction', { method: 'POST', body: { chain: 56, from: OWNER, to: '0x3333333333333333333333333333333333333333', value: '1000000000000000', inputData: '0x' } });
    check('POST /screen/transaction ALLOWs a plain EOA transfer', r.status === 200 && r.json?.verdict === 'ALLOW', `status=${r.status} verdict=${r.json?.verdict} flags=${JSON.stringify(r.json?.flags)}`);
  }

  // 10. Value to a contract with empty calldata: expected REVIEW.
  {
    const r = await req(base, '/screen/transaction', { method: 'POST', body: { chain: 56, from: OWNER, to: USDT, value: '1000', inputData: '0x' } });
    check('POST /screen/transaction REVIEWs value-to-contract with empty calldata', r.status === 200 && r.json?.verdict === 'REVIEW' && r.json.flags.some((f) => f.rule === 'value-to-contract-empty-calldata'), `status=${r.status} verdict=${r.json?.verdict}`);
  }

  // 11. Malformed JSON body: 400.
  {
    const r = await req(base, '/screen/transaction', { method: 'POST', rawBody: '{not json' });
    check('POST /screen/transaction rejects malformed JSON with 400', r.status === 400, `status=${r.status}`);
  }

  // 12. Unknown route: 404 JSON.
  {
    const r = await req(base, '/nope');
    check('GET unknown route returns 404 JSON', r.status === 404 && typeof r.json?.error === 'string', `status=${r.status}`);
  }

  // 13. Wrong method on the address screen: 405.
  {
    const r = await req(base, '/screen/address', { method: 'POST', body: {} });
    check('POST /screen/address returns 405', r.status === 405, `status=${r.status}`);
  }
} catch (err) {
  check('test harness completed without exception', false, String(err?.message ?? err));
} finally {
  child.kill('SIGTERM');
}

const failed = results.filter((r) => !r.pass);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length === 0 ? 0 : 1);
