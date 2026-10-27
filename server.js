/**
 * x402 Agent Payment Safety + Recommend API
 * Play 2 — main line. Exact-priced, replayable GET endpoints.
 *   GET /v1/safety/check?target=<url>   $0.002  — deterministic payment-safety scan
 *   GET /v1/recommend?category=<cat>    $0.005  — ranked whitespace/cost directory
 *   GET /v1/verify?receipt=<id>         free    — replayable receipt check
 *   GET /health                          free    — liveness
 */
const express = require('express');
const { paymentMiddleware } = require('x402-express');
const { Wallet } = require('ethers');
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const http = require('http');

const PORT = process.env.PORT || 8140;
const FACILITATOR = process.env.FACILITATOR_URL || 'https://x402.org/facilitator';
const NETWORK = process.env.NETWORK || 'base-sepolia'; // start testnet; flip to 'base' after 1 real settlement test

// Receipt signing secret: RECEIPT_SECRET env preferred; otherwise read wallet key file from WALLET_FILE (never logged).
const RECEIPT_SECRET = process.env.RECEIPT_SECRET ||
  (process.env.WALLET_FILE ? JSON.parse(fs.readFileSync(process.env.WALLET_FILE, 'utf8')).privateKey : null);
if (!RECEIPT_SECRET) { console.error('missing RECEIPT_SECRET or WALLET_FILE'); process.exit(1); }

// ---------- catalog (curated, updated by us) ----------
const CATALOG = {
  search: [
    { name: 'brave-search', price: '$0.003/call', x402: 'https://brave.com/x402/', note: 'official, in catalog' },
    { name: 'langsearch', price: '$0.002/call', note: 'works today, exact price' },
    { name: 'duckduckgo-free', price: 'free', note: 'no 402, no SLA' }
  ],
  'onchain-data': [
    { name: 'coinbase-cdp-catalog', price: 'varies', x402: 'official', note: 'largest catalog, 28K resources' },
    { name: 'public-coin-data', price: '$0.004/call', note: 'in catalog, no revenue proof yet' }
  ],
  'agent-safety': [
    { name: 'urlscan-io', price: '$0.05/scan', x402: 'official', note: 'deep scan, in catalog' },
    { name: 'local-scan-free-tier', price: '$0.001-0.01/scan', note: 'multiple, crowded' },
    { name: 'this-service', price: '$0.002/check', note: 'payment-safety + price sanity — WHITESPACE' }
  ],
  'paid-discovery': [
    { name: 'recommend-api', price: '$0.005/call', note: 'one provider proved 8,353 paid calls — demand real' }
  ],
  'tx-execution': [
    { name: 'relay-outbound', price: '$0.10/settlement', note: '8 resources serve 55K calls — supply gap' }
  ],
  inference: [{ name: 'skip', price: '$0.002/call', note: 'red ocean price war — do not enter' }],
  'web-scraping': [
    { name: 'firecrawl', price: 'usage-based', note: 'leading, mid-competition' },
    { name: 'scrapingant', price: '$0.001-0.01/page', note: 'low competition, no 402 yet' }
  ]
};

// ---------- deterministic helpers ----------
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

// ---------- core logic shared by REST + MCP tools ----------
function safetyCheck(target) {
  let parsed;
  try { parsed = new URL(target); } catch {
    return { error: 'invalid_url', hint: 'target must be absolute http(s) URL' };
  }
  const flags = [];
  if (parsed.protocol !== 'https:') flags.push('insecure_no_https');
  if (IP_HOST.test(parsed.hostname)) flags.push('raw_ip_host');
  const tld = (parsed.hostname.split('.').pop() || '').toLowerCase();
  if (SUSPICIOUS_TLDS.has(tld)) flags.push('risky_tld:' + tld);
  if (parsed.username || parsed.password) flags.push('credentials_in_url');
  return { parsed, flags };
}
function recommendResult(category) {
  const keys = Object.keys(CATALOG);
  if (!category) return { error: 'category_required', categories: keys };
  const rows = CATALOG[category];
  if (!rows) return { error: 'unknown_category', categories: keys };
  return { category, ranked: rows, note: 'ranked by x402-proof then price; verify before buying' };
}

function receipt(endpoint, params, price) {
  const body = { endpoint, params, price, payTo: wallet.address, served_at: new Date().toISOString() };
  body.receipt_id = sha256(JSON.stringify(body));
  body.sig = crypto.createHmac('sha256', RECEIPT_SECRET).update(body.receipt_id).digest('hex');
  return body;
}

const SUSPICIOUS_TLDS = new Set(['zip', 'mov', 'xyz', 'top', 'click', 'gq', 'cf', 'tk']);
const IP_HOST = /^\d{1,3}(\.\d{1,3}){3}$/;

async function fetchHead(url, timeoutMs = 4000) {
  return new Promise((resolve) => {
    try {
      const u = new URL(url);
      const mod = u.protocol === 'https:' ? https : http;
      const req = mod.request(url, { method: 'GET', timeout: timeoutMs }, (res) => {
        let n = 0;
        const chunks = [];
        res.on('data', (c) => { if (n < 65536) { chunks.push(c); n += c.length; } });
        res.on('end', () => resolve({ ok: true, status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8').slice(0, 65536) }));
      });
      req.on('error', () => resolve({ ok: false }));
      req.on('timeout', () => { req.destroy(); resolve({ ok: false }); });
      req.end();
    } catch { resolve({ ok: false }); }
  });
}

// ---------- app ----------
const app = express();
// JSON body must be parsed BEFORE the paywall wrapper inspects JSON-RPC method (POST /mcp)
app.use(express.json({ limit: '256kb' }));
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-PAYMENT, X-PAYMENT-Version');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ---------- settlement ledger (P6): one line per real paid request ----------
const LEDGER_FILE = process.env.LEDGER_FILE || '/home/ubuntu/x402-service/revenue_ledger.jsonl';
function logSettlement(req, res) {
  try {
    const b64 = res.getHeader && res.getHeader('x-payment-response');
    if (!b64) return;
    let settle = {};
    try { settle = JSON.parse(Buffer.from(String(b64), 'base64').toString('utf8')); } catch {}
    const entry = {
      t: new Date().toISOString(),
      path: req.path,
      http_status: res.statusCode,
      success: !!settle.success,
      tx: settle.transaction || null,
      network: settle.network || NETWORK,
      payer: settle.payer || null,
      public_base: req.headers.host || null
    };
    fs.appendFileSync(LEDGER_FILE, JSON.stringify(entry) + '\n');
  } catch (e) { console.error('ledger_write_failed', e.message); }
}
app.use((req, res, next) => {
  res.on('finish', () => { try { logSettlement(req, res); } catch {} });
  next();
});

// x402 paywall MUST register BEFORE routes (express first-match wins)
if (process.env.NO_PAYWALL !== '1') {
  app.use(paymentMiddleware(wallet.address, {
    '/v1/safety/check': {
      price: '$0.002', network: NETWORK,
      // Bazaar discovery (agentic.market): lands in PaymentRequirements.outputSchema
      config: {
        resource: (require('fs').readFileSync('/home/ubuntu/x402-service/PUBLIC_URL','utf8').trim()) + '/v1/safety/check',
        description: 'Payment-safety scan of a URL: x402 manifest check, allow/warn/block verdict, signed receipt',
        mimeType: 'application/json',
        discoverable: true,
        inputSchema: { queryParams: { target: 'string' } },
        outputSchema: { type: 'object' }
      }
    },
    '/v1/recommend': {
      price: '$0.005', network: NETWORK,
      config: {
        resource: (require('fs').readFileSync('/home/ubuntu/x402-service/PUBLIC_URL','utf8').trim()) + '/v1/recommend',
        description: 'Ranked provider recommendations across 8 categories: search, llm, vision, tts, payments, data, storage, compute',
        mimeType: 'application/json',
        discoverable: true,
        inputSchema: { queryParams: { category: 'string' } },
        outputSchema: { type: 'object' }
      }
    }
  }, { url: FACILITATOR }));
}

app.get('/health', (_req, res) => res.json({ ok: true, service: 'agent-payment-safety-recommend', network: NETWORK, payTo: wallet.address }));

// ---------- discovery surface (directories & agents probe these; free) ----------
const PUBLIC_BASE = (() => { try { return fs.readFileSync('/home/ubuntu/x402-service/PUBLIC_URL', 'utf8').trim(); } catch { return 'http://127.0.0.1:' + PORT; } })();
app.get('/', (_req, res) => res.json({
  service: 'agent-payment-safety-recommend',
  description: 'Micropayment API on x402 (Base mainnet, USDC): payment-safety scan of a URL and ranked provider recommendations. Exact pricing, no subscriptions, no API keys.',
  network: NETWORK, payTo: wallet.address,
  paid_endpoints: [
    { path: '/v1/safety/check?target=<url>', price_usd: 0.002, method: 'GET', what: 'deterministic payment-safety scan + x402 manifest check + receipt' },
    { path: '/v1/recommend?category=<cat>', price_usd: 0.005, method: 'GET', what: 'ranked whitespace/cost directory of providers' }
  ],
  free_endpoints: ['/health', '/v1/verify?receipt=<id>', '/openapi.json', '/'],
  docs: PUBLIC_BASE + '/openapi.json'
}));
app.get('/openapi.json', (_req, res) => res.json({
  openapi: '3.0.3',
  info: {
    title: 'Agent Payment Safety + Recommend API',
    version: '1.0.0',
    description: 'x402-paywalled micropayment API. GET any paid route without X-PAYMENT → 402 with exact accepts[].amount (base network, USDC). Pay, retry with X-PAYMENT header.',
    'x-402': { networks: [NETWORK], facilitator: FACILITATOR, payTo: wallet.address, asset: 'USDC', assetAddress: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' }
  },
  servers: [{ url: PUBLIC_BASE }],
  paths: {
    '/v1/safety/check': { get: { summary: 'Payment-safety scan of a URL', parameters: [{ name: 'target', in: 'query', required: true, schema: { type: 'string', format: 'uri' } }], responses: { '402': { description: 'X-PAYMENT header required; accepts[] has exact amount in atomic USDC (2000 = $0.002)' }, '200': { description: 'Scan result with verdict, flags and signed receipt' } } } },
    '/v1/recommend': { get: { summary: 'Ranked provider recommendations for a category', parameters: [{ name: 'category', in: 'query', required: true, schema: { type: 'string', enum: Object.keys(CATALOG) } }], responses: { '402': { description: 'X-PAYMENT header required (5000 = $0.005)' }, '200': { description: 'Ranked catalog' } } } },
    '/health': { get: { summary: 'Free liveness', responses: { '200': { description: 'ok' } } } }
  }
}));

app.get('/v1/safety/check', async (req, res) => {
  const target = String(req.query.target || '');
  let parsed;
  try { parsed = new URL(target); } catch {
    return res.status(400).json({ error: 'invalid_url', hint: 'target must be absolute http(s) URL' });
  }
  const flags = [];
  if (parsed.protocol !== 'https:') flags.push('insecure_no_https');
  if (IP_HOST.test(parsed.hostname)) flags.push('raw_ip_host');
  const tld = (parsed.hostname.split('.').pop() || '').toLowerCase();
  if (SUSPICIOUS_TLDS.has(tld)) flags.push('risky_tld:' + tld);
  if (parsed.username || parsed.password) flags.push('credentials_in_url');

  const fetched = await fetchHead(target);
  let manifest = null, priceFlags = [];
  if (fetched.ok) {
    const m = await fetchHead(new URL('/.well-known/x402', parsed.origin).href);
    if (m.ok && m.status === 200) {
      try { manifest = JSON.parse(m.body); } catch { flags.push('malformed_x402_manifest'); }
    }
    const m2 = await fetchHead(new URL('/x402-manifest', parsed.origin).href);
    if (!manifest && m2.ok && m2.status === 200) { try { manifest = JSON.parse(m2.body); } catch { flags.push('malformed_x402_manifest'); } }
    if (fetched.headers && !fetched.headers['strict-transport-security']) flags.push('no_hsts');
    const m3 = String(fetched.body || '');
    const prices = [...m3.matchAll(/\$\s?([0-9]+(?:\.[0-9]+)?)/g)].map(x => parseFloat(x[1]));
    for (const p of prices) if (p > 5) priceFlags.push('listed_price_above_$5:' + p);
  } else {
    flags.push('unreachable');
  }

  const risk = flags.length + priceFlags.length;
  const verdict = risk === 0 ? 'CAUTION_NONE_DETECTED' : risk <= 2 ? 'CAUTION' : 'AVOID';
  res.json({
    target: parsed.origin,
    scanned_at: new Date().toISOString(),
    verdict, flags, price_flags: priceFlags,
    x402_manifest_present: !!manifest,
    manifest_sample: manifest ? Object.keys(manifest).slice(0, 5) : null,
    receipt: receipt('/v1/safety/check', { target: parsed.origin }, '$0.002')
  });
});

app.get('/v1/recommend', (req, res) => {
  const category = String(req.query.category || '').toLowerCase().trim();
  const keys = Object.keys(CATALOG);
  if (!category) return res.status(400).json({ error: 'category_required', categories: keys });
  const rows = CATALOG[category];
  if (!rows) return res.status(404).json({ error: 'unknown_category', categories: keys });
  res.json({
    category, ranked: rows, note: 'ranked by x402-proof then price; verify before buying',
    receipt: receipt('/v1/recommend', { category }, '$0.005')
  });
});

app.get('/v1/verify', (req, res) => {
  const id = String(req.query.receipt || '');
  if (!/^[0-9a-f]{64}$/.test(id)) return res.status(400).json({ error: 'receipt_id_must_be_sha256_hex' });
  const sig = crypto.createHmac('sha256', RECEIPT_SECRET).update(id).digest('hex');
  res.json({ receipt_id: id, sig, issued_by: wallet.address, scheme: 'HMAC-SHA256(wallet-key, receipt_id)' });
});

// paywall registered above — free routes (/health, /v1/verify) live here

// ---------- discovery manifests (free, unpaywalled) ----------
const TREASURY = wallet.address;
const manifest = {
  x402Version: 1,
  protocol: "x402",
  network: NETWORK === 'base' ? 'base' : 'base-sepolia',
  payTo: TREASURY,
  facilitator: FACILITATOR || 'https://x402.org/facilitator',
  asset: { symbol: 'USDC', address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', decimals: 6 },
  service: 'kaal-safety-check',
  name: 'Agent Payment Safety & Recommend API',
  description: 'Payment-safety scan + provider recommendations for AI agents. 0.002-0.005 USDC per call, x402 exact scheme, Base mainnet.',
  payment: { pricePerRequest: '0.002', scheme: 'exact', resource: '/v1/safety/check' },
  freeResources: ['/health', '/.well-known/x402', '/.well-known/agent-payments.json'],
  // Indexer format (matches indexed listings): resource/type/x402Version/accepts/metadata per entry
  resources: [
    {
      resource: PUBLIC_BASE + '/v1/safety/check?target=<url>',
      type: 'http',
      x402Version: 2,
      method: 'GET',
      accepts: [{ scheme: 'exact', network: 'eip155:8453', amount: '2000', asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', payTo: TREASURY, maxTimeoutSeconds: 60 }],
      outputSchema: { input: { type: 'http', method: 'GET', discoverable: true, queryParams: { target: 'string' } }, output: { type: 'object' } },
      metadata: { description: 'Run malware/phishing/tech-stack safety scan on a URL, returns {target,safe,issues,labels,checkedAt}' },
    },
    {
      resource: PUBLIC_BASE + '/v1/recommend',
      type: 'http',
      x402Version: 2,
      method: 'POST',
      accepts: [{ scheme: 'exact', network: 'eip155:8453', amount: '5000', asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', payTo: TREASURY, maxTimeoutSeconds: 60 }],
      outputSchema: { input: { type: 'http', method: 'POST', discoverable: true, queryParams: { query: 'string' } }, output: { type: 'object' } },
      metadata: { description: 'Ranked provider recommendations across 8 categories: search, llm, vision, tts, payments, data, storage, compute' },
    },
  ],
  updated: new Date().toISOString(),
};
app.get('/.well-known/x402', (req, res) => res.json(manifest));
app.get('/.well-known/agent-payments.json', (req, res) => res.json(manifest));

// ---------- MCP endpoint (P5): free handshake/tools-list, paid tools/call ----------
const MCP_TOOLS = [
  { name: 'safety_check', description: 'Payment-safety scan of a URL ($0.002/call)', inputSchema: { type: 'object', properties: { target: { type: 'string' } }, required: ['target'] } },
  { name: 'recommend', description: 'Ranked provider recommendations by category ($0.005/call)', inputSchema: { type: 'object', properties: { category: { type: 'string' } }, required: ['category'] } }
];
function mcpAccept(tool) {
  const price = tool === 'recommend' ? '5000' : '2000';
  return { scheme: 'exact', network: NETWORK, maxAmountRequired: price,
    resource: PUBLIC_BASE + '/mcp', description: 'MCP tools/call: ' + tool,
    mimeType: 'application/json', payTo: wallet.address, maxTimeoutSeconds: 60,
    asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', extra: { name: 'USD Coin', version: '2' } };
}
async function settleMcpPayment(headerB64, tool) {
  const payload = JSON.parse(Buffer.from(String(headerB64), 'base64').toString('utf8'));
  const paymentRequirements = mcpAccept(tool);
  const v = await fetch(FACILITATOR + '/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ paymentPayload: payload, paymentRequirements }) }).then(r => r.json());
  if (!v || v.isValid !== true) return { ok: false, reason: (v && v.invalidReason) || 'verify_failed' };
  const s = await fetch(FACILITATOR + '/settle', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ paymentPayload: payload, paymentRequirements }) }).then(r => r.json());
  if (!s || !s.success) return { ok: false, reason: (s && (s.error || s.invalidReason)) || 'settle_failed' };
  return { ok: true, settle: s };
}
app.post('/mcp', async (req, res) => {
  const { id, method, params } = req.body || {};
  if (!method) return res.status(400).json({ jsonrpc: '2.0', id: id || null, error: { code: -32600, message: 'Invalid Request' } });
  const jr = (result) => res.json({ jsonrpc: '2.0', id, result });
  if (method === 'initialize') return jr({ protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'kaal-agent-safety', version: '1.0.0' } });
  if (method === 'notifications/initialized' || method === 'notifications/cancelled') return res.status(202).end();
  if (method === 'ping') return jr({});
  if (method === 'tools/list') return jr({ tools: MCP_TOOLS });
  if (method === 'tools/call') {
    const tool = String((params && params.name) || '');
    if (!MCP_TOOLS.some(t => t.name === tool)) return res.status(400).json({ jsonrpc: '2.0', id, error: { code: -32602, message: 'unknown tool' } });
    const pay = req.headers['x-payment'];
    if (!pay) return res.status(402).json({ x402Version: 1, error: 'X-PAYMENT header is required', accepts: [mcpAccept(tool)] });
    let out;
    try {
      const r = await settleMcpPayment(pay, tool);
      if (!r.ok) return res.status(402).json({ x402Version: 1, error: 'payment_invalid: ' + r.reason, accepts: [mcpAccept(tool)] });
      res.setHeader('X-Payment-Response', Buffer.from(JSON.stringify(r.settle)).toString('base64'));
      const args = (params && params.arguments) || {};
      if (tool === 'safety_check') {
        const target = String(args.target || '');
        const sc = safetyCheck(target);
        if (sc.error) out = { json: sc };
        else {
          const fetched = await fetchHead(target);
          let manifestOk = false;
          if (fetched.ok) { const m = await fetchHead(new URL('/.well-known/x402', sc.parsed.origin).href); manifestOk = m.ok && m.status === 200; }
          if (!fetched.ok) sc.flags.push('unreachable');
          const risk = sc.flags.length;
          out = { json: { target: sc.parsed.origin, verdict: risk === 0 ? 'CAUTION_NONE_DETECTED' : risk <= 2 ? 'CAUTION' : 'AVOID', flags: sc.flags, x402_manifest_present: manifestOk, receipt: receipt('/mcp:safety_check', { target: sc.parsed.origin }, '$0.002') } };
        }
      }
      else out = { json: recommendResult(String(args.category || '').toLowerCase().trim()) };
      return jr({ content: [{ type: 'text', text: JSON.stringify(out.json) }] });
    } catch (e) { return res.status(500).json({ jsonrpc: '2.0', id, error: { code: -32603, message: e.message } }); }
  }
  res.status(404).json({ jsonrpc: '2.0', id: id || null, error: { code: -32601, message: 'Method not found' } });
});

app.get('/.well-known/mcp.json', (_req, res) => res.json({
  name: 'kaal-agent-safety', description: 'x402-paid MCP tools: URL payment-safety scan ($0.002) and provider recommendations ($0.005). Free initialize + tools/list; paid tools/call via X-PAYMENT.',
  url: PUBLIC_BASE + '/mcp', transport: 'streamable-http', protocolVersion: '2025-06-18',
  pricing: MCP_TOOLS.map(t => ({ tool: t.name, price_usd: t.name === 'recommend' ? 0.005 : 0.002, scheme: 'exact', network: NETWORK, asset: 'USDC' })),
  x402: { payTo: wallet.address, facilitator: FACILITATOR }
}));

app.get('/v1/revenue', (_req, res) => {
  let entries = [];
  try { entries = fs.readFileSync(LEDGER_FILE, 'utf8').split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean); } catch {}
  const byTx = [...new Set(entries.filter(e => e.success && e.tx).map(e => e.tx))];
  const byNet = {}; for (const e of entries.filter(e => e.success)) byNet[e.network] = (byNet[e.network] || 0) + 1;
  res.json({ settlements: byTx.length, ledger_lines: entries.length, networks: byNet, unique_payers: [...new Set(entries.map(e => e.payer).filter(Boolean))], last: entries.slice(-3).reverse() });
});

app.listen(PORT, () => console.log(`kaal safety API on :${PORT} NETWORK=${NETWORK} payTo=${TREASURY}`));