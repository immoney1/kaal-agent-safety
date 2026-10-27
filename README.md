# kaal-agent-safety — x402 paid MCP server

Two paid MCP tools plus three free HTTP endpoints. Buyers pay **USDC on Base**
(per-call, x402 `exact` scheme, EIP-3009 transferWithAuthorization) — no API
keys, no subscriptions. Free `initialize` + `tools/list`; payment only on
`tools/call` (HTTP 402 with payment requirements).

## Endpoints

| Endpoint | Method | Price | Notes |
|---|---|---|---|
| `/v1/safety/check?target=<url>` | GET | $0.002 | deterministic payment-safety / phishing scan + signed receipt |
| `/v1/recommend?category=<cat>` | GET | $0.005 | ranked provider / cost-directory lookup |
| `/mcp` | POST (MCP) | see below | streamable-http MCP transport |
| `/.well-known/mcp.json` | GET | free | MCP discovery manifest |
| `/.well-known/x402` | GET | free | x402 payment manifest (payTo, facilitator, prices) |
| `/v1/verify?receipt=<id>` | GET | free | replayable receipt verification |
| `/health` | GET | free | liveness |

### MCP tools

- `safety_check(target)` — $0.002 per call: flags `credentials_in_url`,
  `no_hsts`, `ip_literal`, lookalike hosts, missing `/.well-known/x402`
  manifest; returns `AVOID / CAUTION / CAUTION_NONE_DETECTED` + signed receipt.
- `recommend(category)` — $0.005 per call: ranked whitespace/cost directory
  across search, onchain-data, agent-safety, paid-discovery, tx-execution.

## Connect

```bash
claude mcp add --transport http kaal-agent-safety https://<host>/mcp
# or any MCP client pointed at the streamable-http URL in server.json
```

Free: `initialize`, `notifications/initialized`, `tools/list`.
Paid: `tools/call` requires `X-PAYMENT` header (base64 exact-scheme payload);
server settles through an x402 facilitator and returns `X-Payment-Response`
with the on-chain transaction.

## Run

```bash
npm ci
RECEIPT_SECRET=<32-byte-hex> \
NETWORK=base FACILITATOR_URL=http://127.0.0.1:8142 \
PORT=8140 node server.js
```

`RECEIPT_SECRET` (or `WALLET_FILE=<path-to-wallet-json>`) signs receipts.
`NETWORK` is `base` (mainnet) or `base-sepolia`. Settlement is non-custodial:
funds go straight to the configured `payTo` wallet on every settlement.

## Verified

- Local E2E: unpaid 402 → EIP-3009 signed payment → verify → settle →
  on-chain receipt status 1.
- Public E2E over a tunnel: paid `GET /v1/safety/check` settled with tx
  `0xd7bd01780b75d106fb3e286b6a3c55a78a6a486ee2cf439f4d2b3d8b5b1c28d7`
  (Base mainnet, block 53162843, gas 83208).
- Revenue ledger + treasury sweep + systemd auto-restart are part of the
  production deployment.

## License

MIT
