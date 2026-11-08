# OpenDoor

**Make your existing website agent-ready.** OpenDoor exposes your site's features to Claude, ChatGPT and custom AI agents through the Model Context Protocol (MCP). Users stay in control: they approve each agent, choose what it may do, set limits, and can revoke it at any time. Every call is logged.

You keep your app, your login and your business logic. You describe what agents may do, and OpenDoor handles the rest:

| You write | OpenDoor provides |
|---|---|
| A list of actions that call your existing functions | An MCP server at `/mcp` (Streamable HTTP) and a matching REST API at `/agent/v1/actions` |
| Scopes (permissions) and optional limits | OAuth 2.1 for agents: discovery, dynamic client registration, PKCE, refresh rotation |
| `getUser(req)` from your existing session | A consent screen, plus a "Connected agents" dashboard with tokens, permissions, revoke and an activity log |
| | Per-call permission checks, input validation, confirmation for risky steps, rate limits, an audit log, and `llms.txt` |

## Quick start (Express)

```bash
npm install @abhishekvardanbotta/opendoor
```

```js
import { openDoor, action, z } from "@abhishekvardanbotta/opendoor";

const door = openDoor({
  name: "Acme Store",
  db: pool,                                    // pg Pool or PGlite; OpenDoor adds its own opendoor_* tables
  getUser: (req) => req.user,                  // your existing sign-in → { id, name?, email? } or null
  loginUrl: (next) => `/login?next=${encodeURIComponent(next)}`,
  scopes: {
    "orders:read": { label: "View your orders", description: "Order history and status." },
    "checkout:create": { label: "Place orders", description: "Buy with your saved card.", risk: "high" },
  },
  limits: { spend: { label: "Per-order spending limit", scope: "checkout:create", format: "usd_cents" } },
  actions: [
    action({
      name: "orders.list", scope: "orders:read", readOnly: true,
      description: "List the user's recent orders.",
      run: (ctx) => orders.listForUser(ctx.user.id),
    }),
    action({
      name: "checkout.create", scope: "checkout:create", confirm: true,
      description: "Buy everything in the cart.",
      input: z.object({ coupon: z.string().optional() }),
      run: async (ctx, { coupon }) => {
        const total = await cart.total(ctx.user.id, coupon);
        ctx.enforceLimit("spend", total);        // the user's per-agent cap
        return checkout.place(ctx.user.id, { coupon });
      },
    }),
  ],
});

app.use(door.router);   // after your session middleware
```

Users connect agents at `/opendoor`. In Claude or ChatGPT, adding `https://your-site.com/mcp` as a custom connector sends them through your consent screen.

Check the setup:

```bash
npx @abhishekvardanbotta/opendoor check https://your-site.com
```

## Concepts

**Actions** are the things an agent may do. Each has a dotted name (`orders.get`), one required scope, a zod input schema, and a `run(ctx, input)` that calls your existing code as `ctx.user`. Optional flags:

- `readOnly`, `destructive` and `idempotent` become hints for MCP clients.
- `confirm: true` requires the agent to pass `confirm: true`, after asking the user.
- `summarize(result, input)` sets the one-line text shown in the activity log.

Throw an error with a string `code` and a `status` below 500 to return a clean error to the agent. Any other error becomes `INTERNAL_ERROR`, and its details stay on your server.

**Scopes** are the permissions users grant, with a label, a description and `risk: "low" | "medium" | "high"`. High-risk scopes are unticked by default on consent screens. Agents only see tools for the scopes they hold, and every call is checked again.

**Limits** are numeric caps the user sets for each agent, such as a spending limit, a number of messages per day, or a maximum discount. Enforce them inside your action with `ctx.enforceLimit(key, amount)`, or read `ctx.limits[key]`.

**Grants** are one user's approval of one agent. Scopes and limits are read on every request, so edits and revocations apply immediately. Agents connect by:

- **OAuth.** Hosted assistants such as Claude, ChatGPT and Cursor register themselves; their `client_id` becomes the Agent ID.
- **Token.** For scripts and custom agents, the user registers an Agent ID and gets a bearer token. Only its SHA-256 hash is stored.

## Options

| Option | Default | |
|---|---|---|
| `name` | required | Shown on consent screens and to agents |
| `db` | required | Anything with `query(text, params) → { rows }` |
| `getUser(req)` | required | Current signed-in user, or null |
| `scopes`, `actions` | required | See above |
| `findUser(id)` | — | Fills in `ctx.user` (name, email) for agent calls |
| `loginUrl(next)` | — | Where the built-in pages send signed-out users |
| `limits` | `{}` | `{ key: { label, scope, format: "usd_cents" \| "number" } }` |
| `publicUrl` | taken from the request | Public HTTPS origin, a string or `(req) => string` |
| `consentPath`, `dashboardPath`, `appUrl` | built-in pages | Use your own UI on top of the JSON API |
| `pages` | `true` | `false` disables the built-in pages |
| `basePath` | `/opendoor` | Where the pages and `/api` live |
| `toolNames` | `"underscore"` | MCP names `orders_get`. Claude and ChatGPT reject dots; `"dotted"` keeps them |
| `rateLimit` | `{ perMinute: 60 }` | Per agent connection |
| `accessTokenTtl`, `refreshTokenTtl` | 1 h, 30 d | OAuth token lifetimes, in seconds |
| `instructions` | generated | MCP server instructions for agents |

**Build your own UI.** `{basePath}/api` is a JSON API covering `meta`, `grants`, `connect`, `grants/:id` (PATCH), `grants/:id/token`, `grants/:id/revoke`, `activity`, `oauth/request` and `oauth/consent`. It uses your session through `getUser`, and writes must send JSON. AIShop (live at https://aishop-alpha.vercel.app) uses its own React screens on top of this API.

## Security model

- **Tokens:** 256-bit random tokens, stored as hashes. OAuth codes are single use, expire after 10 minutes and require PKCE (S256 only). Refresh tokens rotate on every use, and loopback-aware redirect URIs must match exactly.
- **Permissions:** checked on every call against the live grant. An agent can't exceed what the user approved, and the user can narrow what the agent asked for but never widen it. An optional `X-Agent-Id` header must match the token's agent.
- **Consent pages:** framing is denied, everything an agent supplies (such as its name) is escaped, and management writes must be JSON, which works as CSRF protection alongside your cookie's SameSite setting.
- **Audit log:** records the agent, action, transport, required and granted scopes, redacted input, outcome and IP, plus authorization events (connect, authorize, deny, update, rotate, revoke).
- **Limits of this version:** rate limits are kept in memory per process. OpenDoor trusts your `getUser`, so protect your sessions as usual.

## Coding agents

[skill/SKILL.md](skill/SKILL.md) teaches Claude Code and similar coding agents to add OpenDoor to an existing codebase: survey the app, propose an action and scope map, wire it up, and verify it.

## Examples

- [examples/tasks](examples/tasks): a plain server-rendered app made agent-ready with one block of code (`node examples/tasks/server.js`).
- AIShop: a full store with a React UI built on OpenDoor, live at https://aishop-alpha.vercel.app.

Requires Node 20+, PostgreSQL (or PGlite), Express 4.18+ or 5.
