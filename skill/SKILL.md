---
name: opendoor
description: Make an existing website or web app agent-ready with OpenDoor (@abhishekvardanbotta/opendoor), so Claude, ChatGPT and custom AI agents can use its features over MCP with user consent, scoped permissions, limits and an audit log. Use when the user asks to make their site "AI-ready" or "agent-ready", expose their app to AI assistants or agents, add an MCP server to a web app, let Claude or ChatGPT operate their site, or add agent permissions or consent to an app.
---

# Make a website agent-ready with OpenDoor

OpenDoor is a Node library. You describe what agents may do (**actions**), grouped into
permissions (**scopes**), and it adds:

- an MCP server (`/mcp`) and a REST twin (`/agent/v1/actions`)
- OAuth 2.1 for agents (Claude and ChatGPT connect themselves)
- a consent screen, plus a "Connected agents" dashboard with tokens, permissions, revoke and an activity log
- permission checks, input validation, confirmations, limits and audit logging on every call

Your job is to map the app's existing features onto actions **without changing its business
logic**, wire up its existing login, and prove the result works.

## 1. Survey the app (read before writing anything)

Find out, and note file paths:

- **Server stack.** OpenDoor mounts as Express middleware (Express 4.18+ or 5, Node 20+).
  - **Next.js, Fastify, Nest or Koa:** Nest and Next's custom server can host an Express router. Otherwise run OpenDoor in a small Express service that shares the app's database and session store. Say which, and why, in your plan.
  - **Not Node (Rails, Django, Laravel, Go…):** run an Express sidecar that calls the app's internal API with a service credential, and resolves the user from the shared session or a signed cookie. Flag this as more work and confirm it with the user.
- **Authentication.** How the current user is resolved per request: session cookie, JWT or passport (`req.user`). You'll write `getUser(req) → { id, name?, email? } | null`. It must use the existing mechanism; never add a second login.
- **Database.** OpenDoor needs PostgreSQL through anything with `query(text, params) → { rows }` (a `pg` Pool, Prisma's `$queryRawUnsafe` wrapped to that shape, Knex's `raw`, or PGlite). It creates only `opendoor_*` tables. With no Postgres (MySQL, Mongo), give OpenDoor its own Postgres (Neon or Supabase) or PGlite with a persistent directory. Never put OpenDoor tables in a non-Postgres database.
- **Capabilities.** List what a signed-in user can do in the UI and API: the routes, controllers or service functions. Prefer **service-layer functions** over HTTP handlers.
- **Login URL**, the **public URL** in production, and whether the app runs serverless (Vercel or Netlify functions don't keep a filesystem, so use a real database URL).

## 2. Design the action map, and show it to the user before coding

The plan decides what an AI may do with people's accounts, so get the user's approval. Present a table:

| Action | Calls | Scope | Flags | Notes |
|---|---|---|---|---|
| `orders.list` | `orderService.listForUser(userId)` | `orders:read` | readOnly | |
| `checkout.create` | `checkoutService.place(userId)` | `checkout:create` (high) | confirm | spend limit |

Rules:

- **Names:** lowercase and dotted, as `resource.verb` (`cart.add`, `invoices.get`).
- **Scopes:** usually `resource:read` and `resource:write`, aiming for 4–10 in total. Give each a human `label` and `description`.
- **Risk:** irreversible, financial, outward-facing (sending email or posts) or destructive actions are `risk: "high"` with `confirm: true`. Edits are `"medium"`.
- **Limits:** for money or volume (spend per order, messages per day), define one and call `ctx.enforceLimit(key, amount)`. Where the check must be atomic with the write, pass `ctx.limits[key]` into the transaction.
- **Always act as the user:** every `run` must use `ctx.user.id`. Never accept a user id from agent input.
- **Leave out** admin and staff features, password and email changes, payment-method management, account deletion and anything that bypasses existing authorization. Mention what you excluded.
- **Read-only first:** if unsure, start with read actions plus one or two safe writes, and suggest more later.
- **Inputs:** zod objects with `.describe()` on non-obvious fields, documented units (`price_cents`) and bounded lengths and numbers. Accept slugs or ids that a list or search action returns, so agents can chain calls.
- **Outputs:** return plain JSON. Include ids that other actions accept, and human-formatted values next to raw ones (`"total": "$12.50"`, `"total_cents": 1250`). Never return secrets, tokens or other users' data.

## 3. Wire it up

```bash
npm install @abhishekvardanbotta/opendoor
```

Create one module (`src/agents.js` or similar) with all OpenDoor config, then mount it:

```js
import { openDoor, action, z } from "@abhishekvardanbotta/opendoor";   // use this z for schemas

export const door = openDoor({
  name: "Acme",                                           // shown on consent screens
  db: pool,
  getUser: async (req) => req.user ?? null,               // existing auth → { id, name, email }
  findUser: (id) => users.findById(id),                   // optional: name and email in ctx.user
  loginUrl: (next) => `/login?next=${encodeURIComponent(next)}`,
  publicUrl: process.env.PUBLIC_URL,                      // https origin in production
  scopes: { /* from the plan */ },
  limits: { /* optional */ },
  actions: [ /* action({...}) per row of the plan */ ],
});
```

```js
app.set("trust proxy", true);       // behind a proxy or Vercel, so https URLs are right
// … existing session middleware …
app.use(door.router);               // after the session middleware, before any SPA catch-all route
```

Checks:

- **Errors:** errors the agent should see carry `code` (string) and `status` (4xx). Reuse the app's error class if it already has both; otherwise use `OpenDoorError` from the package.
- **Body parsing:** OpenDoor parses its own bodies, and a global `express.json()` is fine.
- **CSRF and CORS:** OpenDoor's management writes require JSON, and its agent endpoints are bearer-only with open CORS. Don't add cookie auth to them.
- **SPA catch-all:** make sure `/mcp`, `/oauth/*`, `/.well-known/*`, `/agent/*`, `/opendoor*` and `/llms.txt` reach Express, both in dev-server proxies and in hosting rewrites.
- **Link it in the UI:** add a link such as "Connected AI agents" to `/opendoor` in the account menu or settings. Building a custom UI on `/opendoor/api` is optional.

## 4. Verify (don't skip this; report what you ran)

1. Start the app and run `npx @abhishekvardanbotta/opendoor check http://localhost:PORT`. Every line should be ✓.
2. Sign in as a test user, open `/opendoor`, choose **Connect an agent** with read-only scopes, and copy the token.
3. Call a read action and a forbidden one:
   ```bash
   curl -s -X POST localhost:PORT/agent/v1/actions/<read.action> -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '{}'
   curl -s -X POST localhost:PORT/agent/v1/actions/<write.action> -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '{…}'   # expect 403 INSUFFICIENT_SCOPE
   ```
4. List the tools over MCP: `npx @abhishekvardanbotta/opendoor check http://localhost:PORT --token $T`.
5. Check that the activity log on `/opendoor` shows both calls, including the denial.
6. If the project has tests, add one that connects with a token, calls an action and checks the result belongs to the right user. The `@modelcontextprotocol/sdk` client with `StreamableHTTPClientTransport` works well.
7. For any `confirm: true` action, show that a call without `confirm` fails with `INVALID_INPUT`.

## 5. Tell the user how to connect

- **Claude:** Settings → Connectors → Add custom connector → `https://<site>/mcp`, then approve on the site.
- **ChatGPT:** Settings → Apps & Connectors → Developer mode → Create → the MCP URL with OAuth, then approve.
- **Claude Code:** `claude mcp add --transport http <name> https://<site>/mcp`, then `/mcp` to sign in.
- **Scripts:** a token from `/opendoor`, sent as a Bearer header.

Hosted assistants need a public HTTPS URL. For local testing, a tunnel (`cloudflared tunnel --url http://localhost:PORT`) plus `PUBLIC_URL` works.

## Reference

- `ctx` in `run(ctx, input)` has: `user` (`{ id, …findUser }`), `agent` (`{ id, name, kind }`), `grant` (`{ id, method }`), `scopes`, `limits`, `enforceLimit(key, amount)` and `req`.
- Built-in error codes: `INSUFFICIENT_SCOPE` (403), `INVALID_INPUT` (400), `LIMIT_EXCEEDED` (403), `RATE_LIMITED` (429), `UNKNOWN_ACTION` (404) and `INTERNAL_ERROR` (500).
- Tool names default to underscores (`orders_list`) because Claude and ChatGPT reject dots. The REST API and logs use dotted names.
- Full reference: the package README (https://github.com/abhishekvardan/opendoor). Live example: https://aishop-alpha.vercel.app.
