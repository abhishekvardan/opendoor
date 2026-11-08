import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { PGlite } from "@electric-sql/pglite";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { openDoor, action, z } from "../src/index.js";
import { createTasksApp } from "../examples/tasks/app.js";

let server, base, cookie, pg;

before(async () => {
  pg = new PGlite();
  const { app } = await createTasksApp({ db: pg, openDoor, action, z });
  server = app.listen(0);
  await new Promise((r) => server.once("listening", r));
  base = `http://localhost:${server.address().port}`;
  const res = await fetch(`${base}/login`, {
    method: "POST", redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "email=sam%40example.com&password=tasks-demo",
  });
  cookie = res.headers.get("set-cookie").split(";")[0];
});
after(async () => {
  server?.close();
  await pg?.close();
});

const api = async (path, method = "GET", body) => {
  const r = await fetch(base + "/opendoor/api" + path, { method, headers: { cookie, ...(body ? { "content-type": "application/json" } : {}) }, body: body && JSON.stringify(body) });
  return { status: r.status, body: await r.json().catch(() => null) };
};
async function mcp(token) {
  const c = new Client({ name: "t", version: "1" });
  await c.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${token}` } } }));
  return c;
}
const out = (r) => JSON.parse(r.content[0].text);

test("config validation catches mistakes early", () => {
  assert.throws(() => openDoor({ name: "x" }), /missing required option "db"/);
  assert.throws(() => openDoor({ name: "x", db: pg, getUser: () => null, scopes: { a: {} }, actions: [{ name: "x.y", scope: "b", run() {} }] }), /unknown scope "b"/);
  assert.throws(() => action({ name: "Bad Name", scope: "a", run() {} }), /invalid action name/);
});

test("discovery: 401 challenge, protected-resource and authorization-server metadata, llms.txt", async () => {
  const r = await fetch(`${base}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  assert.equal(r.status, 401);
  assert.match(r.headers.get("www-authenticate"), /resource_metadata="http:\/\/localhost:\d+\/.well-known\/oauth-protected-resource\/mcp"/);
  const prm = await (await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)).json();
  assert.deepEqual(prm.scopes_supported, ["tasks:read", "tasks:write", "tasks:delete"]);
  const as = await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json();
  assert.deepEqual(as.code_challenge_methods_supported, ["S256"]);
  assert.match(await (await fetch(`${base}/llms.txt`)).text(), /tasks\.create \(tasks:write\)/);
});

test("built-in pages need the site's own sign-in", async () => {
  const anon = await fetch(`${base}/opendoor`, { redirect: "manual" });
  assert.equal(anon.status, 302);
  assert.equal(anon.headers.get("location"), "/login?next=%2Fopendoor");
  const page = await fetch(`${base}/opendoor`, { headers: { cookie } });
  assert.equal(page.status, 200);
  assert.equal(page.headers.get("x-frame-options"), "DENY");
  assert.match(await page.text(), /Connected agents/);
});

let token, grantId;
test("token connect → MCP tools filtered by scope → actions run as the user", async () => {
  const c = await api("/connect", "POST", { agent_id: "my-script", name: "My script", scopes: ["tasks:read", "tasks:write"], consent: true });
  assert.equal(c.status, 201, JSON.stringify(c.body));
  ({ access_token: token, grant_id: grantId } = c.body);
  assert.match(token, /^od_at_/);
  const client = await mcp(token);
  const names = (await client.listTools()).tools.map((t) => t.name);
  assert.deepEqual(names, ["tasks_list", "tasks_create", "tasks_complete"]);
  const created = out(await client.callTool({ name: "tasks_create", arguments: { title: "Book flights" } }));
  assert.equal(created.title, "Book flights");
  assert.equal(out(await client.callTool({ name: "tasks_complete", arguments: { id: created.id } })).done, true);
  const missing = await client.callTool({ name: "tasks_complete", arguments: { id: 999 } });
  assert.equal(out(missing).error.code, "TASK_NOT_FOUND"); // the app's own error, surfaced safely
  const denied = await client.callTool({ name: "tasks_delete", arguments: { id: created.id, confirm: true } });
  assert.equal(out(denied).error.code, "INSUFFICIENT_SCOPE");
  await client.close();
  // The site sees the agent's work as the user's own data.
  assert.match(await (await fetch(base + "/", { headers: { cookie } })).text(), /✓ Book flights/);
});

test("confirmation is enforced for confirm: true actions", async () => {
  await api(`/grants/${grantId}`, "PATCH", { scopes: ["tasks:read", "tasks:write", "tasks:delete"] });
  const call = (body) => fetch(`${base}/agent/v1/actions/tasks.delete`, { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify(body) });
  const noConfirm = await call({ id: 1 });
  assert.equal(noConfirm.status, 400);
  assert.equal((await noConfirm.json()).error.code, "INVALID_INPUT");
  const ok = await call({ id: 1, confirm: true });
  assert.deepEqual((await ok.json()).result, { deleted: true });
});

test("activity log and revocation", async () => {
  const { body } = await api("/activity?limit=100");
  const seen = body.entries.map((e) => `${e.action}:${e.status}`);
  for (const s of ["auth.connect:success", "tasks.create:success", "tasks.delete:denied", "tasks.delete:success", "auth.update:success"]) assert.ok(seen.includes(s), s);
  await api(`/grants/${grantId}/revoke`, "POST", {});
  const r = await fetch(`${base}/agent/v1/me`, { headers: { authorization: `Bearer ${token}` } });
  assert.equal(r.status, 401);
});

test("OAuth: registration, consent narrowing, PKCE, single-use code, refresh rotation", async () => {
  const reg = await (await fetch(`${base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Claude", redirect_uris: ["https://claude.ai/api/mcp/auth_callback"] }) })).json();
  const verifier = crypto.randomBytes(32).toString("base64url");
  const params = { response_type: "code", client_id: reg.client_id, redirect_uri: reg.redirect_uris[0], state: "s1", code_challenge: crypto.createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", scope: "tasks:read tasks:write" };
  const authz = await fetch(`${base}/oauth/authorize?${new URLSearchParams(params)}`, { redirect: "manual" });
  assert.match(authz.headers.get("location"), /\/opendoor\/authorize\?/);
  const info = await api(`/oauth/request?${new URLSearchParams(params)}`);
  assert.equal(info.body.agent.kind, "claude");
  const consent = await api("/oauth/consent", "POST", { params, approve: true, scopes: ["tasks:read", "tasks:delete"] });
  const code = new URL(consent.body.redirect).searchParams.get("code");
  const exchange = (v) => fetch(`${base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: params.redirect_uri, client_id: reg.client_id, code_verifier: v }) });
  const tok = await (await exchange(verifier)).json();
  assert.equal(tok.scope, "tasks:read"); // tasks:delete was never requested, so it could not be granted
  assert.equal((await exchange(verifier)).status, 400); // single use
  const client = await mcp(tok.access_token);
  assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ["tasks_list"]);
  await client.close();
  const refresh = (rt) => fetch(`${base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: rt, client_id: reg.client_id }) });
  assert.equal((await refresh(tok.refresh_token)).status, 200);
  assert.equal((await refresh(tok.refresh_token)).status, 400);
});

test("hostile agent names are escaped on the consent page", async () => {
  const reg = await (await fetch(`${base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "<img src=x onerror=alert(1)>", redirect_uris: ["https://evil.example/cb"] }) })).json();
  const html = await (await fetch(`${base}/opendoor/authorize?client_id=${reg.client_id}`, { headers: { cookie } })).text();
  assert.ok(!html.includes("<img src=x"), "raw agent name must not be in server HTML");
  const info = await api(`/oauth/request?${new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: "https://evil.example/cb", code_challenge: "a".repeat(43), code_challenge_method: "S256" })}`);
  assert.equal(info.body.agent.name, "<img src=x onerror=alert(1)>"); // returned as data; the page escapes it when rendering
});

test("limits: generic, per-grant, enforced via ctx.enforceLimit", async () => {
  const door = openDoor({
    name: "Shop", db: pg, getUser: () => ({ id: "u1" }),
    scopes: { "checkout:create": { label: "Buy", risk: "high" } },
    limits: { spend: { label: "Per-order spending limit", scope: "checkout:create", format: "usd_cents" } },
    actions: [action({ name: "checkout.create", scope: "checkout:create", confirm: true, input: z.object({ total_cents: z.number().int() }),
      run: (ctx, { total_cents }) => { ctx.enforceLimit("spend", total_cents); return { ok: true }; } })],
  });
  await door.migrate();
  const ctx = { userId: "u1", user: { id: "u1" }, agent: { id: "a", name: "A" }, grant: { id: crypto.randomUUID() }, scopes: ["checkout:create"], limits: { spend: 30000 } };
  await assert.rejects(door.execute(ctx, "checkout.create", { total_cents: 43092, confirm: true }), (e) => e.code === "LIMIT_EXCEEDED" && /\$430\.92 exceeds the per-order spending limit of \$300\.00/.test(e.message));
  assert.deepEqual(await door.execute(ctx, "checkout.create", { total_cents: 26892, confirm: true }), { ok: true });
});
