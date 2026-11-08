#!/usr/bin/env node
// opendoor check <site-url> [--token <bearer>]
// Verifies that a site is agent-ready the way Claude, ChatGPT and other MCP clients will see it.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const [cmd, target, ...rest] = process.argv.slice(2);
const flag = (n) => (rest.includes(n) ? rest[rest.indexOf(n) + 1] : null);
const color = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (c, s) => (color ? `\x1b[${c}m${s}\x1b[0m` : s);

if (cmd !== "check" || !target) {
  console.log(`Usage: opendoor check <site-url> [--token <access-token>]

Checks MCP discovery, OAuth metadata and the action catalog of a site using OpenDoor
(or any MCP server that follows the MCP authorization spec).`);
  process.exit(cmd ? 2 : 0);
}

const base = target.replace(/\/+$/, "").replace(/\/mcp$/, "");
let failed = 0;
const pass = (msg, detail = "") => console.log(`${paint(32, "✓")} ${msg}${detail ? paint(90, `  ${detail}`) : ""}`);
const fail = (msg, detail = "") => { failed++; console.log(`${paint(31, "✗")} ${msg}${detail ? paint(90, `  ${detail}`) : ""}`); };
const getJson = async (url, init) => {
  const r = await fetch(url, init);
  let body = null;
  try { body = await r.json(); } catch {}
  return { r, body };
};

console.log(paint(1, `\nChecking ${base}\n`));
try {
  const { r } = await getJson(`${base}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
  const www = r.headers.get("www-authenticate") ?? "";
  r.status === 401 && /resource_metadata=/.test(www)
    ? pass("MCP endpoint asks for authorization", `${base}/mcp → 401 with resource_metadata`)
    : fail("MCP endpoint should return 401 with a resource_metadata challenge", `got ${r.status}`);

  const prm = await getJson(`${base}/.well-known/oauth-protected-resource/mcp`);
  prm.r.ok && prm.body?.authorization_servers?.length
    ? pass("Protected resource metadata (RFC 9728)", `scopes: ${(prm.body.scopes_supported ?? []).join(" ")}`)
    : fail("Protected resource metadata missing", `${prm.r.status}`);

  const as = await getJson(`${(prm.body?.authorization_servers?.[0] ?? base).replace(/\/$/, "")}/.well-known/oauth-authorization-server`);
  if (as.r.ok) {
    as.body.registration_endpoint ? pass("Dynamic client registration (RFC 7591)", as.body.registration_endpoint) : fail("No registration_endpoint: hosted assistants can't self-register");
    as.body.code_challenge_methods_supported?.includes("S256") ? pass("PKCE S256 supported") : fail("PKCE S256 not advertised");
  } else fail("Authorization server metadata missing", `${as.r.status}`);

  const cat = await getJson(`${base}/agent/v1/actions`);
  if (cat.r.ok && Array.isArray(cat.body?.actions)) {
    pass(`Action catalog: ${cat.body.actions.length} actions`);
    for (const a of cat.body.actions) {
      const tags = [a.required_scope, a.read_only ? "read-only" : null, a.requires_confirmation ? "needs confirm" : null].filter(Boolean).join(", ");
      console.log(`    ${paint(36, a.name.padEnd(24))} ${paint(90, tags)}`);
    }
  } else console.log(paint(90, "  (no REST action catalog at /agent/v1/actions; fine for plain MCP servers)"));

  const llms = await fetch(`${base}/llms.txt`);
  llms.ok ? pass("llms.txt points agents to the MCP server") : console.log(paint(90, "  (no /llms.txt)"));

  const token = flag("--token");
  if (token) {
    const client = new Client({ name: "opendoor-check", version: "1.0.0" });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${token}` } } }));
    const tools = (await client.listTools()).tools;
    pass(`Token works: ${tools.length} tools visible`, tools.map((t) => t.name).join(", "));
    await client.close();
  }
} catch (err) {
  fail("Could not reach the site", err.message);
}
console.log(failed ? paint(31, `\n${failed} check(s) failed\n`) : paint(32, "\nAgent-ready. Add the MCP URL to Claude or ChatGPT as a custom connector.\n"));
process.exit(failed ? 1 : 0);
