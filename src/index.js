import express from "express";
import { action, catalog } from "./actions.js";
import { createEngine } from "./engine.js";
import { createStorage } from "./storage.js";
import { createOAuth } from "./oauth.js";
import { createActionApi, createManagementApi } from "./api.js";
import { mcpHandler } from "./mcp.js";
import { consentPage, dashboardPage } from "./pages.js";

export { action } from "./actions.js";
export { z } from "zod";
export { OpenDoorError } from "./security.js";

const trim = (v) => (v ? String(v).replace(/\/+$/, "") : null);

/**
 * Opens your existing website to AI agents.
 *
 *   const door = openDoor({
 *     name: "Acme Store",
 *     db: pool,                                   // pg Pool / PGlite: OpenDoor creates opendoor_* tables
 *     getUser: (req) => req.user,                 // your existing sign-in → { id, name?, email? }
 *     loginUrl: (returnTo) => `/login?next=${encodeURIComponent(returnTo)}`,
 *     scopes: { "orders:read": { label: "View your orders", description: "…" } },
 *     actions: [ action({ name: "orders.list", scope: "orders:read", run: (ctx) => orders.list(ctx.user.id) }) ],
 *   });
 *   app.use(door.router);                         // after your session middleware
 *
 * That mounts: /mcp, /oauth/*, /.well-known/*, /agent/v1/*, /llms.txt, and the consent screen and
 * agent dashboard at /opendoor (with a JSON API at /opendoor/api for building your own UI).
 */
export function openDoor(options) {
  const config = {
    toolNames: "underscore",
    basePath: "/opendoor",
    accessTokenTtl: 3600,
    refreshTokenTtl: 30 * 86400,
    llmsTxt: true,
    limits: {},
    ...options,
  };
  for (const k of ["name", "db", "getUser", "scopes", "actions"]) {
    if (!config[k]) throw new Error(`OpenDoor: missing required option "${k}"`);
  }
  config.slug ??= config.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "site";
  config.basePath = trim(config.basePath) || "";

  const actions = config.actions.map((a) => (a.__opendoor ? a : action(a)));
  const scopeNames = Object.keys(config.scopes);
  for (const a of actions) {
    if (!scopeNames.includes(a.scope)) throw new Error(`OpenDoor: action "${a.name}" uses unknown scope "${a.scope}"`);
  }
  for (const [k, d] of Object.entries(config.limits)) {
    if (d.scope && !scopeNames.includes(d.scope)) throw new Error(`OpenDoor: limit "${k}" uses unknown scope "${d.scope}"`);
  }

  const storage = createStorage(config.db);
  let migrated = null;
  const ready = () => (migrated ??= storage.migrate().catch((err) => { migrated = null; throw err; }));

  const door = {
    config,
    storage,
    actions,
    actionMap: new Map(actions.map((a) => [a.name, a])),
    scopeNames,
    defaultScopes: config.defaultScopes ?? scopeNames.filter((s) => config.scopes[s].risk !== "high"),
    apiBase: `${config.basePath}/api`,
    normalizeScopes(list) {
      const arr = Array.isArray(list) ? list : String(list ?? "").split(/[\s,]+/);
      return [...new Set(arr.filter((s) => scopeNames.includes(s)))];
    },
    baseUrl(req) {
      const pub = typeof config.publicUrl === "function" ? config.publicUrl(req) : config.publicUrl;
      return trim(pub) || `${req.protocol}://${req.get("host")}`;
    },
    /** Where browser pages live (your app may serve them from another origin in development). */
    appUrl(req) {
      const app = typeof config.appUrl === "function" ? config.appUrl(req) : config.appUrl;
      return trim(app) || door.baseUrl(req);
    },
    consentUrl(req) {
      return `${door.appUrl(req)}${config.consentPath ?? `${config.basePath}/authorize`}`;
    },
    meta(req) {
      const base = door.baseUrl(req);
      return {
        site: config.name,
        base_url: base,
        mcp_url: `${base}/mcp`,
        rest_actions_url: `${base}/agent/v1/actions`,
        oauth_metadata_url: `${base}/.well-known/oauth-authorization-server`,
        protected_resource_metadata_url: `${base}/.well-known/oauth-protected-resource/mcp`,
        dashboard_url: `${door.appUrl(req)}${config.dashboardPath ?? config.basePath}`,
        mcp_tool_names: config.toolNames,
        scopes: config.scopes,
        default_scopes: door.defaultScopes,
        limits: config.limits,
        actions: catalog(actions, config.toolNames),
      };
    },
  };
  door.instructions = config.instructions ?? defaultInstructions(config, actions);
  door.engine = createEngine(door);
  const oauth = createOAuth(door);

  const router = express.Router();
  router.use(async (_req, _res, next) => {
    try {
      await ready();
      next();
    } catch (err) {
      next(err);
    }
  });
  // Agent-facing endpoints are called cross-origin with bearer tokens (never cookies).
  router.use(["/mcp", "/oauth", "/.well-known", "/agent"], (req, res, next) => {
    res.set({
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID, X-Agent-Id",
      "Access-Control-Expose-Headers": "WWW-Authenticate, Mcp-Session-Id, Mcp-Protocol-Version",
    });
    if (req.method === "OPTIONS") return res.status(204).end();
    next();
  });
  router.post("/mcp", express.json({ limit: "256kb" }), mcpHandler(door));
  router.all("/mcp", mcpHandler(door));
  router.use(oauth.router);
  router.use("/agent/v1", createActionApi(door));
  if (config.llmsTxt) router.get("/llms.txt", (req, res) => res.type("text/plain").send(llmsTxt(door, req)));
  router.use(door.apiBase, createManagementApi(door, oauth));

  const pageGuard = (render) => async (req, res, next) => {
    try {
      const user = await config.getUser(req);
      if (!user?.id) {
        const returnTo = req.originalUrl;
        const login = config.loginUrl ? config.loginUrl(returnTo) : null;
        return login ? res.redirect(302, login) : res.status(401).send("Please sign in first.");
      }
      res.set({ "X-Frame-Options": "DENY", "Content-Security-Policy": "frame-ancestors 'none'", "Cache-Control": "no-store" });
      res.type("html").send(render(door, req));
    } catch (err) {
      next(err);
    }
  };
  if (config.pages !== false) {
    router.get(`${config.basePath}/authorize`, pageGuard(consentPage));
    router.get(config.basePath || "/", pageGuard(dashboardPage));
  }

  return {
    router,
    /** Creates OpenDoor's tables now instead of on the first request. */
    migrate: ready,
    actions,
    /** Run an action directly (tests, scripts) as if `ctx` were an authenticated agent. */
    execute: (ctx, name, input) => door.engine.execute(ctx, name, input, { transport: "direct", ip: null, req: null }),
    meta: door.meta,
  };
}

function defaultInstructions(config, actions) {
  return `${config.name} exposes these tools on behalf of one signed-in user who connected you and granted specific permissions.
Only the tools you were granted are listed. If a tool returns INSUFFICIENT_SCOPE or LIMIT_EXCEEDED, tell the user and do not retry.
Tools marked as requiring confirmation need explicit user approval first; then pass confirm: true.
Tool names use "_" where actions use "." (e.g. ${actions[0]?.name.replace(/\./g, "_") ?? "orders_list"} = ${actions[0]?.name ?? "orders.list"}).`;
}

function llmsTxt(door, req) {
  const m = door.meta(req);
  return `# ${door.config.name}

> This site can be operated by AI agents on behalf of a user, with the user's consent.

Use the MCP server or REST action API instead of scraping pages.

- MCP server (Streamable HTTP): ${m.mcp_url}
- OAuth 2.1 metadata: ${m.oauth_metadata_url} (dynamic client registration + PKCE)
- REST actions: GET ${m.rest_actions_url}, POST ${m.rest_actions_url}/{name} with "Authorization: Bearer <token>"
- Users manage connected agents at ${m.dashboard_url}

## Actions
${door.actions.map((a) => `- ${a.name} (${a.scope}): ${a.description}`).join("\n")}
`;
}
