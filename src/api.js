import express from "express";
import { z } from "zod";
import { catalog } from "./actions.js";
import { formatLimit, normalizeLimits } from "./engine.js";
import { OpenDoorError, toPublicError } from "./security.js";

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const AGENT_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/;

/**
 * JSON API behind the consent screen and the "connected agents" dashboard, at {basePath}/api.
 * Uses your site's own sign-in through config.getUser(req). Writes must be JSON, which a
 * cross-site form cannot send (CSRF defence alongside your cookie's SameSite setting).
 */
export function createManagementApi(door, oauth) {
  const { storage, config } = door;
  const router = express.Router();
  router.use(express.json({ limit: "64kb" }));
  router.use((req, res, next) => {
    if (["POST", "PATCH", "PUT", "DELETE"].includes(req.method) && !req.is("application/json")) {
      return res.status(415).json({ error: { code: "UNSUPPORTED_MEDIA_TYPE", message: "Send JSON." } });
    }
    next();
  });
  const requireUser = wrap(async (req, res, next) => {
    const user = await config.getUser(req);
    if (!user?.id) return res.status(401).json({ error: { code: "UNAUTHENTICATED", message: "Please sign in." } });
    req.opendoorUser = { ...user, id: String(user.id) };
    next();
  });

  router.get("/meta", (req, res) => res.json(door.meta(req)));

  const toGrant = (g) => ({
    id: g.id,
    status: g.status,
    method: g.method,
    scopes: g.scopes,
    limits: g.limits ?? {},
    limits_display: Object.fromEntries(Object.entries(g.limits ?? {}).map(([k, v]) => [k, formatLimit(config.limits?.[k], v)])),
    created_at: g.created_at,
    updated_at: g.updated_at,
    revoked_at: g.revoked_at,
    last_used_at: g.last_used_at,
    agent: { id: g.agent_id, name: g.agent_name, kind: g.agent_kind, registered_via: g.registered_via },
    active_tokens: g.active_tokens ?? 0,
    token_expires_at: g.token_expires_at ?? null,
    calls_24h: g.calls_24h ?? 0,
  });

  router.get("/grants", requireUser, wrap(async (req, res) => res.json({ grants: (await storage.listGrants(req.opendoorUser.id)).map(toGrant) })));

  const settings = z.object({
    scopes: z.array(z.string()).min(1, "Select at least one permission"),
    limits: z.record(z.string(), z.number().int().min(0).nullable()).optional(),
  });

  router.post("/connect", requireUser, wrap(async (req, res) => {
    const parsed = settings.extend({
      agent_id: z.string().trim().regex(AGENT_ID, "Agent ID must be 3–64 characters: letters, numbers, dot, dash or underscore"),
      name: z.string().trim().min(1).max(80),
      kind: z.enum(["claude", "chatgpt", "custom"]).default("custom"),
      expires_in_days: z.number().int().min(1).max(365).default(30),
      consent: z.literal(true, { error: "You must confirm consent" }),
    }).safeParse(req.body);
    if (!parsed.success) throw new OpenDoorError("INVALID_INPUT", parsed.error.issues.map((i) => i.message).join("; "));
    const b = parsed.data;
    const user = req.opendoorUser;
    const scopes = door.normalizeScopes(b.scopes);
    if (!scopes.length) throw new OpenDoorError("INVALID_INPUT", "Select at least one valid permission.");
    const existing = await storage.getAgent(b.agent_id);
    if (existing && !(existing.registered_via === "manual" && existing.created_by === user.id)) {
      throw new OpenDoorError("AGENT_ID_TAKEN", "That Agent ID is already registered by someone else. Choose a different one.", 409);
    }
    if (existing) await storage.renameAgent(b.agent_id, b.name, b.kind);
    else await storage.createAgent({ id: b.agent_id, name: b.name, kind: b.kind, registeredVia: "manual", createdBy: user.id });
    const limits = normalizeLimits(config.limits ?? {}, b.limits, scopes);
    const grantId = await storage.upsertGrant({ userId: user.id, agentId: b.agent_id, scopes, limits, method: "token" });
    const token = await storage.issueToken(grantId, "access", b.expires_in_days * 86400);
    await storage.log({ userId: user.id, grantId, agentId: b.agent_id, agentName: b.name, action: "auth.connect", transport: "web", grantedScopes: scopes, status: "success", resultSummary: `Connected with an access token valid for ${b.expires_in_days} days`, ip: req.ip });
    const meta = door.meta(req);
    res.status(201).json({ grant_id: grantId, agent_id: b.agent_id, access_token: token, expires_in_days: b.expires_in_days, mcp_url: meta.mcp_url, rest_actions_url: meta.rest_actions_url });
  }));

  async function ownGrant(req) {
    const g = await storage.getGrant(req.params.id);
    if (!g || g.user_id !== req.opendoorUser.id) throw new OpenDoorError("NOT_FOUND", "Connection not found.", 404);
    return g;
  }

  router.patch("/grants/:id", requireUser, wrap(async (req, res) => {
    const g = await ownGrant(req);
    if (g.status !== "active") throw new OpenDoorError("REVOKED", "This connection was revoked. Connect the agent again.", 409);
    const parsed = settings.safeParse(req.body);
    if (!parsed.success) throw new OpenDoorError("INVALID_INPUT", parsed.error.issues.map((i) => i.message).join("; "));
    const scopes = door.normalizeScopes(parsed.data.scopes);
    if (!scopes.length) throw new OpenDoorError("INVALID_INPUT", "Select at least one valid permission.");
    const limits = normalizeLimits(config.limits ?? {}, parsed.data.limits, scopes);
    await storage.updateGrant(g.id, { scopes, limits });
    const lim = Object.entries(limits).map(([k, v]) => `${config.limits[k]?.label ?? k} ${formatLimit(config.limits[k], v)}`).join(", ");
    await storage.log({ userId: g.user_id, grantId: g.id, agentId: g.agent_id, agentName: g.agent_name, action: "auth.update", transport: "web", grantedScopes: scopes, status: "success", resultSummary: `Permissions set to ${scopes.join(", ")}${lim ? `; ${lim}` : ""}`, ip: req.ip });
    res.json({ ok: true });
  }));

  router.post("/grants/:id/token", requireUser, wrap(async (req, res) => {
    const g = await ownGrant(req);
    if (g.status !== "active") throw new OpenDoorError("REVOKED", "This connection was revoked.", 409);
    if (g.method !== "token") throw new OpenDoorError("OAUTH_GRANT", "This agent connected with OAuth and refreshes its own tokens.", 409);
    const days = Math.min(Math.max(Number(req.body?.expires_in_days) || 30, 1), 365);
    await storage.revokeTokens(g.id);
    const token = await storage.issueToken(g.id, "access", days * 86400);
    await storage.log({ userId: g.user_id, grantId: g.id, agentId: g.agent_id, agentName: g.agent_name, action: "auth.rotate", transport: "web", grantedScopes: g.scopes, status: "success", resultSummary: `Old tokens revoked; new token valid for ${days} days`, ip: req.ip });
    res.json({ access_token: token, expires_in_days: days, agent_id: g.agent_id, mcp_url: door.meta(req).mcp_url });
  }));

  router.post("/grants/:id/revoke", requireUser, wrap(async (req, res) => {
    const g = await ownGrant(req);
    await storage.revokeGrant(g.id);
    await storage.log({ userId: g.user_id, grantId: g.id, agentId: g.agent_id, agentName: g.agent_name, action: "auth.revoke", transport: "web", status: "success", resultSummary: "Access revoked; all tokens invalidated", ip: req.ip });
    res.json({ ok: true });
  }));

  router.get("/activity", requireUser, wrap(async (req, res) => {
    const q = req.query;
    res.json(await storage.activity(req.opendoorUser.id, { agentId: q.agent_id, status: q.status, kind: q.kind, before: q.before, limit: q.limit }));
  }));

  router.get("/oauth/request", requireUser, wrap(async (req, res) => {
    try {
      res.json(await oauth.describeRequest(req.query, req, req.opendoorUser));
    } catch (err) {
      res.status(400).json({ error: { code: err.error ?? "invalid_request", message: err.message } });
    }
  }));

  router.post("/oauth/consent", requireUser, wrap(async (req, res) => {
    try {
      res.json({ redirect: await oauth.decide(req.body ?? {}, req, req.opendoorUser) });
    } catch (err) {
      if (err instanceof oauth.OAuthError || err instanceof OpenDoorError) {
        return res.status(400).json({ error: { code: err.error ?? err.code, message: err.message } });
      }
      throw err;
    }
  }));

  // eslint-disable-next-line no-unused-vars
  router.use((err, _req, res, _next) => {
    const e = toPublicError(err);
    if (e.status >= 500) console.error("[opendoor] api:", err);
    res.status(e.status).json({ error: { code: e.code, message: e.message } });
  });
  return router;
}

/** REST twin of the MCP server: GET /agent/v1/actions, POST /agent/v1/actions/{name}. */
export function createActionApi(door) {
  const router = express.Router();
  router.get("/actions", (_req, res) => res.json({ actions: catalog(door.actions, door.config.toolNames) }));
  const unauthorized = (req, res, a) =>
    res.status(401)
      .set("WWW-Authenticate", `Bearer realm="${door.config.slug}", error="invalid_token", resource_metadata="${door.baseUrl(req)}/.well-known/oauth-protected-resource/mcp"`)
      .json({ ok: false, error: { code: a.code.toUpperCase(), message: a.message } });
  router.get("/me", wrap(async (req, res) => {
    const a = await door.engine.authenticate(req);
    if (!a.ok) return unauthorized(req, res, a);
    res.json({ agent: a.ctx.agent, scopes: a.ctx.scopes, limits: a.ctx.limits });
  }));
  router.post("/actions/:name", express.json({ limit: "64kb" }), wrap(async (req, res) => {
    const a = await door.engine.authenticate(req);
    if (!a.ok) return unauthorized(req, res, a);
    try {
      const result = await door.engine.execute(a.ctx, req.params.name, req.body ?? {}, { transport: "rest", ip: req.ip, req });
      res.json({ ok: true, action: req.params.name, result });
    } catch (err) {
      const e = toPublicError(err);
      res.status(e.status).json({ ok: false, action: req.params.name, error: { code: e.code, message: e.message, details: e.details } });
    }
  }));
  return router;
}
