import express from "express";
import { normalizeLimits } from "./engine.js";
import { escapeHtml, randomId, randomToken, safeEqual, sha256, verifyPkce } from "./security.js";

/**
 * OAuth 2.1 authorization server for agents: RFC 8414 / 9728 discovery, RFC 7591 dynamic client
 * registration (the client_id becomes the Agent ID), authorization code + PKCE (S256 only),
 * single-use codes, refresh-token rotation, RFC 7009 revocation.
 */
class OAuthError extends Error {
  constructor(error, description, status = 400) {
    super(description);
    this.error = error;
    this.status = status;
  }
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);
const BANNED = new Set(["javascript:", "data:", "file:", "vbscript:", "blob:"]);

function validRedirectUri(uri) {
  let u;
  try { u = new URL(uri); } catch { return false; }
  if (u.hash) return false;
  if (u.protocol === "https:") return true;
  if (u.protocol === "http:") return LOOPBACK.has(u.hostname);
  return !BANNED.has(u.protocol) && /^[a-z][a-z0-9+.-]*:$/i.test(u.protocol); // RFC 8252 private-use schemes
}

/** Exact match, except loopback redirects may use any port (RFC 8252 §7.3). */
function redirectAllowed(registered, requested) {
  if (registered.includes(requested)) return true;
  let r;
  try { r = new URL(requested); } catch { return false; }
  if (r.protocol !== "http:" || !LOOPBACK.has(r.hostname)) return false;
  return registered.some((reg) => {
    try {
      const g = new URL(reg);
      return g.protocol === r.protocol && g.hostname === r.hostname && g.pathname === r.pathname && g.search === r.search;
    } catch { return false; }
  });
}

export const agentKind = (name) => (/claude|anthropic/i.test(name) ? "claude" : /chatgpt|openai|gpt/i.test(name) ? "chatgpt" : "custom");

function redirectWith(uri, params) {
  const u = new URL(uri);
  for (const [k, v] of Object.entries(params)) if (v != null) u.searchParams.set(k, v);
  return u.toString();
}

export function createOAuth(door) {
  const { storage, config } = door;
  const router = express.Router();
  const mcpResource = (req) => `${door.baseUrl(req)}/mcp`;

  /* Discovery */
  const protectedResource = (req, res) => res.json({
    resource: mcpResource(req),
    authorization_servers: [door.baseUrl(req)],
    scopes_supported: door.scopeNames,
    bearer_methods_supported: ["header"],
    resource_name: config.name,
  });
  router.get("/.well-known/oauth-protected-resource", protectedResource);
  router.get("/.well-known/oauth-protected-resource/mcp", protectedResource);
  const asMetadata = (req, res) => {
    const base = door.baseUrl(req);
    res.json({
      issuer: base,
      authorization_endpoint: `${base}/oauth/authorize`,
      token_endpoint: `${base}/oauth/token`,
      registration_endpoint: `${base}/oauth/register`,
      revocation_endpoint: `${base}/oauth/revoke`,
      scopes_supported: door.scopeNames,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
    });
  };
  router.get("/.well-known/oauth-authorization-server", asMetadata);
  router.get("/.well-known/oauth-authorization-server/mcp", asMetadata);

  /* Dynamic client registration */
  const registrations = new Map();
  router.post("/oauth/register", express.json({ limit: "32kb" }), async (req, res) => {
    const now = Date.now();
    const hits = (registrations.get(req.ip) ?? []).filter((t) => now - t < 3_600_000);
    if (hits.length >= 30) return res.status(429).json({ error: "too_many_requests" });
    registrations.set(req.ip, [...hits, now]);
    const body = req.body ?? {};
    const uris = Array.isArray(body.redirect_uris) ? body.redirect_uris.map(String) : [];
    if (!uris.length || uris.length > 10 || !uris.every(validRedirectUri)) {
      return res.status(400).json({ error: "invalid_redirect_uri", error_description: "redirect_uris must be https, http loopback, or private-use app schemes." });
    }
    const method = body.token_endpoint_auth_method ?? "none";
    if (!["none", "client_secret_post", "client_secret_basic"].includes(method)) {
      return res.status(400).json({ error: "invalid_client_metadata", error_description: "Unsupported token_endpoint_auth_method." });
    }
    const grantTypes = body.grant_types ?? ["authorization_code", "refresh_token"];
    if (!Array.isArray(grantTypes) || grantTypes.some((g) => !["authorization_code", "refresh_token"].includes(g))) {
      return res.status(400).json({ error: "invalid_client_metadata", error_description: "Unsupported grant_types." });
    }
    const name = String(body.client_name ?? "Unnamed agent").slice(0, 80).trim() || "Unnamed agent";
    const clientId = `agt_${randomId(12)}`;
    const secret = method === "none" ? null : randomToken("od_cs");
    await storage.createAgent({ id: clientId, name, kind: agentKind(name), registeredVia: "oauth_dcr", redirectUris: uris, clientSecretHash: secret ? sha256(secret) : null });
    res.status(201).json({
      client_id: clientId,
      ...(secret ? { client_secret: secret, client_secret_expires_at: 0 } : {}),
      client_id_issued_at: Math.floor(now / 1000),
      client_name: name,
      redirect_uris: uris,
      grant_types: grantTypes,
      response_types: ["code"],
      token_endpoint_auth_method: method,
      scope: door.scopeNames.join(" "),
    });
  });

  /**
   * Errors about client_id / redirect_uri are shown to the user and never redirected (no open
   * redirects); everything else goes back to the client.
   */
  async function validate(q, req) {
    const agent = q.client_id ? await storage.getAgent(String(q.client_id)) : null;
    if (!agent) throw Object.assign(new OAuthError("invalid_client", "Unknown client_id. The agent must register first."), { fatal: true });
    const redirectUri = String(q.redirect_uri ?? "");
    if (!redirectUri || !redirectAllowed(agent.redirect_uris, redirectUri)) {
      throw Object.assign(new OAuthError("invalid_request", "redirect_uri is not registered for this agent."), { fatal: true });
    }
    const fail = (e, d) => Object.assign(new OAuthError(e, d), { redirectUri, state: q.state });
    if (q.response_type !== "code") throw fail("unsupported_response_type", "Only response_type=code is supported.");
    if (!q.code_challenge || q.code_challenge_method !== "S256") throw fail("invalid_request", "PKCE with code_challenge_method=S256 is required.");
    if (q.resource) {
      const want = mcpResource(req);
      const got = String(q.resource).replace(/\/$/, "");
      if (got !== want && got !== door.baseUrl(req)) throw fail("invalid_target", `resource must be ${want}.`);
    }
    const requested = q.scope ? door.normalizeScopes(q.scope) : door.defaultScopes;
    if (q.scope && !requested.length) throw fail("invalid_scope", `Valid scopes: ${door.scopeNames.join(" ")}.`);
    return { agent, redirectUri, requested, state: q.state ? String(q.state) : null, codeChallenge: String(q.code_challenge), resource: q.resource ? String(q.resource) : null };
  }

  router.get("/oauth/authorize", async (req, res) => {
    try {
      await validate(req.query, req);
      res.redirect(302, `${door.consentUrl(req)}?${new URLSearchParams(req.query)}`);
    } catch (err) {
      if (err.fatal || !err.redirectUri) {
        return res.status(400).type("html").send(`<!doctype html><title>Authorization error</title>
          <body style="font-family:system-ui;padding:3rem;max-width:36rem"><h1>Can't connect this agent</h1><p>${escapeHtml(err.message)}</p></body>`);
      }
      res.redirect(302, redirectWith(err.redirectUri, { error: err.error, error_description: err.message, state: err.state }));
    }
  });

  /** Data for any consent UI (built-in page or your own). */
  async function describeRequest(query, req, user) {
    const r = await validate(query, req);
    const existing = await storage.activeGrantFor(String(user.id), r.agent.id);
    return {
      site: config.name,
      agent: { id: r.agent.id, name: r.agent.name, kind: r.agent.kind, registered_via: r.agent.registered_via, created_at: r.agent.created_at },
      redirect_host: new URL(r.redirectUri).host || r.redirectUri,
      requested_scopes: r.requested,
      scopes: config.scopes,
      limits: config.limits ?? {},
      existing_grant: existing ? { scopes: existing.scopes, limits: existing.limits } : null,
      user: { name: user.name ?? null, email: user.email ?? null },
    };
  }

  /** Records the user's decision; returns the URL to send the browser back to the agent. */
  async function decide({ params = {}, approve, scopes, limits }, req, user) {
    const r = await validate(params, req);
    const userId = String(user.id);
    if (!approve) {
      await storage.log({ userId, agentId: r.agent.id, agentName: r.agent.name, action: "auth.deny", transport: "oauth", status: "denied", resultSummary: "User denied the connection request", ip: req.ip });
      return redirectWith(r.redirectUri, { error: "access_denied", error_description: "The user denied access.", state: r.state });
    }
    // The user can narrow what the agent asked for, never widen it.
    const granted = door.normalizeScopes(scopes).filter((s) => r.requested.includes(s));
    if (!granted.length) throw new OAuthError("invalid_scope", "Select at least one permission.");
    const lim = normalizeLimits(config.limits ?? {}, limits, granted);
    const grantId = await storage.upsertGrant({ userId, agentId: r.agent.id, scopes: granted, limits: lim, method: "oauth" });
    const code = randomToken("od_code");
    await storage.saveCode({ code, grantId, agentId: r.agent.id, redirectUri: r.redirectUri, codeChallenge: r.codeChallenge, resource: r.resource });
    await storage.log({ userId, grantId, agentId: r.agent.id, agentName: r.agent.name, action: "auth.authorize", transport: "oauth", grantedScopes: granted, status: "success", resultSummary: `Granted ${granted.length} permissions via OAuth`, ip: req.ip });
    return redirectWith(r.redirectUri, { code, state: r.state, iss: door.baseUrl(req) });
  }

  /* Token endpoint */
  async function authenticateClient(req) {
    let id = req.body.client_id;
    let secret = req.body.client_secret;
    const basic = /^Basic\s+(.+)$/i.exec(req.get("authorization") ?? "");
    if (basic) [id, secret] = Buffer.from(basic[1], "base64").toString().split(":").map(decodeURIComponent);
    const agent = id ? await storage.getAgent(String(id)) : null;
    if (!agent) throw new OAuthError("invalid_client", "Unknown client.", 401);
    if (agent.client_secret_hash && !(secret && safeEqual(sha256(secret), agent.client_secret_hash))) {
      throw new OAuthError("invalid_client", "Client authentication failed.", 401);
    }
    return agent;
  }

  async function tokens(grantId) {
    const grant = await storage.getGrant(grantId);
    return {
      access_token: await storage.issueToken(grantId, "access", config.accessTokenTtl),
      token_type: "Bearer",
      expires_in: config.accessTokenTtl,
      refresh_token: await storage.issueToken(grantId, "refresh", config.refreshTokenTtl),
      scope: grant.scopes.join(" "),
    };
  }

  router.post("/oauth/token", express.urlencoded({ extended: false }), express.json(), async (req, res) => {
    res.set("Cache-Control", "no-store");
    try {
      const agent = await authenticateClient(req);
      if (req.body.grant_type === "authorization_code") {
        const { code, redirect_uri, code_verifier } = req.body;
        if (!code || !code_verifier) throw new OAuthError("invalid_request", "code and code_verifier are required.");
        const row = await storage.consumeCode(code);
        if (!row) throw new OAuthError("invalid_grant", "Authorization code is invalid or already used.");
        if (!row.fresh) throw new OAuthError("invalid_grant", "Authorization code expired.");
        if (row.agent_id !== agent.id) throw new OAuthError("invalid_grant", "Code was issued to another client.");
        if (row.redirect_uri !== redirect_uri) throw new OAuthError("invalid_grant", "redirect_uri does not match.");
        if (!verifyPkce(String(code_verifier), row.code_challenge)) throw new OAuthError("invalid_grant", "PKCE verification failed.");
        const grant = await storage.getGrant(row.grant_id);
        if (grant?.status !== "active") throw new OAuthError("invalid_grant", "Access was revoked.");
        await storage.log({ userId: grant.user_id, grantId: grant.id, agentId: agent.id, agentName: agent.name, action: "auth.token", transport: "oauth", status: "success", resultSummary: "Exchanged authorization code for tokens", ip: req.ip });
        return res.json(await tokens(row.grant_id));
      }
      if (req.body.grant_type === "refresh_token") {
        const row = await storage.consumeRefreshToken(String(req.body.refresh_token ?? ""));
        if (!row) throw new OAuthError("invalid_grant", "Refresh token is invalid, expired or already used.");
        const grant = await storage.getGrant(row.grant_id);
        if (grant.agent_id !== agent.id) throw new OAuthError("invalid_grant", "Refresh token belongs to another client.");
        if (grant.status !== "active") throw new OAuthError("invalid_grant", "Access was revoked.");
        return res.json(await tokens(row.grant_id));
      }
      throw new OAuthError("unsupported_grant_type", "Use authorization_code or refresh_token.");
    } catch (err) {
      if (!(err instanceof OAuthError)) {
        console.error("[opendoor] token endpoint:", err);
        return res.status(500).json({ error: "server_error" });
      }
      if (err.status === 401) res.set("WWW-Authenticate", "Basic");
      res.status(err.status).json({ error: err.error, error_description: err.message });
    }
  });

  router.post("/oauth/revoke", express.urlencoded({ extended: false }), express.json(), async (req, res) => {
    try {
      await authenticateClient(req);
    } catch {
      return res.status(401).json({ error: "invalid_client" });
    }
    if (req.body.token) await storage.revokeToken(req.body.token);
    res.status(200).end();
  });

  return { router, describeRequest, decide, OAuthError };
}
