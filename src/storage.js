import { randomToken, redact, sha256 } from "./security.js";

/**
 * OpenDoor keeps its own tables (all prefixed `opendoor_`) in your PostgreSQL database and never
 * touches yours. `db` is anything with `query(text, params) → { rows }`: a `pg` Pool, a PGlite
 * instance, or an adapter around your own client.
 */
const SCHEMA = `
CREATE TABLE IF NOT EXISTS opendoor_agents (
  id text PRIMARY KEY,
  name text NOT NULL,
  kind text NOT NULL DEFAULT 'custom',
  registered_via text NOT NULL,
  redirect_uris jsonb NOT NULL DEFAULT '[]'::jsonb,
  client_secret_hash text,
  created_by text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS opendoor_grants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id text NOT NULL,
  agent_id text NOT NULL REFERENCES opendoor_agents(id) ON DELETE CASCADE,
  scopes jsonb NOT NULL,
  limits jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'active',
  method text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  last_used_at timestamptz
);
CREATE INDEX IF NOT EXISTS opendoor_grants_user_idx ON opendoor_grants (user_id);
CREATE TABLE IF NOT EXISTS opendoor_codes (
  code_hash text PRIMARY KEY,
  grant_id uuid NOT NULL REFERENCES opendoor_grants(id) ON DELETE CASCADE,
  agent_id text NOT NULL,
  redirect_uri text NOT NULL,
  code_challenge text NOT NULL,
  resource text,
  expires_at timestamptz NOT NULL,
  used_at timestamptz
);
CREATE TABLE IF NOT EXISTS opendoor_tokens (
  token_hash text PRIMARY KEY,
  grant_id uuid NOT NULL REFERENCES opendoor_grants(id) ON DELETE CASCADE,
  kind text NOT NULL,
  display_prefix text NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS opendoor_tokens_grant_idx ON opendoor_tokens (grant_id);
CREATE TABLE IF NOT EXISTS opendoor_activity (
  id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id text,
  grant_id uuid,
  agent_id text,
  agent_name text,
  action text NOT NULL,
  transport text NOT NULL,
  required_scope text,
  granted_scopes jsonb NOT NULL DEFAULT '[]'::jsonb,
  status text NOT NULL,
  input jsonb,
  result_summary text,
  error_code text,
  error_message text,
  duration_ms integer,
  ip text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS opendoor_activity_user_idx ON opendoor_activity (user_id, id DESC);
`;

export function createStorage(db) {
  if (!db || typeof db.query !== "function") throw new Error("OpenDoor: `db` must have a query(text, params) method (pg Pool, PGlite, …).");
  const q = (text, params = []) => db.query(text, params);
  const one = async (text, params) => (await q(text, params)).rows[0] ?? null;
  const many = async (text, params) => (await q(text, params)).rows;

  const GRANT_SELECT = `SELECT g.*, a.name AS agent_name, a.kind AS agent_kind, a.registered_via
    FROM opendoor_grants g JOIN opendoor_agents a ON a.id = g.agent_id`;

  return {
    async migrate() {
      // One statement at a time: works with pg, PGlite and transaction-mode poolers alike.
      for (const stmt of SCHEMA.split(";").map((s) => s.trim()).filter(Boolean)) await q(stmt);
    },

    /* agents */
    getAgent: (id) => one("SELECT * FROM opendoor_agents WHERE id = $1", [id]),
    createAgent: ({ id, name, kind, registeredVia, redirectUris = [], clientSecretHash = null, createdBy = null }) =>
      q(`INSERT INTO opendoor_agents (id, name, kind, registered_via, redirect_uris, client_secret_hash, created_by)
         VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7)`, [id, name, kind, registeredVia, JSON.stringify(redirectUris), clientSecretHash, createdBy]),
    renameAgent: (id, name, kind) => q("UPDATE opendoor_agents SET name = $2, kind = $3 WHERE id = $1", [id, name, kind]),

    /* grants */
    async upsertGrant({ userId, agentId, scopes, limits, method }) {
      const existing = await one("SELECT id FROM opendoor_grants WHERE user_id = $1 AND agent_id = $2 AND status = 'active'", [userId, agentId]);
      if (existing) {
        await q("UPDATE opendoor_grants SET scopes = $2::jsonb, limits = $3::jsonb, method = $4, updated_at = now() WHERE id = $1",
          [existing.id, JSON.stringify(scopes), JSON.stringify(limits), method]);
        return existing.id;
      }
      return (await one(
        "INSERT INTO opendoor_grants (user_id, agent_id, scopes, limits, method) VALUES ($1,$2,$3::jsonb,$4::jsonb,$5) RETURNING id",
        [userId, agentId, JSON.stringify(scopes), JSON.stringify(limits), method],
      )).id;
    },
    getGrant: (id) => one(`${GRANT_SELECT} WHERE g.id = $1`, [id]),
    activeGrantFor: (userId, agentId) =>
      one("SELECT * FROM opendoor_grants WHERE user_id = $1 AND agent_id = $2 AND status = 'active'", [userId, agentId]),
    listGrants: (userId) => many(
      `${GRANT_SELECT.replace("SELECT g.*", `SELECT g.*,
        (SELECT count(*)::int FROM opendoor_tokens t WHERE t.grant_id = g.id AND t.revoked_at IS NULL AND t.expires_at > now()) AS active_tokens,
        (SELECT max(t.expires_at) FROM opendoor_tokens t WHERE t.grant_id = g.id AND t.revoked_at IS NULL AND t.expires_at > now()) AS token_expires_at,
        (SELECT count(*)::int FROM opendoor_activity x WHERE x.grant_id = g.id AND x.created_at > now() - interval '1 day') AS calls_24h`)}
       WHERE g.user_id = $1 ORDER BY (g.status = 'active') DESC, g.created_at DESC`, [userId]),
    updateGrant: (id, { scopes, limits }) =>
      q("UPDATE opendoor_grants SET scopes = $2::jsonb, limits = $3::jsonb, updated_at = now() WHERE id = $1", [id, JSON.stringify(scopes), JSON.stringify(limits)]),
    async revokeGrant(id) {
      await q("UPDATE opendoor_grants SET status = 'revoked', revoked_at = now(), updated_at = now() WHERE id = $1", [id]);
      await q("UPDATE opendoor_tokens SET revoked_at = now() WHERE grant_id = $1 AND revoked_at IS NULL", [id]);
    },
    touchGrant: (id) => q("UPDATE opendoor_grants SET last_used_at = now() WHERE id = $1", [id]),

    /* tokens */
    async issueToken(grantId, kind, ttlSec) {
      const raw = randomToken(kind === "refresh" ? "od_rt" : "od_at");
      await q(`INSERT INTO opendoor_tokens (token_hash, grant_id, kind, display_prefix, expires_at)
               VALUES ($1,$2,$3,$4, now() + make_interval(secs => $5))`, [sha256(raw), grantId, kind, raw.slice(0, 12), ttlSec]);
      return raw;
    },
    revokeTokens: (grantId) => q("UPDATE opendoor_tokens SET revoked_at = now() WHERE grant_id = $1 AND revoked_at IS NULL", [grantId]),
    revokeToken: (raw) => q("UPDATE opendoor_tokens SET revoked_at = now() WHERE token_hash = $1", [sha256(String(raw))]),
    grantForAccessToken: (raw) => one(
      `${GRANT_SELECT} JOIN opendoor_tokens t ON t.grant_id = g.id
       WHERE t.token_hash = $1 AND t.kind = 'access' AND t.revoked_at IS NULL AND t.expires_at > now()`, [sha256(raw)]),
    /** Single use: atomically consumes a refresh token and returns its grant id. */
    consumeRefreshToken: (raw) => one(
      `UPDATE opendoor_tokens SET revoked_at = now()
       WHERE token_hash = $1 AND kind = 'refresh' AND revoked_at IS NULL AND expires_at > now() RETURNING grant_id`, [sha256(raw)]),

    /* authorization codes */
    saveCode: ({ code, grantId, agentId, redirectUri, codeChallenge, resource }) =>
      q(`INSERT INTO opendoor_codes (code_hash, grant_id, agent_id, redirect_uri, code_challenge, resource, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6, now() + interval '10 minutes')`, [sha256(code), grantId, agentId, redirectUri, codeChallenge, resource]),
    /** Single use: the code is consumed even if the exchange later fails. */
    consumeCode: (code) => one(
      "UPDATE opendoor_codes SET used_at = now() WHERE code_hash = $1 AND used_at IS NULL RETURNING *, (expires_at > now()) AS fresh", [sha256(String(code))]),

    /* activity */
    async log(e) {
      try {
        await q(`INSERT INTO opendoor_activity (user_id, grant_id, agent_id, agent_name, action, transport, required_scope,
                   granted_scopes, status, input, result_summary, error_code, error_message, duration_ms, ip)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10::jsonb,$11,$12,$13,$14,$15)`,
        [e.userId == null ? null : String(e.userId), e.grantId ?? null, e.agentId ?? null, e.agentName ?? null, e.action, e.transport,
          e.requiredScope ?? null, JSON.stringify(e.grantedScopes ?? []), e.status,
          e.input === undefined ? null : JSON.stringify(redact(e.input)), e.resultSummary ?? null, e.errorCode ?? null,
          e.errorMessage ?? null, e.durationMs ?? null, e.ip ?? null]);
      } catch (err) {
        console.error("[opendoor] activity log write failed:", err.message);
      }
    },
    async activity(userId, { agentId, status, kind, before, limit = 50 } = {}) {
      const where = ["user_id = $1"];
      const params = [String(userId)];
      const add = (sql, v) => { params.push(v); where.push(sql.replace("?", `$${params.length}`)); };
      if (agentId) add("agent_id = ?", agentId);
      if (status) add("status = ?", status);
      if (kind === "actions") where.push("action NOT LIKE 'auth.%'");
      if (kind === "auth") where.push("action LIKE 'auth.%'");
      if (before) add("id < ?", Number(before) || 0);
      const lim = Math.min(Math.max(Number(limit) || 50, 1), 200);
      const entries = await many(`SELECT * FROM opendoor_activity WHERE ${where.join(" AND ")} ORDER BY id DESC LIMIT ${lim}`, params);
      const summary = await one(
        `SELECT count(*)::int AS total, count(*) FILTER (WHERE status = 'success')::int AS success,
           count(*) FILTER (WHERE status = 'denied')::int AS denied, count(*) FILTER (WHERE status = 'error')::int AS error,
           count(DISTINCT agent_id)::int AS agents
         FROM opendoor_activity WHERE user_id = $1 AND created_at > now() - interval '7 days'`, [String(userId)]);
      return { entries, summary, next_before: entries.length === lim ? entries.at(-1).id : null };
    },
  };
}
