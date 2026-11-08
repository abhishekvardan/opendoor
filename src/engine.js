import { parseInput } from "./actions.js";
import { OpenDoorError, rateLimiter, toPublicError } from "./security.js";

export const formatters = {
  usd_cents: (v) => `$${(v / 100).toFixed(2)}`,
  number: (v) => String(v),
};
export const formatLimit = (def, v) => (formatters[def?.format] ?? formatters.number)(v);

/** Keeps only configured limits whose scope was granted, as non-negative integers (null = no limit). */
export function normalizeLimits(limitDefs, raw, scopes) {
  const out = {};
  for (const [key, def] of Object.entries(limitDefs)) {
    if (def.scope && !scopes.includes(def.scope)) continue;
    const v = raw?.[key];
    if (v === null || v === undefined || v === "") continue;
    const n = Math.floor(Number(v));
    if (!Number.isFinite(n) || n < 0) throw new OpenDoorError("INVALID_LIMIT", `Invalid value for ${def.label ?? key}.`);
    out[key] = n;
  }
  return out;
}

export function createEngine(door) {
  const { storage, config, actionMap } = door;
  const limited = rateLimiter(config.rateLimit?.perMinute ?? 60);

  function contextFromGrant(row, user) {
    return {
      user: user ?? { id: row.user_id },
      userId: row.user_id,
      agent: { id: row.agent_id, name: row.agent_name, kind: row.agent_kind },
      grant: { id: row.id, method: row.method },
      scopes: row.scopes.filter((s) => door.scopeNames.includes(s)),
      limits: row.limits ?? {},
    };
  }

  /**
   * Resolves `Authorization: Bearer …` to the consenting user, the agent and its grant. Scopes and
   * limits are read from the grant on every request, so edits and revocations apply immediately.
   */
  async function authenticate(req) {
    const m = /^Bearer\s+(\S+)$/i.exec(req.get("authorization") ?? "");
    if (!m) return { ok: false, code: "missing_token", message: "Send an access token as 'Authorization: Bearer <token>'." };
    const row = await storage.grantForAccessToken(m[1]);
    if (!row) return { ok: false, code: "invalid_token", message: "The access token is invalid, expired or revoked." };
    if (row.status !== "active") return { ok: false, code: "invalid_token", message: "This agent's access has been revoked." };
    const claimed = req.get("x-agent-id");
    if (claimed && claimed !== row.agent_id) {
      return { ok: false, code: "invalid_token", message: "X-Agent-Id does not match the agent this token was issued to." };
    }
    const user = config.findUser ? await config.findUser(row.user_id) : null;
    return { ok: true, ctx: contextFromGrant(row, user ? { ...user, id: row.user_id } : null) };
  }

  /** Every agent call goes through here, whatever the transport. Every outcome is logged. */
  async function execute(ctx, name, rawInput, { transport, ip, req }) {
    const started = Date.now();
    const a = actionMap.get(name);
    const base = {
      userId: ctx.userId, grantId: ctx.grant.id, agentId: ctx.agent.id, agentName: ctx.agent.name, action: name, transport,
      requiredScope: a?.scope, grantedScopes: ctx.scopes, input: rawInput, ip,
    };
    const fail = async (err) => {
      const status = [401, 403, 429].includes(err.status) ? "denied" : "error";
      await storage.log({ ...base, status, errorCode: err.code, errorMessage: err.message, durationMs: Date.now() - started });
      throw err;
    };

    if (!a) return fail(new OpenDoorError("UNKNOWN_ACTION", `Unknown action "${name}".`, 404));
    if (limited(ctx.grant.id)) return fail(new OpenDoorError("RATE_LIMITED", "Too many calls; slow down.", 429));
    if (!ctx.scopes.includes(a.scope)) {
      return fail(new OpenDoorError("INSUFFICIENT_SCOPE",
        `${name} requires the "${a.scope}" permission, which the user has not granted to this agent. Ask the user to grant it on ${config.name}.`, 403));
    }
    let input;
    try {
      input = parseInput(a, rawInput);
      const runCtx = {
        ...ctx,
        req,
        /** Throws LIMIT_EXCEEDED if `amount` is above the limit the user set for this agent. */
        enforceLimit(key, amount) {
          const max = ctx.limits[key];
          if (max != null && amount > max) {
            const def = config.limits?.[key];
            throw new OpenDoorError("LIMIT_EXCEEDED",
              `${formatLimit(def, amount)} exceeds the ${def?.label?.toLowerCase() ?? key} of ${formatLimit(def, max)} the user set for this agent.`, 403);
          }
        },
      };
      const result = await a.run(runCtx, input);
      await storage.log({ ...base, input, status: "success", resultSummary: safeSummary(a, result, input), durationMs: Date.now() - started });
      storage.touchGrant(ctx.grant.id).catch(() => {});
      return result ?? { ok: true };
    } catch (err) {
      const e = toPublicError(err);
      if (e.status >= 500) console.error(`[opendoor] ${name} failed:`, err);
      return fail(e);
    }
  }

  return { authenticate, execute, contextFromGrant };
}

function safeSummary(a, result, input) {
  try {
    return a.summarize?.(result, input) ?? null;
  } catch {
    return null;
  }
}
