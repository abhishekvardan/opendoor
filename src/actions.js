import { z } from "zod";
import { OpenDoorError } from "./security.js";

const NAME = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$/;

/**
 * Declares one thing an agent may do on your site.
 *
 *   action({
 *     name: "products.search", scope: "products:read", readOnly: true,
 *     description: "Search the catalog…",
 *     input: z.object({ query: z.string() }),
 *     run: (ctx, input) => catalog.search(input.query),   // ctx.user.id is the consenting user
 *   })
 *
 * `confirm: true` makes the agent pass `confirm: true`, for purchases and other irreversible steps.
 */
export function action(def) {
  if (!NAME.test(def.name ?? "")) throw new Error(`OpenDoor: invalid action name "${def.name}" (use lowercase dotted names like "orders.get")`);
  if (!def.scope) throw new Error(`OpenDoor: action "${def.name}" needs a scope`);
  if (typeof def.run !== "function") throw new Error(`OpenDoor: action "${def.name}" needs a run(ctx, input) function`);
  let input = def.input ?? z.object({});
  if (!(input instanceof z.ZodObject)) throw new Error(`OpenDoor: action "${def.name}" input must be z.object(…)`);
  if (def.confirm) {
    input = input.extend({ confirm: z.literal(true).describe("Must be true. Confirms the user explicitly approved this step.") });
  }
  return {
    name: def.name,
    title: def.title ?? def.name,
    description: def.description ?? "",
    scope: def.scope,
    input: input.strict(),
    readOnly: !!def.readOnly,
    destructive: !!(def.destructive || def.confirm),
    idempotent: !!(def.readOnly || def.idempotent),
    confirm: !!def.confirm,
    run: def.run,
    summarize: def.summarize,
    __opendoor: true,
  };
}

export const toolName = (name, style) => (style === "dotted" ? name : name.replace(/\./g, "_"));

export function jsonSchema(a) {
  const schema = z.toJSONSchema(a.input, { io: "input", unrepresentable: "any" });
  delete schema.$schema;
  return schema;
}

export function parseInput(a, raw) {
  const r = a.input.safeParse(raw ?? {});
  if (!r.success) {
    const issues = r.error.issues.map((i) => `${i.path.join(".") || "input"}: ${i.message}`);
    throw new OpenDoorError("INVALID_INPUT", `Invalid input for ${a.name}: ${issues.join("; ")}`, 400, { issues });
  }
  return r.data;
}

export function catalog(actions, style) {
  return actions.map((a) => ({
    name: a.name,
    mcp_tool: toolName(a.name, style),
    title: a.title,
    description: a.description,
    required_scope: a.scope,
    read_only: a.readOnly,
    destructive: a.destructive,
    requires_confirmation: a.confirm,
    input_schema: jsonSchema(a),
  }));
}

export { z };
