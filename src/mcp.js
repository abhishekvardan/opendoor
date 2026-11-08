import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { jsonSchema, toolName } from "./actions.js";
import { toPublicError } from "./security.js";

function buildServer(door, ctx, req) {
  const { config, actions } = door;
  const style = config.toolNames;
  const byTool = new Map(actions.map((a) => [toolName(a.name, style), a]));
  const server = new Server(
    { name: config.slug, title: config.name, version: config.version ?? "1.0.0" },
    { capabilities: { tools: {} }, instructions: door.instructions },
  );

  // Advertise only what this agent may use; every call is still checked individually.
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: actions.filter((a) => ctx.scopes.includes(a.scope)).map((a) => ({
      name: toolName(a.name, style),
      title: a.title,
      description: `${a.description}${a.confirm ? " Requires confirm: true after the user approves." : ""} (requires ${a.scope})`,
      inputSchema: jsonSchema(a),
      annotations: { title: a.title, readOnlyHint: a.readOnly, destructiveHint: a.destructive, idempotentHint: a.idempotent, openWorldHint: false },
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const name = byTool.get(request.params.name)?.name ?? request.params.name;
    try {
      const result = await door.engine.execute(ctx, name, request.params.arguments ?? {}, { transport: "mcp", ip: req.ip, req });
      const structured = result && typeof result === "object" && !Array.isArray(result) ? result : { result };
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }], structuredContent: structured };
    } catch (err) {
      const e = toPublicError(err);
      return { isError: true, content: [{ type: "text", text: JSON.stringify({ error: { code: e.code, message: e.message } }) }] };
    }
  });
  return server;
}

/** Stateless Streamable HTTP: each POST carries its own bearer token. */
export function mcpHandler(door) {
  return async (req, res) => {
    if (req.method !== "POST") {
      return res.set("Allow", "POST").status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Send MCP JSON-RPC requests with POST." }, id: null });
    }
    const authn = await door.engine.authenticate(req);
    if (!authn.ok) {
      const base = door.baseUrl(req);
      return res
        .status(401)
        .set("WWW-Authenticate",
          `Bearer realm="${door.config.slug}", error="${authn.code === "missing_token" ? "invalid_request" : "invalid_token"}", error_description="${authn.message}", resource_metadata="${base}/.well-known/oauth-protected-resource/mcp"`)
        .json({ jsonrpc: "2.0", error: { code: -32001, message: authn.message }, id: req.body?.id ?? null });
    }
    const server = buildServer(door, authn.ctx, req);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on("close", () => {
      transport.close();
      server.close();
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      console.error("[opendoor] MCP error:", err);
      if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal error" }, id: null });
    }
  };
}
