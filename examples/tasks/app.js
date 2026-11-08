// An ordinary, pre-existing web app: server-rendered task list with its own cookie login.
// Everything between the OPENDOOR markers is all it takes to make it agent-ready.
import crypto from "node:crypto";
import express from "express";

const USERS = [{ id: 1, email: "sam@example.com", password: "tasks-demo", name: "Sam" }];
const sessions = new Map();
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

export async function createTasksApp({ db, openDoor, action, z }) {
  await db.query(`CREATE TABLE IF NOT EXISTS tasks (
    id serial PRIMARY KEY, user_id integer NOT NULL, title text NOT NULL, done boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now())`);
  const tasks = {
    list: async (userId, { done } = {}) =>
      (await db.query(`SELECT id, title, done, created_at FROM tasks WHERE user_id = $1 ${done == null ? "" : `AND done = ${done ? "true" : "false"}`} ORDER BY id`, [userId])).rows,
    create: async (userId, title) => (await db.query("INSERT INTO tasks (user_id, title) VALUES ($1,$2) RETURNING id, title, done", [userId, title])).rows[0],
    complete: async (userId, id) => {
      const row = (await db.query("UPDATE tasks SET done = true WHERE id = $1 AND user_id = $2 RETURNING id, title, done", [id, userId])).rows[0];
      if (!row) throw Object.assign(new Error(`No task ${id}.`), { code: "TASK_NOT_FOUND", status: 404 });
      return row;
    },
    remove: async (userId, id) => (await db.query("DELETE FROM tasks WHERE id = $1 AND user_id = $2", [id, userId])).rowCount > 0,
  };

  const app = express();
  app.use(express.urlencoded({ extended: false }));
  // The app's existing session handling.
  app.use((req, _res, next) => {
    const sid = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie ?? "")?.[1];
    req.user = sid ? sessions.get(sid) ?? null : null;
    next();
  });

  app.get("/login", (req, res) => res.send(`<h1>Sign in</h1><form method="post"><input type="hidden" name="next" value="${esc(req.query.next ?? "/")}">
    <input name="email" value="sam@example.com"> <input name="password" type="password"> <button>Sign in</button></form>`));
  app.post("/login", (req, res) => {
    const u = USERS.find((x) => x.email === req.body.email && x.password === req.body.password);
    if (!u) return res.status(401).send("Wrong email or password");
    const sid = crypto.randomBytes(24).toString("base64url");
    sessions.set(sid, { id: u.id, name: u.name, email: u.email });
    res.set("Set-Cookie", `sid=${sid}; HttpOnly; SameSite=Lax; Path=/`);
    const next = String(req.body.next ?? "/");
    res.redirect(next.startsWith("/") && !next.startsWith("//") ? next : "/");
  });
  app.get("/", async (req, res) => {
    if (!req.user) return res.redirect("/login");
    const rows = await tasks.list(req.user.id);
    res.send(`<h1>${esc(req.user.name)}'s tasks</h1><ul>${rows.map((t) => `<li>${t.done ? "✓" : "○"} ${esc(t.title)}</li>`).join("")}</ul>
      <form method="post" action="/tasks"><input name="title"><button>Add</button></form><p><a href="/opendoor">Connected AI agents</a></p>`);
  });
  app.post("/tasks", async (req, res) => {
    if (!req.user) return res.redirect("/login");
    await tasks.create(req.user.id, String(req.body.title ?? "").slice(0, 200));
    res.redirect("/");
  });

  // ─── OPENDOOR ──────────────────────────────────────────────────────────────────────────
  const door = openDoor({
    name: "Tasks",
    db,
    getUser: (req) => req.user,
    findUser: (id) => USERS.find((u) => String(u.id) === String(id)),
    loginUrl: (next) => `/login?next=${encodeURIComponent(next)}`,
    scopes: {
      "tasks:read": { label: "View your tasks", description: "List tasks and their status." },
      "tasks:write": { label: "Add and complete tasks", description: "Create tasks and mark them done.", risk: "medium" },
      "tasks:delete": { label: "Delete tasks", description: "Permanently delete tasks.", risk: "high" },
    },
    actions: [
      action({ name: "tasks.list", scope: "tasks:read", readOnly: true, description: "List the user's tasks.",
        input: z.object({ done: z.boolean().optional().describe("Filter by completion") }),
        run: async (ctx, { done }) => ({ tasks: await tasks.list(ctx.user.id, { done }) }),
        summarize: (r) => `${r.tasks.length} tasks` }),
      action({ name: "tasks.create", scope: "tasks:write", description: "Add a task.",
        input: z.object({ title: z.string().min(1).max(200) }),
        run: (ctx, { title }) => tasks.create(ctx.user.id, title),
        summarize: (r) => `created #${r.id} "${r.title}"` }),
      action({ name: "tasks.complete", scope: "tasks:write", idempotent: true, description: "Mark a task as done.",
        input: z.object({ id: z.number().int() }),
        run: (ctx, { id }) => tasks.complete(ctx.user.id, id) }),
      action({ name: "tasks.delete", scope: "tasks:delete", confirm: true, description: "Delete a task permanently.",
        input: z.object({ id: z.number().int() }),
        run: async (ctx, { id }) => ({ deleted: await tasks.remove(ctx.user.id, id) }) }),
    ],
  });
  app.use(door.router);
  // ─── /OPENDOOR ─────────────────────────────────────────────────────────────────────────

  return { app, door, sessions, USERS };
}
