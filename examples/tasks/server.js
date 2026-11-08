// Run: node examples/tasks/server.js  → http://localhost:4800 (sam@example.com / tasks-demo)
import { PGlite } from "@electric-sql/pglite";
import { openDoor, action, z } from "../../src/index.js";
import { createTasksApp } from "./app.js";

const port = Number(process.env.PORT) || 4800;
const { app } = await createTasksApp({ db: new PGlite(process.env.PGLITE_DIR), openDoor, action, z });
app.listen(port, () => console.log(`Tasks example on http://localhost:${port}  (sam@example.com / tasks-demo)\nAgent dashboard: http://localhost:${port}/opendoor`));
