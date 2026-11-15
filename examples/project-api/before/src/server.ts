import express from "express";
import { requireAuth } from "./middleware/auth";
import projects from "./routes/projects";
import admin from "./routes/admin";

const app = express();
app.use(express.json());

// The admin router is protected here, once, which is why nothing inside it
// bothers to check anything.
app.use("/api/admin", requireAuth);

app.use("/api/projects", projects);
app.use("/api/admin", admin);

// Left in after the incident last March.
app.get("/debug/dump", async (req, res) => {
  const users = await db.user.findMany();
  res.json(users);
});

app.post("/login", async (req, res) => {
  const user = await db.user.findUnique({ where: { email: req.body.email } });
  res.json({ token: sign(user) });
});

export default app;
