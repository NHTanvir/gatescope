import express from "express";
import rateLimit from "express-rate-limit";
import { requireAuth } from "./middleware/auth";
import projects from "./routes/projects";
import admin from "./routes/admin";

const app = express();
app.use(express.json());

// Identity is the router's property, not each handler's, so a new handler
// cannot be added without it.
app.use("/api", requireAuth);

app.use("/api/projects", projects);
app.use("/api/admin", admin);

// The debug dump is gone. It is in git history if anyone needs it again.

const loginLimiter = rateLimit({ windowMs: 15 * 60_000, max: 10 });

app.post("/login", loginLimiter, async (req, res) => {
  const user = await db.user.findUnique({ where: { email: req.body.email } });
  res.json({ token: sign(user) });
});

export default app;
