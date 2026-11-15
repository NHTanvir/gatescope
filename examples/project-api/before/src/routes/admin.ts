import { Router } from "express";

const router = Router();

// Guarded by the mount in server.ts, so every logged-in user reaches it.
router.get("/users", async (req, res) => {
  const users = await db.user.findMany();
  res.json(users);
});

router.post("/users/:id/promote", async (req, res) => {
  await db.user.update({
    where: { id: req.params.id },
    data: { role: req.body.role },
  });
  res.json({ ok: true });
});

export default router;
