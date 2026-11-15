import { Router } from "express";
import { requireRole } from "../middleware/auth";

const router = Router();

// Identity comes from the mount in server.ts. Authority is asserted here,
// because being logged in was never the question on an admin surface.
router.use(requireRole("admin"));

router.get("/users", async (req, res) => {
  const users = await db.user.findMany({
    select: { id: true, email: true, role: true, createdAt: true },
  });
  res.json(users);
});

router.post("/users/:id/promote", async (req, res) => {
  await db.user.update({
    where: { id: req.params.id },
    data: { role: "admin" },
  });
  res.json({ ok: true });
});

export default router;
