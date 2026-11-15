import { Router } from "express";
import { requireAuth } from "../middleware/auth";

const router = Router();

// Listing is scoped to the caller. Good.
router.get("/", requireAuth, async (req, res) => {
  const projects = await db.project.findMany({ where: { userId: req.user.id } });
  res.json(projects);
});

// Reading one is not. Any logged-in user can read any project by id.
router.get("/:id", requireAuth, async (req, res) => {
  const project = await db.project.findUnique({ where: { id: req.params.id } });
  res.json(project);
});

// Whatever the client sends becomes the record, role included.
router.post("/", requireAuth, async (req, res) => {
  const project = await db.project.create({
    data: { ...req.body, userId: req.user.id, role: req.body.role },
  });
  res.json(project);
});

// No guard on this one at all.
router.delete("/:id", async (req, res) => {
  await db.project.delete({ where: { id: req.params.id } });
  res.status(204).end();
});

// The update writes first and checks who is asking afterwards.
router.patch("/:id", async (req, res) => {
  await db.project.update({ where: { id: req.params.id }, data: req.body });
  const session = await getServerSession(req);
  if (!session) return res.status(401).end();
  res.json({ ok: true });
});

export default router;
