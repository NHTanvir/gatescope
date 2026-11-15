import { Router } from "express";
import { CreateProject, UpdateProject } from "../schemas/project";

const router = Router();

// Identity arrives from app.use("/api", requireAuth) in server.ts.
// Every query below is scoped to it, including the ones that look up by id.

router.get("/", async (req, res) => {
  const projects = await db.project.findMany({ where: { userId: req.user.id } });
  res.json(projects);
});

router.get("/:id", async (req, res) => {
  const project = await db.project.findFirst({
    where: { id: req.params.id, userId: req.user.id },
  });
  // 404 rather than 403: a 403 confirms the row exists.
  if (!project) return res.status(404).end();
  res.json(project);
});

router.post("/", async (req, res) => {
  const { name, description } = CreateProject.parse(req.body);
  const project = await db.project.create({
    data: { name, description, userId: req.user.id },
  });
  res.json(project);
});

router.patch("/:id", async (req, res) => {
  const { name, description } = UpdateProject.parse(req.body);
  const { count } = await db.project.updateMany({
    where: { id: req.params.id, userId: req.user.id },
    data: { name, description },
  });
  if (count === 0) return res.status(404).end();
  res.json({ ok: true });
});

router.delete("/:id", async (req, res) => {
  const { count } = await db.project.deleteMany({
    where: { id: req.params.id, userId: req.user.id },
  });
  if (count === 0) return res.status(404).end();
  res.status(204).end();
});

export default router;
