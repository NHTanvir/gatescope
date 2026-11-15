import type { NextFunction, Request, Response } from "express";

/** Establishes who the caller is. One implementation, one name. */
export async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const session = await getServerSession(req);
  if (!session?.user) return res.status(401).end();
  req.user = session.user;
  next();
}

/** Establishes what the caller may do. Never reads the role from the request. */
export function requireRole(role: "admin" | "member") {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.user?.role !== role) return res.status(403).end();
    next();
  };
}
