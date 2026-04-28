import { Request, Response, Router } from "express";

interface User { id: string; name: string }
const users = new Map<string, User>();

export const userRouter = Router();

userRouter.get("/users/:id", (req: Request, res: Response) => {
  const u = users.get(req.params.id);
  if (!u) return res.status(404).json({ error: "not found" });
  return res.json(u);
});
