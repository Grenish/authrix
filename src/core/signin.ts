import { authConfig } from "../config";
import { createToken } from "../tokens/createToken";
import bcrypt from "bcryptjs";
import type { Response } from "express";

export async function signin(email: string, password: string, res: Response) {
  const db = authConfig.db;
  if (!db) throw new Error("Database not configured");

  const user = await db.findUserByEmail(email);
  if (!user) throw new Error("Invalid email or password");

  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) throw new Error("Invalid email or password");

  const token = createToken({ id: user.id, email });

  res.cookie(authConfig.cookieName, token, {
    httpOnly: true,
    secure: true,
    maxAge: 1000 * 60 * 60 * 24 * 7,
    sameSite: "lax",
  });

  return { id: user.id, email };
}