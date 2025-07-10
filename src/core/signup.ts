import { authConfig } from "../config";
import { hashPassword } from "../utils/hash";
import { createToken } from "../tokens/createToken";
import type { Response } from "express";

export async function signup(email: string, password: string, res: Response) {
  const db = authConfig.db;
  if (!db) throw new Error("Database not configured");

  const existing = await db.findUserByEmail(email);
  if (existing) throw new Error("Email already registered");

  const hashedPassword = await hashPassword(password);

  const user = await db.createUser({
    email,
    password: hashedPassword,
  });

  const token = createToken({ id: user.id, email });

  res.cookie(authConfig.cookieName, token, {
    httpOnly: true,
    secure: true,
    maxAge: 1000 * 60 * 60 * 24 * 7,
    sameSite: "lax",
  });

  return { id: user.id, email };
}
