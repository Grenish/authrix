import { authConfig } from "../config";
import { createToken } from "../tokens/createToken";
import bcrypt from "bcryptjs";
import type { Response } from "express";

// Framework-agnostic signin function
export async function signinCore(email: string, password: string) {
  const db = authConfig.db;
  if (!db) throw new Error("Database not configured");

  const user = await db.findUserByEmail(email);
  if (!user) throw new Error("Invalid email or password");

  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) throw new Error("Invalid email or password");

  const token = createToken({ id: user.id, email });

  return { 
    user: { id: user.id, email }, 
    token,
    cookieOptions: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 7,
      sameSite: "lax" as const,
      path: "/",
    }
  };
}

// Express.js specific signin function for backward compatibility
export async function signin(email: string, password: string, res: Response) {
  const result = await signinCore(email, password);
  
  res.cookie(authConfig.cookieName, result.token, result.cookieOptions);
  
  return result.user;
}