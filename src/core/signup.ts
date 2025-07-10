import { authConfig } from "../config";
import { hashPassword } from "../utils/hash";
import { createToken } from "../tokens/createToken";
import type { Response } from "express";

// Framework-agnostic signup function
export async function signupCore(email: string, password: string) {
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

// Express.js specific signup function for backward compatibility
export async function signup(email: string, password: string, res: Response) {
  const result = await signupCore(email, password);
  
  res.cookie(authConfig.cookieName, result.token, result.cookieOptions);
  
  return result.user;
}
