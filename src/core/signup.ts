import { authConfig } from "../config";
import { hashPassword } from "../utils/hash";
import { createToken } from "../tokens/createToken";
import type { Response } from "express";

// Framework-agnostic signup function
export async function signupCore(email: string, password: string) {
  const db = authConfig.db;
  
  if (!db) {
    throw new Error("Database not configured. Make sure initAuth() is called before using authentication functions.");
  }

  // Input validation
  if (!email || !email.trim()) {
    throw new Error("Email is required");
  }
  
  if (!password || !password.trim()) {
    throw new Error("Password is required");
  }
  
  // Basic email format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    throw new Error("Invalid email format");
  }
  
  // Basic password strength validation
  if (password.length < 6) {
    throw new Error("Password must be at least 6 characters long");
  }

  const existing = await db.findUserByEmail(email);
  if (existing) throw new Error("Email already registered");

  // Use skipValidation to maintain backward compatibility with existing basic validation
  const hashedPassword = await hashPassword(password, { skipValidation: true });

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
