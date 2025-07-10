import type { Request } from "express";
import { authConfig } from "../config";
import { verifyToken } from "../tokens/verifyToken";

export async function getCurrentUser(req: Request) {
  try {
    const token = req.cookies[authConfig.cookieName];
    
    if (!token) {
      return null;
    }

    const payload = verifyToken(token);
    
    // Verify user still exists in database
    const db = authConfig.db;
    if (!db) {
      return null;
    }

    const user = await db.findUserById(payload.id);
    
    if (!user) {
      return null;
    }

    return {
      id: user.id,
      email: user.email,
      createdAt: user.createdAt,
    };
  } catch (error) {
    return null;
  }
}

export async function isAuthenticated(req: Request): Promise<boolean> {
  const user = await getCurrentUser(req);
  return user !== null;
}
