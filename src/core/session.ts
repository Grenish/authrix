import type { Request } from "express";
import { authConfig } from "../config";
import { verifyToken } from "../tokens/verifyToken";

// Framework-agnostic function to get current user from token
export async function getCurrentUserFromToken(token: string | null) {
  try {
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

// Express.js specific function for backward compatibility
export async function getCurrentUser(req: Request) {
  const token = req.cookies[authConfig.cookieName];
  return getCurrentUserFromToken(token);
}

// Framework-agnostic function to check if token is valid
export async function isTokenValid(token: string | null): Promise<boolean> {
  const user = await getCurrentUserFromToken(token);
  return user !== null;
}

// Express.js specific function for backward compatibility
export async function isAuthenticated(req: Request): Promise<boolean> {
  const user = await getCurrentUser(req);
  return user !== null;
}
