import type { Request, Response, NextFunction } from "express";
import { authConfig } from "../config";
import { verifyToken } from "../tokens/verifyToken";
import { UnauthorizedError, InternalServerError } from "../utils/errors";

export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
  };
}

export async function requireAuth(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  try {
    const token = req.cookies[authConfig.cookieName];
    
    if (!token) {
      throw new UnauthorizedError("Authentication required");
    }

    const payload = verifyToken(token);
    
    const db = authConfig.db;
    if (!db) {
      throw new InternalServerError("Database not configured");
    }

    const user = await db.findUserById(payload.id);
    
    if (!user) {
      res.clearCookie(authConfig.cookieName);
      throw new UnauthorizedError("User not found");
    }

    req.user = {
      id: user.id,
      email: user.email,
    };

    next();
  } catch (error) {
    // Let the global error handler manage the response
    next(error);
  }
}
