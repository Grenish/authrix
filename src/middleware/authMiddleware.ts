import type { Request, Response, NextFunction } from "express";
import { authConfig } from "../config";
import { verifyToken } from "../tokens/verifyToken";
import { UnauthorizedError, InternalServerError } from "../utils/errors";

export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    createdAt?: Date;
  };
}

export async function authMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const token = req.cookies[authConfig.cookieName];
    if (!token) {
      throw new UnauthorizedError("Authentication token is missing.");
    }

    const payload = verifyToken(token);

    const db = authConfig.db;
    if (!db) {
      throw new InternalServerError("Database not configured.");
    }

    const user = await db.findUserById(payload.id);
    if (!user) {
      // To prevent token reuse for a deleted user, clear the cookie.
      res.clearCookie(authConfig.cookieName);
      throw new UnauthorizedError("User not found or token is invalid.");
    }

    req.user = {
      id: user.id,
      email: user.email,
      createdAt: user.createdAt,
    };

    next();
  } catch (error) {
    // Pass the error to the global error handler
    next(error);
  }
}
