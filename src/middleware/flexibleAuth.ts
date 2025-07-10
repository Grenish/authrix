// Flexible middleware that can work with different frameworks
import type { Request, Response, NextFunction } from "express";
import { validateAuth, getAuthTokenFromCookies, parseCookies } from "../frameworks/universal";
import { authConfig } from "../config";

/**
 * Framework-agnostic authentication middleware
 * Can be used with Express, Fastify, Koa, etc.
 */
export function createAuthMiddleware(options: {
  required?: boolean; // If true, throws error when not authenticated
  tokenExtractor?: (req: any) => string | null; // Custom token extraction
  errorHandler?: (error: any, req: any, res: any, next?: any) => void; // Custom error handling
} = {}) {
  const { 
    required = true, 
    tokenExtractor = defaultTokenExtractor,
    errorHandler = defaultErrorHandler 
  } = options;

  return async function authMiddleware(req: any, res: any, next: any) {
    try {
      const token = tokenExtractor(req);
      const authResult = await validateAuth(token);

      // Add auth info to request object
      req.auth = authResult;
      req.user = authResult.user;
      req.isAuthenticated = authResult.isValid;

      if (required && !authResult.isValid) {
        return errorHandler(
          new Error(authResult.error || "Authentication required"), 
          req, 
          res, 
          next
        );
      }

      if (typeof next === 'function') {
        next();
      }
    } catch (error) {
      return errorHandler(error, req, res, next);
    }
  };
}

/**
 * Default token extractor for Express-like frameworks
 */
function defaultTokenExtractor(req: any): string | null {
  // Try to get token from cookies first
  if (req.cookies && req.cookies[authConfig.cookieName]) {
    return req.cookies[authConfig.cookieName];
  }

  // Try to get from cookie header
  if (req.headers && req.headers.cookie) {
    const cookies = parseCookies(req.headers.cookie);
    const token = getAuthTokenFromCookies(cookies);
    if (token) return token;
  }

  // Try to get from Authorization header
  if (req.headers && req.headers.authorization) {
    const auth = req.headers.authorization;
    if (auth.startsWith('Bearer ')) {
      return auth.slice(7);
    }
  }

  return null;
}

/**
 * Default error handler for Express-like frameworks
 */
function defaultErrorHandler(error: any, req: any, res: any, next?: any) {
  if (res && typeof res.status === 'function') {
    // Express-like response
    return res.status(401).json({
      success: false,
      error: { message: error.message || "Authentication required" }
    });
  }

  // If we can't handle the response, pass to next middleware
  if (typeof next === 'function') {
    next(error);
  } else {
    throw error;
  }
}

/**
 * Express.js specific middleware (backward compatibility)
 */
export function authMiddleware(
  req: Request & { user?: any; auth?: any; isAuthenticated?: boolean },
  res: Response,
  next: NextFunction
): void {
  const middleware = createAuthMiddleware({ required: true });
  middleware(req, res, next);
}

/**
 * Express.js optional auth middleware
 * Adds user info if available, but doesn't require authentication
 */
export function optionalAuthMiddleware(
  req: Request & { user?: any; auth?: any; isAuthenticated?: boolean },
  res: Response,
  next: NextFunction
): void {
  const middleware = createAuthMiddleware({ required: false });
  middleware(req, res, next);
}

// Re-export the old interface for backward compatibility
export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    createdAt?: Date;
  };
  auth?: {
    isValid: boolean;
    user: { id: string; email: string; createdAt?: Date } | null;
    error: string | null;
  };
  isAuthenticated?: boolean;
}
