import type { Request, Response, NextFunction } from "express";
import { authConfig } from "../config";
import { verifyToken } from "../tokens/verifyToken";
import { UnauthorizedError, InternalServerError, ForbiddenError } from "../utils/errors";
import { getCurrentUserFromTokenWithRefresh, getCurrentUserFromToken, type SessionUser } from "./session";
import { logger } from "../utils/logger";

export interface AuthenticatedRequest extends Request {
  user?: SessionUser;
}

export interface AuthMiddlewareOptions {
  requireEmailVerification?: boolean;
  requiredRoles?: string[];
  requiredPermissions?: string[];
  allowApiKey?: boolean;
  customErrorMessage?: string;
}

/**
 * Enhanced authentication middleware with flexible options
 */
export async function requireAuth(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
  options: AuthMiddlewareOptions = {}
) {
  const {
    requireEmailVerification = false,
    requiredRoles = [],
    requiredPermissions = [],
    allowApiKey = false,
    customErrorMessage
  } = options;

  try {
    // Extract token from multiple sources
    let token = req.cookies?.[authConfig.cookieName];

    // Check Authorization header as fallback
    if (!token && req.headers.authorization) {
      const authHeader = req.headers.authorization;
      if (authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
      }
    }

    // Check API key if allowed
    if (!token && allowApiKey && req.headers['x-api-key']) {
      // TODO: Implement API key validation
      console.log('[AUTHRIX] API key authentication not yet implemented');
    }

    if (!token) {
      throw new UnauthorizedError(customErrorMessage || "Authentication required");
    }

    // Explicit signature validation (fast fail for tampered tokens)
    try {
      verifyToken(token);
    } catch (e) {
      throw new UnauthorizedError(customErrorMessage || "Invalid or expired authentication");
    }

    // Verify token and get user (may return refreshed token wrapper)
  const { user: userMaybe, refreshedToken } = await getCurrentUserFromTokenWithRefresh(token, {
      requireEmailVerification,
      updateLastSeen: true,
      includeUserProfile: true
    });
  const user = userMaybe;

    if (!user) {
      // Clear invalid cookie
      res.clearCookie(authConfig.cookieName, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
      });
      throw new UnauthorizedError(customErrorMessage || "Invalid or expired authentication");
    }

    // Check email verification requirement
    if (requireEmailVerification && !user.emailVerified) {
      throw new ForbiddenError("Email verification required");
    }

    // Check role requirements (if user has roles)
    if (requiredRoles.length > 0) {
      const userRoles = (user as any).roles || [];
      const hasRequiredRole = requiredRoles.some(role => userRoles.includes(role));
      if (!hasRequiredRole) {
        throw new ForbiddenError(`Required role: ${requiredRoles.join(' or ')}`);
      }
    }

    // Check permission requirements (if user has permissions)
    if (requiredPermissions.length > 0) {
      const userPermissions = (user as any).permissions || [];
      const hasRequiredPermission = requiredPermissions.every(permission =>
        userPermissions.includes(permission)
      );
      if (!hasRequiredPermission) {
        throw new ForbiddenError(`Required permissions: ${requiredPermissions.join(', ')}`);
      }
    }

    // Attach user to request
    req.user = user;

    // If rolling session produced refreshed token, set new cookie
    if (refreshedToken) {
      res.cookie(authConfig.cookieName, refreshedToken, {
        httpOnly: true,
        secure: authConfig.forceSecureCookies || process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: authConfig.sessionMaxAgeMs
      });
    }
    next();

  } catch (error) {
    // Enhanced error logging for debugging
    logger.debug('Authentication failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
      path: req.path,
      method: req.method,
      userAgent: req.get('User-Agent'),
      ip: req.ip
    });

    // Let the global error handler manage the response
    next(error);
  }
}

/**
 * Convenience middleware for requiring email verification
 */
export function requireEmailVerification(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  return requireAuth(req, res, next, { requireEmailVerification: true });
}

/**
 * Convenience middleware for requiring specific roles
 */
export function requireRoles(...roles: string[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    return requireAuth(req, res, next, { requiredRoles: roles });
  };
}

/**
 * Convenience middleware for requiring specific permissions
 */
export function requirePermissions(...permissions: string[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    return requireAuth(req, res, next, { requiredPermissions: permissions });
  };
}

/**
 * Optional authentication middleware - doesn't fail if no auth provided
 */
export async function optionalAuth(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  try {
    const token = req.cookies?.[authConfig.cookieName] ||
      req.headers.authorization?.replace('Bearer ', '');

    if (token) {
      const user = await getCurrentUserFromToken(token, { updateLastSeen: false, includeUserProfile: true });
      if (user) req.user = user;
    }

    next();
  } catch (error) {
    // For optional auth, we don't fail on errors, just continue without user
  logger.debug('Optional auth failed', error);
    next();
  }
}
