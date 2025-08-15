import type { Request } from "express";
import { authConfig } from "../config";
import { verifyToken } from "../tokens/verifyToken";
import { createToken } from "../tokens/createToken";
import { logger } from "../utils/logger";
import { UnauthorizedError } from "../utils/errors";

export interface SessionUser {
  id: string;
  email: string;
  username?: string;
  firstName?: string;
  lastName?: string;
  emailVerified?: boolean;
  createdAt?: Date;
  lastLoginAt?: Date;
}

export interface SessionValidationOptions {
  requireEmailVerification?: boolean;
  updateLastSeen?: boolean;
  includeUserProfile?: boolean;
}

/**
 * Framework-agnostic function to get current user from token
 * Enhanced with better error handling and optional user profile data
 */
export async function getCurrentUserFromToken(
  token: string | null,
  options: SessionValidationOptions = {}
): Promise<SessionUser | null> {
  const {
    requireEmailVerification = false,
    updateLastSeen = false,
    includeUserProfile = true
  } = options;

  try {
    if (!token?.trim()) {
      return null;
    }

    // Verify and decode token
  const payload = verifyToken(token);
    if (!payload?.id) {
      return null;
    }

    // Check database connection
    const db = authConfig.db;
    if (!db) {
  logger.structuredWarn({ category: 'session', action: 'validation', outcome: 'skipped', message: 'Database not configured for session validation' });
      return null;
    }

    // Fetch user from database
    const user = await db.findUserById(payload.id);
    if (!user) {
      return null;
    }

    // Check email verification requirement
    if (requireEmailVerification && !user.emailVerified) {
      return null;
    }

    // Update last seen timestamp if requested
    if (updateLastSeen && db.updateUser) {
      try {
        await db.updateUser(user.id, { lastLoginAt: new Date() });
      } catch (error) {
  logger.structuredWarn({ category: 'session', action: 'update-last-login', outcome: 'failed', message: 'Failed to update last login timestamp', error: error instanceof Error ? error.message : String(error) });
        // Don't fail the session validation for this
      }
    }

    // Build session user object
    const sessionUser: SessionUser = {
      id: user.id,
      email: user.email,
      createdAt: user.createdAt,
    };

    // Include additional profile data if requested
    if (includeUserProfile) {
      if (user.username) sessionUser.username = user.username;
      if (user.firstName) sessionUser.firstName = user.firstName;
      if (user.lastName) sessionUser.lastName = user.lastName;
      if (typeof user.emailVerified === 'boolean') {
        sessionUser.emailVerified = user.emailVerified;
      }
      if (user.lastLoginAt) sessionUser.lastLoginAt = user.lastLoginAt;
    }

    return sessionUser;

  } catch (error) {
    // Log error for debugging but don't expose details
  logger.debug('Session validation error', error);
    return null;
  }
}

/**
 * Express.js specific function for backward compatibility
 */
export async function getCurrentUser(
  req: Request,
  options?: SessionValidationOptions
): Promise<SessionUser | null> {
  const token = req.cookies?.[authConfig.cookieName] ||
    req.headers.authorization?.replace('Bearer ', '');
  return getCurrentUserFromToken(token, options);
}

/**
 * Framework-agnostic function to check if token is valid
 */
export async function isTokenValid(
  token: string | null,
  options?: SessionValidationOptions
): Promise<boolean> {
  const user = await getCurrentUserFromToken(token, options);
  return user !== null;
}

/**
 * Express.js specific function for backward compatibility
 */
export async function isAuthenticated(
  req: Request,
  options?: SessionValidationOptions
): Promise<boolean> {
  const user = await getCurrentUser(req, options);
  return user !== null;
}

/**
 * Get session info with additional metadata
 */
export async function getSessionInfo(token: string | null): Promise<{
  isValid: boolean;
  user: SessionUser | null;
  expiresAt?: Date;
  issuedAt?: Date;
}> {
  try {
    if (!token?.trim()) {
      return { isValid: false, user: null };
    }

    const payload = verifyToken(token);
    const user = await getCurrentUserFromToken(token);

    return {
      isValid: user !== null,
      user,
      expiresAt: payload.exp ? new Date(payload.exp * 1000) : undefined,
      issuedAt: payload.iat ? new Date(payload.iat * 1000) : undefined,
    };

  } catch (error) {
    return { isValid: false, user: null };
  }
}

/**
 * Validate session and throw error if invalid (useful for protected routes)
 */
export async function requireValidSession(
  token: string | null,
  options?: SessionValidationOptions
): Promise<SessionUser> {
  const user = await getCurrentUserFromToken(token, options);
  if (!user) {
    throw new UnauthorizedError('Valid authentication required');
  }
  return user;
}

/**
 * Extended helper returning refresh metadata when rolling sessions enabled
 */
export async function getCurrentUserFromTokenWithRefresh(
  token: string | null,
  options: SessionValidationOptions = {}
): Promise<{ user: SessionUser | null; refreshedToken?: string }> {
  const user = await getCurrentUserFromToken(token, options);
  if (!user) return { user: null };

  try {
    if (authConfig.rollingSessionEnabled) {
      const payload = verifyToken(token!);
      if (payload.exp) {
        const nowSeconds = Math.floor(Date.now() / 1000);
        const secondsLeft = payload.exp - nowSeconds;
        if (secondsLeft > 0 && secondsLeft <= authConfig.rollingSessionThresholdSeconds) {
          const refreshedToken = createToken({ id: user.id, email: user.email });
          return { user, refreshedToken };
        }
      }
    }
  } catch {
    // Ignore; base validation already done
  }
  return { user };
}
