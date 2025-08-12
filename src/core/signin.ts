import { authConfig } from "../config";
import { createToken } from "../tokens/createToken";
import { verifyPassword, verifyAndCheckRehash } from "../utils/hash";
import { BadRequestError, UnauthorizedError, ForbiddenError } from "../utils/errors";
import type { Response } from "express";

export interface SigninOptions {
  rememberMe?: boolean;
  requireEmailVerification?: boolean;
  updateLastLogin?: boolean;
  includeUserProfile?: boolean;
  maxLoginAttempts?: number;
  lockoutDuration?: number; // in minutes
}

export interface SigninResult {
  user: {
    id: string;
    email: string;
    username?: string;
    firstName?: string;
    lastName?: string;
    emailVerified?: boolean;
    lastLoginAt?: Date;
  };
  token: string;
  cookieOptions: {
    httpOnly: boolean;
    secure: boolean;
    maxAge: number;
    sameSite: "lax" | "strict" | "none";
    path: string;
  };
  isFirstLogin?: boolean;
  mustChangePassword?: boolean;
}

// Rate limiting for login attempts (simple in-memory store)
const loginAttempts = new Map<string, { count: number; lastAttempt: number; lockedUntil?: number }>();

/**
 * Check and update login rate limiting
 */
function checkLoginRateLimit(email: string, maxAttempts: number = 5, lockoutDuration: number = 15): {
  allowed: boolean;
  attemptsRemaining: number;
  lockedUntil?: Date;
} {
  const now = Date.now();
  const attempts = loginAttempts.get(email);

  if (!attempts) {
    loginAttempts.set(email, { count: 1, lastAttempt: now });
    return { allowed: true, attemptsRemaining: maxAttempts - 1 };
  }

  // Check if lockout period has expired
  if (attempts.lockedUntil && now > attempts.lockedUntil) {
    loginAttempts.set(email, { count: 1, lastAttempt: now });
    return { allowed: true, attemptsRemaining: maxAttempts - 1 };
  }

  // Check if currently locked out
  if (attempts.lockedUntil && now <= attempts.lockedUntil) {
    return {
      allowed: false,
      attemptsRemaining: 0,
      lockedUntil: new Date(attempts.lockedUntil)
    };
  }

  // Reset counter if enough time has passed (1 hour)
  if (now - attempts.lastAttempt > 60 * 60 * 1000) {
    loginAttempts.set(email, { count: 1, lastAttempt: now });
    return { allowed: true, attemptsRemaining: maxAttempts - 1 };
  }

  // Increment attempts
  attempts.count++;
  attempts.lastAttempt = now;

  // Check if should be locked out
  if (attempts.count >= maxAttempts) {
    attempts.lockedUntil = now + (lockoutDuration * 60 * 1000);
    return {
      allowed: false,
      attemptsRemaining: 0,
      lockedUntil: new Date(attempts.lockedUntil)
    };
  }

  return {
    allowed: true,
    attemptsRemaining: maxAttempts - attempts.count
  };
}

/**
 * Clear login attempts for successful login
 */
function clearLoginAttempts(email: string): void {
  loginAttempts.delete(email);
}

/**
 * Framework-agnostic signin function with enhanced security
 */
export async function signinCore(
  email: string,
  password: string,
  options: SigninOptions = {}
): Promise<SigninResult> {
  const {
    rememberMe = false,
    requireEmailVerification = false,
    updateLastLogin = true,
    includeUserProfile = true,
    maxLoginAttempts = 5,
    lockoutDuration = 15
  } = options;

  // Input validation
  if (!email?.trim()) {
    throw new BadRequestError("Email is required");
  }

  if (!password?.trim()) {
    throw new BadRequestError("Password is required");
  }

  const normalizedEmail = email.toLowerCase().trim();

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(normalizedEmail)) {
    throw new BadRequestError("Invalid email format");
  }

  // Check rate limiting
  const rateLimitCheck = checkLoginRateLimit(normalizedEmail, maxLoginAttempts, lockoutDuration);
  if (!rateLimitCheck.allowed) {
    const lockoutMessage = rateLimitCheck.lockedUntil
      ? `Account temporarily locked. Try again after ${rateLimitCheck.lockedUntil.toLocaleTimeString()}`
      : 'Too many login attempts. Please try again later.';
    throw new ForbiddenError(lockoutMessage);
  }

  // Check database configuration
  const db = authConfig.db;
  if (!db) {
    throw new Error("Database not configured. Make sure initAuth() is called before using authentication functions.");
  }

  try {
    // Find user by email
    const user = await db.findUserByEmail(normalizedEmail);
    if (!user) {
      // Don't reveal whether user exists or not
      throw new UnauthorizedError("Invalid email or password");
    }

    // Verify password and upgrade hash transparently if needed
    let isValidPassword = false;
    let upgradedHash: string | undefined;
    try {
      const verifyResult = await verifyAndCheckRehash(password, user.password, {
        identifier: normalizedEmail,
        updateHash: !!(authConfig.db && authConfig.db.updateUser)
      });
      isValidPassword = verifyResult.valid;
      if (verifyResult.valid && verifyResult.needsRehash && verifyResult.newHash) {
        upgradedHash = verifyResult.newHash;
      }
    } catch (e) {
      // Fallback to legacy verify if newer path misbehaves
      const legacyValid = await verifyPassword(password, user.password, { identifier: normalizedEmail });
      isValidPassword = legacyValid;
    }

    if (!isValidPassword) {
      throw new UnauthorizedError("Invalid email or password");
    }

    // Check email verification requirement
    if (requireEmailVerification && !user.emailVerified) {
      throw new ForbiddenError("Please verify your email address before signing in");
    }

    // Check if user is disabled/suspended
    if (user.isDisabled) {
      throw new ForbiddenError("Account has been disabled. Please contact support.");
    }

    // Clear login attempts on successful authentication
    clearLoginAttempts(normalizedEmail);

    // Check if password needs to be changed
    const mustChangePassword = user.mustChangePassword || false;

    // Update last login timestamp if requested
    let updatedUser = user;
    if ((updateLastLogin || upgradedHash) && db.updateUser) {
      try {
        const updatePayload: any = {};
        if (updateLastLogin) {
          updatePayload.lastLoginAt = new Date();
          updatePayload.loginCount = (user.loginCount || 0) + 1;
        }
        if (upgradedHash) {
          updatePayload.password = upgradedHash;
          updatePayload.passwordChangedAt = new Date();
        }
        if (Object.keys(updatePayload).length > 0) {
          updatedUser = await db.updateUser(user.id, updatePayload) || user;
        }
      } catch (error) {
        console.warn('[AUTHRIX] Failed to post-auth update (login timestamp / hash upgrade):', error);
        // Don't fail the login for this
      }
    }

    // Create token payload
    const tokenPayload: any = {
      id: user.id,
      email: user.email
    };

    // Add additional claims if available
    if (user.username) tokenPayload.username = user.username;
    if (user.emailVerified) tokenPayload.emailVerified = user.emailVerified;

    // Create JWT token
    const token = createToken(tokenPayload);

    // Determine cookie max age
    const maxAge = rememberMe
      ? 1000 * 60 * 60 * 24 * 30 // 30 days for remember me
      : 1000 * 60 * 60 * 24 * 7;  // 7 days default

    // Build user response object
    const userResponse: SigninResult['user'] = {
      id: updatedUser.id,
      email: updatedUser.email,
    };

    // Include additional profile data if requested
    if (includeUserProfile) {
      if (updatedUser.username) userResponse.username = updatedUser.username;
      if (updatedUser.firstName) userResponse.firstName = updatedUser.firstName;
      if (updatedUser.lastName) userResponse.lastName = updatedUser.lastName;
      if (typeof updatedUser.emailVerified === 'boolean') {
        userResponse.emailVerified = updatedUser.emailVerified;
      }
      if (updatedUser.lastLoginAt) userResponse.lastLoginAt = updatedUser.lastLoginAt;
    }

    return {
      user: userResponse,
      token,
      cookieOptions: {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge,
        sameSite: "lax" as const,
        path: "/",
      },
      isFirstLogin: !user.lastLoginAt,
      mustChangePassword
    };

  } catch (error) {
    // Log failed attempt for monitoring
    if (process.env.NODE_ENV === 'development') {
      console.debug('[AUTHRIX] Signin failed:', {
        email: normalizedEmail,
        error: error instanceof Error ? error.message : 'Unknown error',
        attemptsRemaining: rateLimitCheck.attemptsRemaining
      });
    }

    // Re-throw the error to be handled by the caller
    throw error;
  }
}

/**
 * Express.js specific signin function for backward compatibility
 */
export async function signin(
  email: string,
  password: string,
  res: Response,
  options?: SigninOptions
): Promise<SigninResult['user']> {
  const result = await signinCore(email, password, options);

  // Set authentication cookie
  res.cookie(authConfig.cookieName, result.token, result.cookieOptions);

  // Set remember me cookie if requested
  if (options?.rememberMe) {
    res.cookie(`${authConfig.cookieName}_remember`, 'true', {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: result.cookieOptions.maxAge,
      sameSite: "lax",
      path: "/",
    });
  }

  return result.user;
}