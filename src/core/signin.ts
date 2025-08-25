import { authConfig } from "../config";
import { logger } from "../utils/logger";
import { createToken } from "../tokens/createToken";
import { verifyAndCheckRehash } from "../utils/hash";
import {
  BadRequestError,
  UnauthorizedError,
  ForbiddenError,
} from "../utils/errors";
import type { Response } from "express";

export interface SigninOptions {
  rememberMe?: boolean;
  requireEmailVerification?: boolean;
  updateLastLogin?: boolean;
  includeUserProfile?: boolean;
  maxLoginAttempts?: number;
  lockoutDuration?: number;
  requesterIp?: string;
  userAgent?: string;
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
  passwordStrengthWarning?: boolean;
}

// Rate limiting for login attempts (simple in-memory store)
// This provides an additional layer on top of the hash module's rate limiting
const loginAttempts = new Map<
  string,
  {
    count: number;
    lastAttempt: number;
    lockedUntil?: number;
    consecutiveFailures: number;
  }
>();

/**
 * Check and update login rate limiting
 * This works in conjunction with the hash module's rate limiting for defense in depth
 */
function checkLoginRateLimit(
  identifier: string,
  maxAttempts: number = 5,
  lockoutDuration: number = 15
): {
  allowed: boolean;
  attemptsRemaining: number;
  lockedUntil?: Date;
} {
  const now = Date.now();
  const attempts = loginAttempts.get(identifier);

  if (!attempts) {
    loginAttempts.set(identifier, {
      count: 1,
      lastAttempt: now,
      consecutiveFailures: 0,
    });
    return { allowed: true, attemptsRemaining: maxAttempts - 1 };
  }

  // Check if lockout period has expired
  if (attempts.lockedUntil && now > attempts.lockedUntil) {
    loginAttempts.set(identifier, {
      count: 1,
      lastAttempt: now,
      consecutiveFailures: 0,
    });
    return { allowed: true, attemptsRemaining: maxAttempts - 1 };
  }

  // Check if currently locked out
  if (attempts.lockedUntil && now <= attempts.lockedUntil) {
    return {
      allowed: false,
      attemptsRemaining: 0,
      lockedUntil: new Date(attempts.lockedUntil),
    };
  }

  // Reset counter if enough time has passed (1 hour)
  if (now - attempts.lastAttempt > 60 * 60 * 1000) {
    loginAttempts.set(identifier, {
      count: 1,
      lastAttempt: now,
      consecutiveFailures: 0,
    });
    return { allowed: true, attemptsRemaining: maxAttempts - 1 };
  }

  // Increment attempts
  attempts.count++;
  attempts.lastAttempt = now;

  // Check if should be locked out (progressive lockout based on consecutive failures)
  if (attempts.count >= maxAttempts) {
    const multiplier = Math.min(attempts.consecutiveFailures + 1, 5);
    attempts.lockedUntil = now + lockoutDuration * multiplier * 60 * 1000;
    attempts.consecutiveFailures++;
    loginAttempts.set(identifier, attempts);

    return {
      allowed: false,
      attemptsRemaining: 0,
      lockedUntil: new Date(attempts.lockedUntil),
    };
  }

  loginAttempts.set(identifier, attempts);
  return {
    allowed: true,
    attemptsRemaining: maxAttempts - attempts.count,
  };
}

/**
 * Record a failed login attempt
 */
function recordFailedAttempt(identifier: string): void {
  const attempts = loginAttempts.get(identifier);
  if (attempts) {
    attempts.consecutiveFailures++;
    loginAttempts.set(identifier, attempts);
  }
}

/**
 * Clear login attempts for successful login
 */
function clearLoginAttempts(identifier: string): void {
  loginAttempts.delete(identifier);
}

/**
 * Cleanup old entries periodically to prevent memory leaks
 */
const cleanupInterval = setInterval(
  () => {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours

    for (const [key, attempts] of loginAttempts.entries()) {
      if (
        now - attempts.lastAttempt > maxAge &&
        (!attempts.lockedUntil || now > attempts.lockedUntil)
      ) {
        loginAttempts.delete(key);
      }
    }
  },
  60 * 60 * 1000
); // Run every hour

// Ensure cleanup doesn't prevent process exit
cleanupInterval.unref?.();

/** Framework-agnostic signin with rate limiting, optional email verification check, and password security updates. */
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
    lockoutDuration = 15,
    requesterIp,
    userAgent,
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

  // Create a unique identifier for rate limiting
  // Combine email with IP for more granular control
  const rateLimitId = requesterIp
    ? `${normalizedEmail}|${requesterIp}`
    : normalizedEmail;

  // Check application-level rate limiting first
  const rateLimitCheck = checkLoginRateLimit(
    rateLimitId,
    maxLoginAttempts,
    lockoutDuration
  );
  if (!rateLimitCheck.allowed) {
    const lockoutMessage = rateLimitCheck.lockedUntil
      ? `Account temporarily locked. Try again after ${rateLimitCheck.lockedUntil.toLocaleTimeString()}`
      : "Too many login attempts. Please try again later.";

    logger.structuredWarn({
      category: "auth",
      action: "signin",
      outcome: "rate_limited_app",
      message: lockoutMessage,
      email: normalizedEmail,
      ip: requesterIp,
      attemptsRemaining: 0,
    });

    throw new ForbiddenError(lockoutMessage);
  }

  // Check database configuration
  const db = authConfig.db;
  if (!db) {
    throw new Error(
      "Database not configured. Make sure initAuth() is called before using authentication functions."
    );
  }

  try {
    // Find user by email
    const user = await db.findUserByEmail(normalizedEmail);
    if (!user) {
      // Record failed attempt even for non-existent users (prevents user enumeration)
      recordFailedAttempt(rateLimitId);

      // Add a small delay to mitigate timing attacks
      await new Promise((resolve) =>
        setTimeout(resolve, 100 + Math.random() * 100)
      );

      throw new UnauthorizedError("Invalid email or password");
    }

    // Check if user is disabled/suspended before password verification
    if (user.isDisabled) {
      logger.structuredWarn({
        category: "auth",
        action: "signin",
        outcome: "account_disabled",
        email: normalizedEmail,
        userId: user.id,
      });
      throw new ForbiddenError(
        "Account has been disabled. Please contact support."
      );
    }

    // Check if user is locked out at the user level (if your schema supports it)
    if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
      const lockUntil = new Date(user.lockedUntil);
      logger.structuredWarn({
        category: "auth",
        action: "signin",
        outcome: "account_locked",
        email: normalizedEmail,
        userId: user.id,
        lockedUntil: lockUntil.toISOString(),
      });
      throw new ForbiddenError(
        `Account is locked until ${lockUntil.toLocaleTimeString()}. Please try again later.`
      );
    }

    let isValidPassword = false;
    let needsRehash = false;
    let upgradedHash: string | undefined;
    let passwordStrengthWarning = false;

    try {
      // Verify password with the hash module's built-in rate limiting
      // The identifier helps the hash module track attempts per user/IP combination
      const verifyResult = await verifyAndCheckRehash(password, user.password, {
        identifier: rateLimitId,
        updateHash: true, // Enable automatic hash upgrade
        skipRateLimit: false, // Use hash module's rate limiting
      });

      isValidPassword = verifyResult.valid;
      needsRehash = verifyResult.needsRehash;
      upgradedHash = verifyResult.newHash;

      // If password is valid but weak, set a warning flag
      if (isValidPassword && needsRehash) {
        passwordStrengthWarning = true;
      }
    } catch (error) {
      // Handle rate limiting from the hash module
      if (
        error instanceof Error &&
        error.message.includes("Rate limit exceeded")
      ) {
        recordFailedAttempt(rateLimitId);

        logger.structuredWarn({
          category: "auth",
          action: "signin",
          outcome: "rate_limited_hash",
          message: "Hash module rate limit exceeded",
          email: normalizedEmail,
          ip: requesterIp,
        });

        throw new ForbiddenError(error.message);
      }

      // Re-throw other errors
      throw error;
    }

    if (!isValidPassword) {
      // Record failed attempt
      recordFailedAttempt(rateLimitId);

      // Log for security monitoring
      const hashAlgo = user.password?.startsWith?.("$argon2")
        ? "argon2"
        : user.password?.startsWith?.("$2")
          ? "bcrypt"
          : "unknown";

      logger.structuredWarn({
        category: "auth",
        action: "signin",
        outcome: "invalid_credentials",
        message: "Invalid password",
        email: normalizedEmail,
        userId: user.id,
        hashAlgorithm: hashAlgo,
        attemptsRemaining: rateLimitCheck.attemptsRemaining - 1,
        ip: requesterIp,
        userAgent,
      });

      throw new UnauthorizedError("Invalid email or password");
    }

    // Check email verification requirement
    if (requireEmailVerification && !user.emailVerified) {
      logger.structuredWarn({
        category: "auth",
        action: "signin",
        outcome: "email_not_verified",
        email: normalizedEmail,
        userId: user.id,
      });
      throw new ForbiddenError(
        "Please verify your email address before signing in"
      );
    }

    // Clear login attempts on successful authentication
    clearLoginAttempts(rateLimitId);

    // Check if password needs to be changed
    const mustChangePassword = user.mustChangePassword || false;

    // Update user record with new hash and/or last login
    let updatedUser = user;
    if ((updateLastLogin || upgradedHash) && db.updateUser) {
      try {
        const updatePayload: any = {};

        if (updateLastLogin) {
          updatePayload.lastLoginAt = new Date();
          updatePayload.loginCount = (user.loginCount || 0) + 1;
          if (requesterIp) {
            updatePayload.lastLoginIp = requesterIp;
          }
        }

        if (upgradedHash) {
          updatePayload.password = upgradedHash;
          updatePayload.passwordChangedAt = new Date();

          logger.info('[AUTHRIX][auth] password_hash_upgraded', {
            userId: user.id,
            email: normalizedEmail,
            message: 'Password hash automatically upgraded to stronger algorithm'
          });
        }

        if (Object.keys(updatePayload).length > 0) {
          updatedUser = (await db.updateUser(user.id, updatePayload)) || user;
        }
      } catch (error) {
        // Log but don't fail the login
        logger.structuredWarn({
          category: "auth",
          action: "post_auth_update",
          outcome: "failed",
          message: "Failed to update user after authentication",
          userId: user.id,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    // Create token payload
    const tokenPayload: any = {
      id: updatedUser.id,
      email: updatedUser.email,
    };

    // Add additional claims if available
    if (updatedUser.username) tokenPayload.username = updatedUser.username;
    if (updatedUser.emailVerified !== undefined) {
      tokenPayload.emailVerified = updatedUser.emailVerified;
    }

    // Create JWT token
    const token = createToken(tokenPayload);

    // Determine cookie max age
    const maxAge = rememberMe
      ? 1000 * 60 * 60 * 24 * 30 // 30 days for remember me
      : authConfig.sessionMaxAgeMs; // Default session duration

    // Build user response object
    const userResponse: SigninResult["user"] = {
      id: updatedUser.id,
      email: updatedUser.email,
    };

    // Include additional profile data if requested
    if (includeUserProfile) {
      if (updatedUser.username) userResponse.username = updatedUser.username;
      if (updatedUser.firstName) userResponse.firstName = updatedUser.firstName;
      if (updatedUser.lastName) userResponse.lastName = updatedUser.lastName;
      if (typeof updatedUser.emailVerified === "boolean") {
        userResponse.emailVerified = updatedUser.emailVerified;
      }
      if (updatedUser.lastLoginAt)
        userResponse.lastLoginAt = updatedUser.lastLoginAt;
    }

    // Log successful signin
    logger.info('[AUTHRIX][auth] signin success', {
      userId: updatedUser.id,
      email: normalizedEmail,
      isFirstLogin: !user.lastLoginAt,
      passwordUpgraded: !!upgradedHash,
      ip: requesterIp,
      userAgent
    });

    return {
      user: userResponse,
      token,
      cookieOptions: {
        httpOnly: true,
        secure:
          authConfig.forceSecureCookies ||
          process.env.NODE_ENV === "production",
        maxAge,
        sameSite: "lax" as const,
        path: "/",
      },
      isFirstLogin: !user.lastLoginAt,
      mustChangePassword,
      passwordStrengthWarning,
    };
  } catch (error) {
    // Log failed attempt for monitoring (avoid logging sensitive data)
    const msg = error instanceof Error ? error.message : "Unknown error";

    if (error instanceof ForbiddenError) {
      logger.structuredWarn({
        category: "auth",
        action: "signin",
        outcome: "forbidden",
        message: msg,
        email: normalizedEmail,
        ip: requesterIp,
        attemptsRemaining: Math.max(0, rateLimitCheck.attemptsRemaining - 1),
      });
    } else if (error instanceof UnauthorizedError) {
      logger.structuredWarn({
        category: "auth",
        action: "signin",
        outcome: "unauthorized",
        message: msg,
        email: normalizedEmail,
        ip: requesterIp,
        attemptsRemaining: Math.max(0, rateLimitCheck.attemptsRemaining - 1),
      });
    } else {
      logger.error("Signin failed with unexpected error", {
        email: normalizedEmail,
        error: msg,
        ip: requesterIp,
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
): Promise<SigninResult["user"]> {
  // Extract IP and user agent from Express request if available
  const req = (res as any).req;
  const enhancedOptions: SigninOptions = {
    ...options,
    requesterIp:
      options?.requesterIp || req?.ip || req?.connection?.remoteAddress,
    userAgent: options?.userAgent || req?.get?.("user-agent"),
  };

  const result = await signinCore(email, password, enhancedOptions);

  // Set authentication cookie
  res.cookie(authConfig.cookieName, result.token, result.cookieOptions);

  // Set additional security headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");

  // Set remember me cookie if requested
  if (options?.rememberMe) {
    res.cookie(`${authConfig.cookieName}_remember`, "true", {
      httpOnly: true,
      secure:
        authConfig.forceSecureCookies || process.env.NODE_ENV === "production",
      maxAge: result.cookieOptions.maxAge,
      sameSite: "lax",
      path: "/",
    });
  }

  // Add warning headers if password needs attention
  if (result.mustChangePassword) {
    res.setHeader("X-Password-Change-Required", "true");
  }
  if (result.passwordStrengthWarning) {
    res.setHeader("X-Password-Strength-Warning", "true");
  }

  return result.user;
}

// Cleanup on process termination
process.on("exit", () => {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
  }
  loginAttempts.clear();
});
