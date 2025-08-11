import { randomUUID } from "crypto";
import { authConfig } from "../config";
import { hashPassword, verifyPassword, validatePassword, generateSecurePassword } from "../utils/hash";
import { BadRequestError, UnauthorizedError, InternalServerError } from "../utils/errors";
import { generateTwoFactorCode, verifyTwoFactorCode } from "./twoFactor";

export interface ForgotPasswordOptions {
  codeLength?: number;
  codeExpiration?: number; // in minutes
  maxAttempts?: number;
  rateLimitDelay?: number; // in seconds
  requireExistingUser?: boolean;
  useEmailService?: boolean; // Use 2FA email service instead of console logging
  customEmailTemplate?: (email: string, code: string, username?: string) => {
    subject: string;
    text: string;
    html?: string;
  };
}

export interface ResetPasswordOptions {
  minPasswordLength?: number;
  requireStrongPassword?: boolean;
  invalidateAllSessions?: boolean;
  preventReuse?: boolean;
  skipPasswordValidation?: boolean; // For backward compatibility
}

export interface ForgotPasswordResult {
  success: boolean;
  message: string;
  codeId?: string;
  codeExpiration?: Date;
  attemptsRemaining?: number;
}

export interface ResetPasswordResult {
  success: boolean;
  message: string;
  user?: {
    id: string;
    email: string;
    username?: string;
  };
  mustChangePassword?: boolean;
}

// Rate limiting for password reset requests
const rateLimitStore = new Map<string, {
  count: number;
  lastAttempt: number;
  blockedUntil?: number;
}>();

/**
 * Enhanced rate limiting with progressive blocking
 */
function checkPasswordResetRateLimit(email: string, rateLimitDelay: number = 60): {
  allowed: boolean;
  attemptsRemaining: number;
  blockedUntil?: Date;
  nextAttemptIn?: number;
} {
  const now = Date.now();
  const rateLimitKey = `forgot_password_${email}`;
  const maxAttemptsPerHour = 3;
  const windowMs = 60 * 60 * 1000; // 1 hour

  const attempts = rateLimitStore.get(rateLimitKey);

  if (!attempts) {
    rateLimitStore.set(rateLimitKey, { count: 1, lastAttempt: now });
    return { allowed: true, attemptsRemaining: maxAttemptsPerHour - 1 };
  }

  // Check if currently blocked
  if (attempts.blockedUntil && now < attempts.blockedUntil) {
    return {
      allowed: false,
      attemptsRemaining: 0,
      blockedUntil: new Date(attempts.blockedUntil),
      nextAttemptIn: Math.ceil((attempts.blockedUntil - now) / 1000)
    };
  }

  // Reset if window has passed
  if (now - attempts.lastAttempt > windowMs) {
    rateLimitStore.set(rateLimitKey, { count: 1, lastAttempt: now });
    return { allowed: true, attemptsRemaining: maxAttemptsPerHour - 1 };
  }

  // Check basic rate limit (time between requests)
  if (now - attempts.lastAttempt < rateLimitDelay * 1000) {
    return {
      allowed: false,
      attemptsRemaining: maxAttemptsPerHour - attempts.count,
      nextAttemptIn: Math.ceil((rateLimitDelay * 1000 - (now - attempts.lastAttempt)) / 1000)
    };
  }

  // Increment attempts
  attempts.count++;
  attempts.lastAttempt = now;

  // Check if should be blocked
  if (attempts.count >= maxAttemptsPerHour) {
    const blockDuration = 60 * 60 * 1000; // 1 hour block
    attempts.blockedUntil = now + blockDuration;
    return {
      allowed: false,
      attemptsRemaining: 0,
      blockedUntil: new Date(attempts.blockedUntil)
    };
  }

  return {
    allowed: true,
    attemptsRemaining: maxAttemptsPerHour - attempts.count
  };
}

/**
 * Clear rate limit for successful password reset
 */
function clearPasswordResetRateLimit(email: string): void {
  rateLimitStore.delete(`forgot_password_${email}`);
}

/**
 * Enhanced forgot password initiation with 2FA integration
 */
export async function initiateForgotPassword(
  email: string,
  options: ForgotPasswordOptions = {}
): Promise<ForgotPasswordResult> {
  const db = authConfig.db;

  if (!db) {
    throw new InternalServerError("Database not configured. Make sure initAuth() is called before using forgot password functions.");
  }

  const {
    codeLength = 6,
    codeExpiration = 15, // 15 minutes
    maxAttempts = 3,
    rateLimitDelay = 60, // 60 seconds
    requireExistingUser = true,
    useEmailService = true,
    customEmailTemplate
  } = options;

  // Input validation
  if (!email?.trim()) {
    throw new BadRequestError("Email is required");
  }

  const normalizedEmail = email.toLowerCase().trim();

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(normalizedEmail)) {
    throw new BadRequestError("Invalid email format");
  }

  // Check rate limiting
  const rateLimitCheck = checkPasswordResetRateLimit(normalizedEmail, rateLimitDelay);
  if (!rateLimitCheck.allowed) {
    const message = rateLimitCheck.blockedUntil
      ? `Too many password reset attempts. Try again after ${rateLimitCheck.blockedUntil.toLocaleTimeString()}`
      : `Please wait ${rateLimitCheck.nextAttemptIn} seconds before requesting another password reset code.`;
    throw new BadRequestError(message);
  }

  try {
    // Check if user exists
    const user = await db.findUserByEmail(normalizedEmail);

    if (!user && requireExistingUser) {
      // For security, don't reveal if user exists or not
      return {
        success: true,
        message: "If an account with this email exists, a password reset code has been sent."
      };
    }

    if (!user && !requireExistingUser) {
      throw new BadRequestError("No account found with this email address.");
    }

    // Use 2FA system for code generation and sending
    if (useEmailService) {
      try {
        const { initiateEmailVerification } = await import('./twoFactor');

        const result = await initiateEmailVerification(user!.id, normalizedEmail, {
          codeLength,
          expiryMinutes: codeExpiration,
          subject: "Password Reset Code",
          metadata: {
            purpose: 'password_reset',
            username: user?.username
          }
        });

        return {
          success: true,
          message: "Password reset code sent to your email address.",
          codeId: result.codeId,
          codeExpiration: result.expiresAt,
          attemptsRemaining: result.attemptsRemaining
        };

      } catch (error) {
        console.error('[AUTHRIX] Failed to send password reset email:', error);
        // Fallback to console logging
        console.log(`[AUTHRIX] Email service failed, check configuration`);
      }
    }

    // Fallback: Generate code using 2FA system but log to console
    const { code, codeId, expiresAt } = await generateTwoFactorCode(user!.id, {
      type: 'password_reset',
      codeLength,
      expiryMinutes: codeExpiration,
      metadata: { email: normalizedEmail, purpose: 'password_reset' }
    });

    // Log code to console (development/fallback)
    console.log(`[AUTHRIX] Password reset code for ${normalizedEmail}: ${code}`);
    console.log(`[AUTHRIX] Code expires at: ${expiresAt.toLocaleString()}`);

    return {
      success: true,
      message: "Password reset code sent to your email address.",
      codeId,
      codeExpiration: expiresAt
    };

  } catch (error) {
    console.error('[AUTHRIX] Forgot password error:', error);

    if (error instanceof BadRequestError) {
      throw error;
    }

    throw new InternalServerError(`Failed to send password reset code: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Enhanced password reset with improved validation and security
 */
export async function resetPasswordWithCode(
  email: string,
  code: string,
  newPassword: string,
  options: ResetPasswordOptions = {}
): Promise<ResetPasswordResult> {
  const db = authConfig.db;

  if (!db) {
    throw new InternalServerError("Database not configured. Make sure initAuth() is called before using forgot password functions.");
  }

  const {
    minPasswordLength = 8,
    requireStrongPassword = true,
    invalidateAllSessions = true,
    preventReuse = true,
    skipPasswordValidation = false
  } = options;

  // Input validation
  if (!email?.trim()) {
    throw new BadRequestError("Email is required");
  }

  if (!code?.trim()) {
    throw new BadRequestError("Reset code is required");
  }

  if (!newPassword?.trim()) {
    throw new BadRequestError("New password is required");
  }

  const normalizedEmail = email.toLowerCase().trim();

  // Password validation
  if (!skipPasswordValidation) {
    if (requireStrongPassword) {
      const validation = validatePassword(newPassword);
      if (!validation.isValid) {
        throw new BadRequestError(`Password validation failed: ${validation.errors.join(', ')}`);
      }
    } else if (newPassword.length < minPasswordLength) {
      throw new BadRequestError(`Password must be at least ${minPasswordLength} characters long`);
    }
  }

  try {
    // Find user
    const user = await db.findUserByEmail(normalizedEmail);
    if (!user) {
      throw new UnauthorizedError("Invalid reset code or email address");
    }

    // Get user's active password reset codes
    const { getUserTwoFactorCodes } = await import('./twoFactor');
    const userCodes = await getUserTwoFactorCodes(user.id, 'password_reset');

    if (userCodes.length === 0) {
      throw new UnauthorizedError("No valid reset code found. Please request a new password reset.");
    }

    // Try to verify the code with any of the user's active codes
    let verificationResult = null;
    let validCodeId = null;

    for (const userCode of userCodes) {
      if (!userCode.isUsed && new Date() <= userCode.expiresAt) {
        const result = await verifyTwoFactorCode(userCode.id, code, user.id);
        if (result.isValid) {
          verificationResult = result;
          validCodeId = userCode.id;
          break;
        }
      }
    }

    if (!verificationResult || !verificationResult.isValid) {
      throw new UnauthorizedError("Invalid or expired reset code");
    }

    // Check if new password is same as current (if preventReuse is enabled)
    if (preventReuse && user.password) {
      try {
        const isSamePassword = await verifyPassword(newPassword, user.password);
        if (isSamePassword) {
          throw new BadRequestError("New password cannot be the same as your current password");
        }
      } catch (error) {
        // If comparison fails, continue (don't block password reset)
        console.warn('[AUTHRIX] Could not compare passwords for reuse prevention:', error);
      }
    }

    // Hash new password
    const hashedPassword = await hashPassword(newPassword, {
      skipValidation: skipPasswordValidation
    });

    // Update user password
    let updatedUser;
    if (db.updateUser) {
      updatedUser = await db.updateUser(user.id, {
        password: hashedPassword,
        passwordChangedAt: new Date(),
        mustChangePassword: false // Reset the flag since they just changed it
      });
    } else {
      throw new InternalServerError("Database adapter does not support password updates");
    }

    if (!updatedUser) {
      throw new InternalServerError("Failed to update password");
    }

    // Clear rate limiting on successful reset
    clearPasswordResetRateLimit(normalizedEmail);

    // TODO: Invalidate all sessions if requested
    if (invalidateAllSessions) {
      console.log('[AUTHRIX] Session invalidation not implemented yet');
      // This would require:
      // 1. Token blacklisting for JWTs
      // 2. Session management in database
      // 3. User token version/salt update
    }

    return {
      success: true,
      message: "Password has been reset successfully",
      user: {
        id: updatedUser.id,
        email: updatedUser.email,
        username: updatedUser.username
      },
      mustChangePassword: false
    };

  } catch (error) {
    console.error('[AUTHRIX] Password reset error:', error);

    if (error instanceof BadRequestError || error instanceof UnauthorizedError) {
      throw error;
    }

    throw new InternalServerError(`Failed to reset password: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Enhanced temporary password generation with better security
 */
export function generateTemporaryPassword(length: number = 12): string {
  if (length < 8 || length > 32) {
    throw new BadRequestError('Temporary password length must be between 8 and 32 characters');
  }

  return generateSecurePassword(length, {
    includeLowercase: true,
    includeUppercase: true,
    includeNumbers: true,
    includeSymbols: true,
    excludeSimilar: true
  });
}

/**
 * Enhanced temporary password sending with 2FA integration
 */
export async function sendTemporaryPassword(
  email: string,
  options: ForgotPasswordOptions & { temporaryPasswordLength?: number } = {}
): Promise<ForgotPasswordResult> {
  const db = authConfig.db;

  if (!db) {
    throw new InternalServerError("Database not configured. Make sure initAuth() is called before using forgot password functions.");
  }

  const {
    temporaryPasswordLength = 12,
    requireExistingUser = true,
    customEmailTemplate,
    rateLimitDelay = 60
  } = options;

  // Input validation
  if (!email?.trim()) {
    throw new BadRequestError("Email is required");
  }

  const normalizedEmail = email.toLowerCase().trim();

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(normalizedEmail)) {
    throw new BadRequestError("Invalid email format");
  }

  // Check rate limiting
  const rateLimitCheck = checkPasswordResetRateLimit(normalizedEmail, rateLimitDelay);
  if (!rateLimitCheck.allowed) {
    const message = rateLimitCheck.blockedUntil
      ? `Too many password reset attempts. Try again after ${rateLimitCheck.blockedUntil.toLocaleTimeString()}`
      : `Please wait ${rateLimitCheck.nextAttemptIn} seconds before requesting another temporary password.`;
    throw new BadRequestError(message);
  }

  try {
    // Find user
    const user = await db.findUserByEmail(normalizedEmail);

    if (!user && requireExistingUser) {
      return {
        success: true,
        message: "If an account with this email exists, a temporary password has been sent."
      };
    }

    if (!user && !requireExistingUser) {
      throw new BadRequestError("No account found with this email address.");
    }

    // Generate secure temporary password
    const temporaryPassword = generateTemporaryPassword(temporaryPasswordLength);
    const hashedPassword = await hashPassword(temporaryPassword);

    // Update user password
    let updatedUser;
    if (db.updateUser) {
      updatedUser = await db.updateUser(user!.id, {
        password: hashedPassword,
        passwordChangedAt: new Date(),
        mustChangePassword: true // Force password change on next login
      });
    } else {
      throw new InternalServerError("Database adapter does not support password updates");
    }

    if (!updatedUser) {
      throw new InternalServerError("Failed to update password");
    }

    // Clear rate limiting on successful operation
    clearPasswordResetRateLimit(normalizedEmail);

    // Log temporary password (in production, send via email service)
    console.log(`[AUTHRIX] Temporary password for ${normalizedEmail}: ${temporaryPassword}`);
    console.log(`[AUTHRIX] User must change password on next login`);

    return {
      success: true,
      message: "Temporary password sent to your email address. Please log in and change your password immediately."
    };

  } catch (error) {
    console.error('[AUTHRIX] Temporary password error:', error);

    if (error instanceof BadRequestError) {
      throw error;
    }

    throw new InternalServerError(`Failed to send temporary password: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Clear rate limit store (for testing purposes)
 */
export function clearRateLimitStore(): void {
  rateLimitStore.clear();
}

/**
 * Get password reset statistics (for admin/monitoring)
 */
export function getPasswordResetStats(): {
  activeRateLimits: number;
  blockedEmails: string[];
  totalAttempts: number;
} {
  const now = Date.now();
  let totalAttempts = 0;
  const blockedEmails: string[] = [];

  for (const [key, attempts] of Array.from(rateLimitStore.entries())) {
    totalAttempts += attempts.count;

    if (attempts.blockedUntil && now < attempts.blockedUntil) {
      const email = key.replace('forgot_password_', '');
      blockedEmails.push(email);
    }
  }

  return {
    activeRateLimits: rateLimitStore.size,
    blockedEmails,
    totalAttempts
  };
}
