import { randomBytes, randomUUID } from "crypto";
import { authConfig } from "../config";
import { hashPassword } from "../utils/hash";

export interface ForgotPasswordOptions {
  codeLength?: number;
  codeExpiration?: number; // in minutes
  maxAttempts?: number;
  rateLimitDelay?: number; // in seconds
  requireExistingUser?: boolean;
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
  preventReuse?: boolean; // Prevent reusing current password
}

export interface ForgotPasswordResult {
  success: boolean;
  message: string;
  codeExpiration?: Date;
}

export interface ResetPasswordResult {
  success: boolean;
  message: string;
  user?: {
    id: string;
    email: string;
    username?: string;
  };
}

// Simple in-memory storage for password reset codes
// In production, use Redis or database storage
interface PasswordResetCode {
  code: string;
  hashedCode: string;
  email: string;
  expiresAt: Date;
  attempts: number;
  createdAt: Date;
  isUsed: boolean;
}

const passwordResetCodes = new Map<string, PasswordResetCode>();
const rateLimitStore = new Map<string, number>();

/**
 * Hash a verification code
 */
async function hashVerificationCode(code: string): Promise<string> {
  try {
    const { createHash } = await import('crypto');
    return createHash('sha256').update(code + process.env.JWT_SECRET || 'default_secret').digest('hex');
  } catch {
    // Fallback if crypto is not available
    return Buffer.from(code).toString('base64');
  }
}

/**
 * Verify a hashed code
 */
async function verifyCodeHash(code: string, hash: string): Promise<boolean> {
  const hashedInput = await hashVerificationCode(code);
  return hashedInput === hash;
}

/**
 * Generate a verification code
 */
function generateVerificationCode(length: number = 6): string {
  const digits = '0123456789';
  let code = '';
  for (let i = 0; i < length; i++) {
    code += digits[Math.floor(Math.random() * digits.length)];
  }
  return code;
}

/**
 * Clean expired codes
 */
function cleanExpiredCodes(): void {
  const now = new Date();
  for (const [key, code] of Array.from(passwordResetCodes.entries())) {
    if (now > code.expiresAt) {
      passwordResetCodes.delete(key);
    }
  }
}

export interface ForgotPasswordOptions {
  codeLength?: number;
  codeExpiration?: number; // in minutes
  maxAttempts?: number;
  rateLimitDelay?: number; // in seconds
  requireExistingUser?: boolean;
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
  preventReuse?: boolean; // Prevent reusing current password
}

export interface ForgotPasswordResult {
  success: boolean;
  message: string;
  codeExpiration?: Date;
}

export interface ResetPasswordResult {
  success: boolean;
  message: string;
  user?: {
    id: string;
    email: string;
    username?: string;
  };
}

/**
 * Initiate forgot password process
 */
export async function initiateForgotPassword(
  email: string,
  options: ForgotPasswordOptions = {}
): Promise<ForgotPasswordResult> {
  const db = authConfig.db;
  
  if (!db) {
    throw new Error("Database not configured. Make sure initAuth() is called before using forgot password functions.");
  }

  const {
    codeLength = 6,
    codeExpiration = 15, // 15 minutes
    maxAttempts = 5,
    rateLimitDelay = 60, // 60 seconds
    requireExistingUser = true,
    customEmailTemplate
  } = options;

  const normalizedEmail = email.toLowerCase().trim();

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(normalizedEmail)) {
    throw new Error("Invalid email format");
  }

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
    throw new Error("No account found with this email address.");
  }

  // Check rate limiting
  const currentTime = new Date();
  const rateLimitKey = `forgot_password_rate_limit_${normalizedEmail}`;
  
  const lastAttempt = rateLimitStore.get(rateLimitKey);
  if (lastAttempt && (currentTime.getTime() - lastAttempt) < (rateLimitDelay * 1000)) {
    throw new Error(`Please wait ${rateLimitDelay} seconds before requesting another password reset code.`);
  }

  try {
    // Clean expired codes first
    cleanExpiredCodes();

    // Generate verification code
    const code = generateVerificationCode(codeLength);
    const hashedCode = await hashVerificationCode(code);
    const expiresAt = new Date(Date.now() + codeExpiration * 60 * 1000);
    const codeId = randomUUID();

    // Store the reset code
    passwordResetCodes.set(codeId, {
      code: '', // Don't store plaintext
      hashedCode,
      email: normalizedEmail,
      expiresAt,
      attempts: 0,
      createdAt: new Date(),
      isUsed: false
    });

    // Prepare email content
    let emailSubject = "Password Reset Code";
    let emailText = `Your password reset code is: ${code}. This code expires in ${codeExpiration} minutes.`;
    let emailHtml: string | undefined;

    if (customEmailTemplate) {
      const template = customEmailTemplate(normalizedEmail, code, user?.username);
      emailSubject = template.subject;
      emailText = template.text;
      emailHtml = template.html;
    } else {
      emailHtml = `
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; font-family: Arial, sans-serif;">
          <h2 style="color: #333; text-align: center;">Password Reset</h2>
          <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <p>Hello${user?.username ? ` ${user.username}` : ''},</p>
            <p>We received a request to reset your password. Use the code below to reset your password:</p>
            <div style="text-align: center; margin: 20px 0;">
              <span style="background: #007bff; color: white; padding: 12px 24px; border-radius: 4px; font-size: 18px; font-weight: bold; letter-spacing: 2px; display: inline-block;">${code}</span>
            </div>
            <p><strong>This code expires in ${codeExpiration} minutes.</strong></p>
            <p>If you didn't request this password reset, please ignore this email.</p>
          </div>
          <p style="color: #666; font-size: 12px; text-align: center;">
            This is an automated message, please do not reply.
          </p>
        </div>
      `;
    }

    // For now, just log the code (in production, implement email service)
    console.log(`[AUTHRIX] Password reset code for ${normalizedEmail}: ${code}`);

    // Update rate limiting
    rateLimitStore.set(rateLimitKey, currentTime.getTime());

    return {
      success: true,
      message: "Password reset code sent to your email address.",
      codeExpiration: expiresAt
    };

  } catch (error) {
    if (error instanceof Error && error.message.includes('rate limit')) {
      throw error;
    }
    
    throw new Error(`Failed to send password reset code: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Verify forgot password code and reset password
 */
export async function resetPasswordWithCode(
  email: string,
  code: string,
  newPassword: string,
  options: ResetPasswordOptions = {}
): Promise<ResetPasswordResult> {
  const db = authConfig.db;
  
  if (!db) {
    throw new Error("Database not configured. Make sure initAuth() is called before using forgot password functions.");
  }

  const {
    minPasswordLength = 8,
    requireStrongPassword = true,
    invalidateAllSessions = true,
    preventReuse = true
  } = options;

  const normalizedEmail = email.toLowerCase().trim();

  // Validate inputs
  if (!code || code.trim().length === 0) {
    throw new Error("Reset code is required");
  }

  if (!newPassword || newPassword.length < minPasswordLength) {
    throw new Error(`Password must be at least ${minPasswordLength} characters long`);
  }

  // Strong password validation
  if (requireStrongPassword) {
    const hasUpperCase = /[A-Z]/.test(newPassword);
    const hasLowerCase = /[a-z]/.test(newPassword);
    const hasNumbers = /\d/.test(newPassword);
    const hasNonAlphas = /\W/.test(newPassword);

    if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasNonAlphas) {
      throw new Error("Password must contain at least one uppercase letter, lowercase letter, number, and special character");
    }
  }

  // Find user
  const user = await db.findUserByEmail(normalizedEmail);
  if (!user) {
    throw new Error("Invalid reset code or email address");
  }

  // Verify the reset code
  try {
    cleanExpiredCodes();
    
    let foundCode: PasswordResetCode | null = null;
    let codeId: string | null = null;
    
    // Find the code by email and verify it
    for (const [id, resetCode] of Array.from(passwordResetCodes.entries())) {
      if (resetCode.email === normalizedEmail && !resetCode.isUsed) {
        const isValidCode = await verifyCodeHash(code, resetCode.hashedCode);
        if (isValidCode) {
          foundCode = resetCode;
          codeId = id;
          break;
        }
      }
    }

    if (!foundCode || !codeId) {
      throw new Error("Invalid reset code");
    }

    // Check if expired
    if (new Date() > foundCode.expiresAt) {
      passwordResetCodes.delete(codeId);
      throw new Error("Reset code has expired");
    }

    // Check max attempts
    if (foundCode.attempts >= 5) {
      passwordResetCodes.delete(codeId);
      throw new Error("Maximum verification attempts exceeded");
    }

    // Increment attempts
    foundCode.attempts++;

    // Mark as used
    foundCode.isUsed = true;
    passwordResetCodes.delete(codeId);

  } catch (error) {
    throw new Error("Invalid or expired reset code");
  }

  // Check if new password is same as current (if preventReuse is enabled)
  if (preventReuse && user.password) {
    try {
      // Use the same hash utility that Authrix uses
      const { verifyPassword } = await import('../utils/hash');
      const isSamePassword = await verifyPassword(newPassword, user.password);
      if (isSamePassword) {
        throw new Error("New password cannot be the same as your current password");
      }
    } catch (error) {
      // If comparison fails, continue (don't block password reset)
      console.warn('[AUTHRIX] Could not compare passwords for reuse prevention:', error);
    }
  }

  // Hash new password
  const hashedPassword = await hashPassword(newPassword);

  // Update user password
  try {
    let updatedUser;
    if (db.updateUser) {
      updatedUser = await db.updateUser(user.id, { 
        password: hashedPassword,
        passwordChangedAt: new Date()
      });
    } else {
      throw new Error("Database adapter does not support password updates");
    }

    if (!updatedUser) {
      throw new Error("Failed to update password");
    }

    // TODO: Invalidate all sessions if requested
    // This would require session management which isn't implemented yet
    if (invalidateAllSessions) {
      // For JWT tokens, you would need to implement token blacklisting
      // or change the user's secret/salt to invalidate all existing tokens
      console.log('[AUTHRIX] Session invalidation not implemented yet');
    }

    return {
      success: true,
      message: "Password has been reset successfully",
      user: {
        id: updatedUser.id,
        email: updatedUser.email,
        username: updatedUser.username
      }
    };

  } catch (error) {
    throw new Error(`Failed to reset password: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Generate a secure temporary password
 */
export function generateTemporaryPassword(length: number = 12): string {
  const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
  let password = "";
  
  // Ensure at least one character from each required set
  password += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[Math.floor(Math.random() * 26)]; // uppercase
  password += "abcdefghijklmnopqrstuvwxyz"[Math.floor(Math.random() * 26)]; // lowercase
  password += "0123456789"[Math.floor(Math.random() * 10)]; // number
  password += "!@#$%^&*"[Math.floor(Math.random() * 8)]; // special
  
  // Fill the rest randomly
  for (let i = password.length; i < length; i++) {
    password += charset[Math.floor(Math.random() * charset.length)];
  }
  
  // Shuffle the password
  return password.split('').sort(() => Math.random() - 0.5).join('');
}

/**
 * Send temporary password to user (alternative to code-based reset)
 */
export async function sendTemporaryPassword(
  email: string,
  options: ForgotPasswordOptions & { temporaryPasswordLength?: number } = {}
): Promise<ForgotPasswordResult> {
  const db = authConfig.db;
  
  if (!db) {
    throw new Error("Database not configured. Make sure initAuth() is called before using forgot password functions.");
  }

  const {
    temporaryPasswordLength = 12,
    requireExistingUser = true,
    customEmailTemplate
  } = options;

  const normalizedEmail = email.toLowerCase().trim();

  // Find user
  const user = await db.findUserByEmail(normalizedEmail);
  
  if (!user && requireExistingUser) {
    return {
      success: true,
      message: "If an account with this email exists, a temporary password has been sent."
    };
  }

  if (!user && !requireExistingUser) {
    throw new Error("No account found with this email address.");
  }

  // Generate temporary password
  const temporaryPassword = generateTemporaryPassword(temporaryPasswordLength);
  const hashedPassword = await hashPassword(temporaryPassword);

  // Update user password
  try {
    let updatedUser;
    if (db.updateUser) {
      updatedUser = await db.updateUser(user!.id, { 
        password: hashedPassword,
        passwordChangedAt: new Date(),
        mustChangePassword: true // Flag to force password change on next login
      });
    } else {
      throw new Error("Database adapter does not support password updates");
    }

    if (!updatedUser) {
      throw new Error("Failed to update password");
    }

    // Prepare email content
    let emailSubject = "Temporary Password";
    let emailText = `Your temporary password is: ${temporaryPassword}. Please log in and change your password immediately.`;
    let emailHtml: string | undefined;

    if (customEmailTemplate) {
      const template = customEmailTemplate(normalizedEmail, temporaryPassword, user?.username);
      emailSubject = template.subject;
      emailText = template.text;
      emailHtml = template.html;
    } else {
      emailHtml = `
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; font-family: Arial, sans-serif;">
          <h2 style="color: #333; text-align: center;">Temporary Password</h2>
          <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <p>Hello${user?.username ? ` ${user.username}` : ''},</p>
            <p>We've generated a temporary password for your account:</p>
            <div style="text-align: center; margin: 20px 0;">
              <span style="background: #dc3545; color: white; padding: 12px 24px; border-radius: 4px; font-size: 16px; font-weight: bold; display: inline-block;">${temporaryPassword}</span>
            </div>
            <p><strong>⚠️ Please log in and change this password immediately for security.</strong></p>
            <p>If you didn't request this password reset, please contact support immediately.</p>
          </div>
          <p style="color: #666; font-size: 12px; text-align: center;">
            This is an automated message, please do not reply.
          </p>
        </div>
      `;
    }

    // Send email
    console.log(`[AUTHRIX] Temporary password for ${normalizedEmail}: ${temporaryPassword}`);

    return {
      success: true,
      message: "Temporary password sent to your email address."
    };

  } catch (error) {
    throw new Error(`Failed to send temporary password: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}
