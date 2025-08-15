import crypto from "crypto";
import { authConfig } from "../config";
import { EmailServiceRegistry as UnifiedEmailServiceRegistry } from "./emailRegistry";
import { BadRequestError, InternalServerError } from "../utils/errors";

export interface TwoFactorCode {
  id: string;
  userId: string;
  code: string;
  hashedCode: string;
  type: 'email_verification' | 'password_reset' | 'login_verification' | 'phone_verification';
  expiresAt: Date;
  createdAt: Date;
  attempts: number;
  isUsed: boolean;
  metadata?: {
    email?: string;
    phone?: string;
    ipAddress?: string;
    userAgent?: string;
    purpose?: string;
    [key: string]: any;
  };
}

export interface TwoFactorOptions {
  codeLength?: number;
  expiryMinutes?: number;
  maxAttempts?: number;
  type?: 'email_verification' | 'password_reset' | 'login_verification' | 'phone_verification';
  metadata?: {
    email?: string;
    phone?: string;
    ipAddress?: string;
    userAgent?: string;
    purpose?: string;
    [key: string]: any;
  };
}

export interface EmailService {
  sendVerificationEmail(to: string, code: string, options?: {
    subject?: string;
    template?: string;
    metadata?: any;
  }): Promise<void>;
}

export interface SMSService {
  sendVerificationSMS(to: string, code: string, options?: {
    template?: string;
    metadata?: any;
  }): Promise<void>;
}

// Enhanced configuration with better defaults
const DEFAULT_CODE_LENGTH = 6;
const DEFAULT_EXPIRY_MINUTES = 10;
const DEFAULT_MAX_ATTEMPTS = 3;
const MAX_CODE_GENERATIONS_PER_HOUR = 5;
const CODE_GENERATION_WINDOW = 60 * 60 * 1000; // 1 hour

// Rate limiting for code generation (per email/user)
const codeGenerationAttempts = new Map<string, {
  count: number;
  lastAttempt: number;
  blockedUntil?: number;
}>();

/**
 * Generate a cryptographically secure random verification code
 */
export function generateVerificationCode(length: number = DEFAULT_CODE_LENGTH): string {
  if (length < 4 || length > 12) {
    throw new BadRequestError('Code length must be between 4 and 12 characters');
  }

  // Use crypto.randomInt for cryptographically secure random numbers
  let code = '';
  for (let i = 0; i < length; i++) {
    code += crypto.randomInt(0, 10).toString();
  }
  return code;
}

/**
 * Hash a verification code for secure storage
 */
export async function hashVerificationCode(code: string): Promise<string> {
  try {
    const bcrypt = await import('bcryptjs');
    return bcrypt.hash(code, 12);
  } catch (error) {
    throw new InternalServerError('Failed to hash verification code');
  }
}

/**
 * Verify a verification code against its hash
 */
export async function verifyCodeHash(code: string, hashedCode: string): Promise<boolean> {
  try {
    const bcrypt = await import('bcryptjs');
    return bcrypt.compare(code, hashedCode);
  } catch (error) {
    console.error('[AUTHRIX] Code verification error:', error);
    return false;
  }
}

/**
 * Enhanced rate limiting for code generation with progressive blocking
 */
function checkCodeGenerationRateLimit(identifier: string): {
  allowed: boolean;
  attemptsRemaining: number;
  blockedUntil?: Date;
} {
  const now = Date.now();
  const attempts = codeGenerationAttempts.get(identifier);

  if (!attempts) {
    codeGenerationAttempts.set(identifier, { count: 1, lastAttempt: now });
    return { allowed: true, attemptsRemaining: MAX_CODE_GENERATIONS_PER_HOUR - 1 };
  }

  // Check if currently blocked
  if (attempts.blockedUntil && now < attempts.blockedUntil) {
    return {
      allowed: false,
      attemptsRemaining: 0,
      blockedUntil: new Date(attempts.blockedUntil)
    };
  }

  // Reset counter if window has passed
  if (now - attempts.lastAttempt > CODE_GENERATION_WINDOW) {
    codeGenerationAttempts.set(identifier, { count: 1, lastAttempt: now });
    return { allowed: true, attemptsRemaining: MAX_CODE_GENERATIONS_PER_HOUR - 1 };
  }

  // Check if under limit
  if (attempts.count < MAX_CODE_GENERATIONS_PER_HOUR) {
    attempts.count++;
    attempts.lastAttempt = now;
    return {
      allowed: true,
      attemptsRemaining: MAX_CODE_GENERATIONS_PER_HOUR - attempts.count
    };
  }

  // Block for progressive duration based on repeated violations
  const blockDuration = Math.min(60 * 60 * 1000, 15 * 60 * 1000 * Math.pow(2, attempts.count - MAX_CODE_GENERATIONS_PER_HOUR));
  attempts.blockedUntil = now + blockDuration;

  return {
    allowed: false,
    attemptsRemaining: 0,
    blockedUntil: new Date(attempts.blockedUntil)
  };
}

/**
 * Generate and store a 2FA verification code with enhanced security
 */
export async function generateTwoFactorCode(
  userId: string,
  options: TwoFactorOptions = {}
): Promise<{ code: string; codeId: string; expiresAt: Date; attemptsRemaining: number }> {
  const db = authConfig.db;
  if (!db || !('storeTwoFactorCode' in db)) {
    throw new InternalServerError('Database adapter does not support 2FA. Please use an adapter that implements storeTwoFactorCode.');
  }

  const {
    codeLength = DEFAULT_CODE_LENGTH,
    expiryMinutes = DEFAULT_EXPIRY_MINUTES,
    maxAttempts = DEFAULT_MAX_ATTEMPTS,
    type = 'email_verification',
    metadata = {}
  } = options;

  // Input validation
  if (!userId?.trim()) {
    throw new BadRequestError('User ID is required');
  }

  // Rate limiting check
  const identifier = metadata.email || metadata.phone || userId;
  const rateLimitResult = checkCodeGenerationRateLimit(identifier);

  if (!rateLimitResult.allowed) {
    const message = rateLimitResult.blockedUntil
      ? `Too many verification code requests. Try again after ${rateLimitResult.blockedUntil.toLocaleTimeString()}`
      : 'Too many verification code requests. Please try again later.';
    throw new BadRequestError(message);
  }

  try {
    // Generate code and expiry
    const code = generateVerificationCode(codeLength);
    const hashedCode = await hashVerificationCode(code);
    const expiresAt = new Date(Date.now() + expiryMinutes * 60 * 1000);
    const codeId = crypto.randomUUID();

    const twoFactorCode: TwoFactorCode = {
      id: codeId,
      userId,
      code: '', // Never store plain text code
      hashedCode,
      type,
      expiresAt,
      createdAt: new Date(),
      attempts: 0,
      isUsed: false,
      metadata: {
        ...metadata,
        generatedAt: new Date().toISOString(),
        ipAddress: metadata.ipAddress,
        userAgent: metadata.userAgent
      }
    };

    // Store in database
    await (db as any).storeTwoFactorCode(twoFactorCode);

    return {
      code, // Return plain text code for sending
      codeId,
      expiresAt,
      attemptsRemaining: rateLimitResult.attemptsRemaining
    };

  } catch (error) {
    console.error('[AUTHRIX] Failed to generate 2FA code:', error);
    throw new InternalServerError('Failed to generate verification code');
  }
}

/**
 * Verify a 2FA code with enhanced security and logging
 */
export async function verifyTwoFactorCode(
  codeId: string,
  inputCode: string,
  userId?: string
): Promise<{
  isValid: boolean;
  isExpired: boolean;
  attemptsRemaining: number;
  error?: string;
  metadata?: any;
}> {
  const db = authConfig.db;
  if (!db || !('getTwoFactorCode' in db) || !('updateTwoFactorCode' in db)) {
    throw new InternalServerError('Database adapter does not support 2FA operations.');
  }

  // Input validation
  if (!codeId?.trim() || !inputCode?.trim()) {
    return {
      isValid: false,
      isExpired: false,
      attemptsRemaining: 0,
      error: 'Code ID and verification code are required'
    };
  }

  try {
    const storedCode = await (db as any).getTwoFactorCode(codeId);

    if (!storedCode) {
      return {
        isValid: false,
        isExpired: false,
        attemptsRemaining: 0,
        error: 'Invalid verification code'
      };
    }

    // Check if code belongs to the user (if userId provided)
    if (userId && storedCode.userId !== userId) {
      return {
        isValid: false,
        isExpired: false,
        attemptsRemaining: 0,
        error: 'Invalid verification code'
      };
    }

    // Check if already used
    if (storedCode.isUsed) {
      return {
        isValid: false,
        isExpired: false,
        attemptsRemaining: 0,
        error: 'Verification code has already been used'
      };
    }

    // Check expiry
    if (new Date() > storedCode.expiresAt) {
      return {
        isValid: false,
        isExpired: true,
        attemptsRemaining: 0,
        error: 'Verification code has expired'
      };
    }

    // Check max attempts
    const maxAttempts = DEFAULT_MAX_ATTEMPTS;
    if (storedCode.attempts >= maxAttempts) {
      return {
        isValid: false,
        isExpired: false,
        attemptsRemaining: 0,
        error: 'Maximum verification attempts exceeded'
      };
    }

    // Increment attempts
    const newAttemptCount = storedCode.attempts + 1;
    await (db as any).updateTwoFactorCode(codeId, {
      attempts: newAttemptCount,
      lastAttemptAt: new Date()
    });

    // Verify the code
    const isValidCode = await verifyCodeHash(inputCode, storedCode.hashedCode);

    if (isValidCode) {
      // Mark as used
      await (db as any).updateTwoFactorCode(codeId, {
        isUsed: true,
        usedAt: new Date()
      });

      return {
        isValid: true,
        isExpired: false,
        attemptsRemaining: maxAttempts - newAttemptCount,
        metadata: storedCode.metadata
      };
    }

    return {
      isValid: false,
      isExpired: false,
      attemptsRemaining: maxAttempts - newAttemptCount,
      error: 'Invalid verification code'
    };

  } catch (error) {
    console.error('[AUTHRIX] Error verifying 2FA code:', error);
    return {
      isValid: false,
      isExpired: false,
      attemptsRemaining: 0,
      error: 'An error occurred during verification'
    };
  }
}

/**
 * Clean up expired 2FA codes and rate limit data
 */
export async function cleanupExpiredCodes(): Promise<{
  codesDeleted: number;
  rateLimitEntriesCleared: number;
}> {
  const db = authConfig.db;
  let codesDeleted = 0;

  if (db && 'cleanupExpiredTwoFactorCodes' in db) {
    try {
      codesDeleted = await (db as any).cleanupExpiredTwoFactorCodes();
    } catch (error) {
      console.error('[AUTHRIX] Error cleaning up expired 2FA codes:', error);
    }
  }

  // Clean up rate limit data
  const now = Date.now();
  let rateLimitEntriesCleared = 0;

  for (const [key, attempts] of Array.from(codeGenerationAttempts.entries())) {
    const shouldClear = (
      (!attempts.blockedUntil && now - attempts.lastAttempt > CODE_GENERATION_WINDOW) ||
      (attempts.blockedUntil && now > attempts.blockedUntil)
    );

    if (shouldClear) {
      codeGenerationAttempts.delete(key);
      rateLimitEntriesCleared++;
    }
  }

  return { codesDeleted, rateLimitEntriesCleared };
}

/**
 * Get user's active 2FA codes (for debugging/admin purposes)
 */
export async function getUserTwoFactorCodes(
  userId: string,
  type?: string
): Promise<TwoFactorCode[]> {
  const db = authConfig.db;
  if (!db || !('getUserTwoFactorCodes' in db)) {
    return [];
  }

  try {
    return await (db as any).getUserTwoFactorCodes(userId, type);
  } catch (error) {
    console.error('[AUTHRIX] Error getting user 2FA codes:', error);
    return [];
  }
}

/**
 * Enhanced email service registry with validation
 */
// Deprecated: Use unified registry from './emailRegistry'
// Keeping type exports above for back-compat, but delegate all lookups to unified registry.

/**
 * Send verification email using configured email service
 */
export async function sendVerificationEmail(
  email: string,
  code: string,
  options: {
    serviceName?: string;
    subject?: string;
    template?: string;
    metadata?: any;
  } = {}
): Promise<void> {
  const {
    serviceName = 'default',
    subject = 'Email Verification Code',
    template,
    metadata
  } = options;

  // Input validation
  if (!email?.trim()) {
    throw new BadRequestError('Email address is required');
  }

  if (!code?.trim()) {
    throw new BadRequestError('Verification code is required');
  }

  const resolvedService = UnifiedEmailServiceRegistry.get(serviceName) || UnifiedEmailServiceRegistry.getDefault();
  if (!resolvedService) {
    throw new InternalServerError(`Email service '${serviceName}' not configured. Please register an email service.`);
  }

  try {
    await resolvedService.sendVerificationEmail(email, code, {
      subject,
      template,
      metadata
    });
  } catch (_error) {
    // Avoid leaking details (e.g., whether email exists or provider specifics)
    throw new InternalServerError('Failed to send verification email');
  }
}

/**
 * Send verification SMS using configured SMS service
 */
export async function sendVerificationSMS(
  phone: string,
  code: string,
  options: {
    serviceName?: string;
    template?: string;
    metadata?: any;
  } = {}
): Promise<void> {
  const {
    serviceName = 'default',
    template,
    metadata
  } = options;

  // Input validation
  if (!phone?.trim()) {
    throw new BadRequestError('Phone number is required');
  }

  if (!code?.trim()) {
    throw new BadRequestError('Verification code is required');
  }

  const resolvedSms = UnifiedEmailServiceRegistry.getSMS(serviceName) || UnifiedEmailServiceRegistry.getDefaultSMS();
  if (!resolvedSms) {
    throw new InternalServerError(`SMS service '${serviceName}' not configured. Please register an SMS service.`);
  }

  try {
    await resolvedSms.sendVerificationSMS(phone, code, {
      template,
      metadata
    });
  } catch (_error) {
    // Avoid leaking details
    throw new InternalServerError('Failed to send verification SMS');
  }
}

/**
 * Complete email verification workflow
 */
export async function initiateEmailVerification(
  userId: string,
  email: string,
  options: {
    serviceName?: string;
    subject?: string;
    template?: string;
    codeLength?: number;
    expiryMinutes?: number;
    metadata?: any;
  } = {}
): Promise<{
  codeId: string;
  expiresAt: Date;
  message: string;
  attemptsRemaining: number;
}> {
  const {
    serviceName,
    subject,
    template,
    codeLength,
    expiryMinutes,
    metadata = {}
  } = options;

  // Generate verification code
  const { code, codeId, expiresAt, attemptsRemaining } = await generateTwoFactorCode(userId, {
    type: 'email_verification',
    codeLength,
    expiryMinutes,
    metadata: { ...metadata, email }
  });

  // Send email
  await sendVerificationEmail(email, code, {
    serviceName,
    subject,
    template,
    metadata: { ...metadata, userId, codeId }
  });

  return {
    codeId,
    expiresAt,
    attemptsRemaining,
    message: `Verification code sent to ${email}. Code expires in ${expiryMinutes || DEFAULT_EXPIRY_MINUTES} minutes.`
  };
}

/**
 * Complete SMS verification workflow
 */
export async function initiateSMSVerification(
  userId: string,
  phone: string,
  options: {
    serviceName?: string;
    template?: string;
    codeLength?: number;
    expiryMinutes?: number;
    metadata?: any;
  } = {}
): Promise<{
  codeId: string;
  expiresAt: Date;
  message: string;
  attemptsRemaining: number;
}> {
  const {
    serviceName,
    template,
    codeLength,
    expiryMinutes,
    metadata = {}
  } = options;

  // Generate verification code
  const { code, codeId, expiresAt, attemptsRemaining } = await generateTwoFactorCode(userId, {
    type: 'phone_verification',
    codeLength,
    expiryMinutes,
    metadata: { ...metadata, phone }
  });

  // Send SMS
  await sendVerificationSMS(phone, code, {
    serviceName,
    template,
    metadata: { ...metadata, userId, codeId }
  });

  return {
    codeId,
    expiresAt,
    attemptsRemaining,
    message: `Verification code sent to ${phone}. Code expires in ${expiryMinutes || DEFAULT_EXPIRY_MINUTES} minutes.`
  };
}
