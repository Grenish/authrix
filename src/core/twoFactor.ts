import crypto from "crypto";
import { authConfig } from "../config";
import { AuthUser } from "../types/db";

export interface TwoFactorCode {
  id: string;
  userId: string;
  code: string;
  hashedCode: string;
  type: 'email_verification' | 'password_reset' | 'login_verification';
  expiresAt: Date;
  createdAt: Date;
  attempts: number;
  isUsed: boolean;
  metadata?: {
    email?: string;
    ipAddress?: string;
    userAgent?: string;
  };
}

export interface TwoFactorOptions {
  codeLength?: number;
  expiryMinutes?: number;
  maxAttempts?: number;
  type?: 'email_verification' | 'password_reset' | 'login_verification';
  metadata?: {
    email?: string;
    ipAddress?: string;
    userAgent?: string;
  };
}

export interface EmailService {
  sendVerificationEmail(to: string, code: string, options?: {
    subject?: string;
    template?: string;
    metadata?: any;
  }): Promise<void>;
}

// Default configuration
const DEFAULT_CODE_LENGTH = 6;
const DEFAULT_EXPIRY_MINUTES = 10;
const DEFAULT_MAX_ATTEMPTS = 3;

// Rate limiting for code generation (per email/user)
const codeGenerationAttempts = new Map<string, { count: number; lastAttempt: number }>();
const MAX_CODE_GENERATIONS_PER_HOUR = 5;
const CODE_GENERATION_WINDOW = 60 * 60 * 1000; // 1 hour

/**
 * Generate a secure random verification code
 */
export function generateVerificationCode(length: number = DEFAULT_CODE_LENGTH): string {
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
  const bcrypt = await import('bcryptjs');
  return bcrypt.hash(code, 12);
}

/**
 * Verify a verification code against its hash
 */
export async function verifyCodeHash(code: string, hashedCode: string): Promise<boolean> {
  try {
    const bcrypt = await import('bcryptjs');
    return bcrypt.compare(code, hashedCode);
  } catch {
    return false;
  }
}

/**
 * Check rate limiting for code generation
 */
function checkCodeGenerationRateLimit(identifier: string): boolean {
  const now = Date.now();
  const attempts = codeGenerationAttempts.get(identifier);
  
  if (!attempts) {
    codeGenerationAttempts.set(identifier, { count: 1, lastAttempt: now });
    return true;
  }
  
  // Reset counter if window has passed
  if (now - attempts.lastAttempt > CODE_GENERATION_WINDOW) {
    codeGenerationAttempts.set(identifier, { count: 1, lastAttempt: now });
    return true;
  }
  
  // Check if under limit
  if (attempts.count < MAX_CODE_GENERATIONS_PER_HOUR) {
    attempts.count++;
    attempts.lastAttempt = now;
    return true;
  }
  
  return false;
}

/**
 * Generate and store a 2FA verification code
 */
export async function generateTwoFactorCode(
  userId: string,
  options: TwoFactorOptions = {}
): Promise<{ code: string; codeId: string; expiresAt: Date }> {
  const db = authConfig.db;
  if (!db || !('storeTwoFactorCode' in db)) {
    throw new Error('Database adapter does not support 2FA. Please use an adapter that implements storeTwoFactorCode.');
  }
  
  const {
    codeLength = DEFAULT_CODE_LENGTH,
    expiryMinutes = DEFAULT_EXPIRY_MINUTES,
    maxAttempts = DEFAULT_MAX_ATTEMPTS,
    type = 'email_verification',
    metadata = {}
  } = options;
  
  // Rate limiting check
  const identifier = metadata.email || userId;
  if (!checkCodeGenerationRateLimit(identifier)) {
    throw new Error('Too many verification code requests. Please try again later.');
  }
  
  // Generate code and expiry
  const code = generateVerificationCode(codeLength);
  const hashedCode = await hashVerificationCode(code);
  const expiresAt = new Date(Date.now() + expiryMinutes * 60 * 1000);
  const codeId = crypto.randomUUID();
  
  const twoFactorCode: TwoFactorCode = {
    id: codeId,
    userId,
    code: '', // Don't store plain text code
    hashedCode,
    type,
    expiresAt,
    createdAt: new Date(),
    attempts: 0,
    isUsed: false,
    metadata
  };
  
  // Store in database
  await (db as any).storeTwoFactorCode(twoFactorCode);
  
  return {
    code, // Return plain text code for sending via email
    codeId,
    expiresAt
  };
}

/**
 * Verify a 2FA code
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
}> {
  const db = authConfig.db;
  if (!db || !('getTwoFactorCode' in db) || !('updateTwoFactorCode' in db)) {
    throw new Error('Database adapter does not support 2FA operations.');
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
    await (db as any).updateTwoFactorCode(codeId, {
      attempts: storedCode.attempts + 1
    });
    
    // Verify the code
    const isValidCode = await verifyCodeHash(inputCode, storedCode.hashedCode);
    
    if (isValidCode) {
      // Mark as used
      await (db as any).updateTwoFactorCode(codeId, {
        isUsed: true
      });
      
      return {
        isValid: true,
        isExpired: false,
        attemptsRemaining: maxAttempts - (storedCode.attempts + 1)
      };
    }
    
    return {
      isValid: false,
      isExpired: false,
      attemptsRemaining: maxAttempts - (storedCode.attempts + 1),
      error: 'Invalid verification code'
    };
    
  } catch (error) {
    console.error('Error verifying 2FA code:', error);
    return {
      isValid: false,
      isExpired: false,
      attemptsRemaining: 0,
      error: 'An error occurred during verification'
    };
  }
}

/**
 * Clean up expired 2FA codes (should be run periodically)
 */
export async function cleanupExpiredCodes(): Promise<number> {
  const db = authConfig.db;
  if (!db || !('cleanupExpiredTwoFactorCodes' in db)) {
    return 0;
  }
  
  try {
    return await (db as any).cleanupExpiredTwoFactorCodes();
  } catch (error) {
    console.error('Error cleaning up expired 2FA codes:', error);
    return 0;
  }
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
    console.error('Error getting user 2FA codes:', error);
    return [];
  }
}

/**
 * Email service registry for different providers
 */
export class EmailServiceRegistry {
  private static services = new Map<string, EmailService>();
  
  static register(name: string, service: EmailService): void {
    this.services.set(name, service);
  }
  
  static get(name: string): EmailService | undefined {
    return this.services.get(name);
  }
  
  static getDefault(): EmailService | undefined {
    return this.services.get('default');
  }
  
  static list(): string[] {
    return Array.from(this.services.keys());
  }
}

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
  
  const emailService = EmailServiceRegistry.get(serviceName);
  if (!emailService) {
    throw new Error(`Email service '${serviceName}' not configured. Please register an email service.`);
  }
  
  await emailService.sendVerificationEmail(email, code, {
    subject,
    template,
    metadata
  });
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
  const { code, codeId, expiresAt } = await generateTwoFactorCode(userId, {
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
    message: `Verification code sent to ${email}. Code expires in ${expiryMinutes || DEFAULT_EXPIRY_MINUTES} minutes.`
  };
}
