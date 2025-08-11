import type { Request, Response } from "express";
import {
  initiateEmailVerification,
  verifyTwoFactorCode,
  cleanupExpiredCodes
} from "../core/twoFactor";
import { EmailServiceRegistry, getAvailableEmailServices, getEmailServiceInstructions } from "../email/providers";
import { authConfig } from "../config";
import { getCurrentUserFromToken } from "../core/session";
import { BadRequestError, UnauthorizedError, ForbiddenError, InternalServerError } from "../utils/errors";

/**
 * Enhanced error response helper
 */
function handleError(error: any, res: Response, defaultMessage: string = 'An error occurred') {
  console.error('[AUTHRIX] Email endpoint error:', error);

  if (error instanceof BadRequestError) {
    return res.status(400).json({
      success: false,
      error: { message: error.message, code: 'BAD_REQUEST' }
    });
  }

  if (error instanceof UnauthorizedError) {
    return res.status(401).json({
      success: false,
      error: { message: error.message, code: 'UNAUTHORIZED' }
    });
  }

  if (error instanceof ForbiddenError) {
    return res.status(403).json({
      success: false,
      error: { message: error.message, code: 'FORBIDDEN' }
    });
  }

  if (error instanceof InternalServerError) {
    return res.status(500).json({
      success: false,
      error: { message: error.message, code: 'INTERNAL_ERROR' }
    });
  }

  // Generic error handling
  const message = error instanceof Error ? error.message : defaultMessage;
  return res.status(500).json({
    success: false,
    error: { message, code: 'UNKNOWN_ERROR' }
  });
}

/**
 * Extract user ID from request (body, auth token, or query)
 */
async function extractUserId(req: Request): Promise<string | null> {
  // Try body first
  if (req.body.userId) {
    return req.body.userId;
  }

  // Try auth token
  const token = req.cookies?.[authConfig.cookieName] ||
    req.headers.authorization?.replace('Bearer ', '');

  if (token) {
    const user = await getCurrentUserFromToken(token);
    return user?.id || null;
  }

  return null;
}

/**
 * POST /api/auth/send-verification-code
 * Send email verification code to user's email with enhanced validation
 */
export async function sendVerificationCodeHandler(req: Request, res: Response) {
  try {
    const { email, type = 'email_verification', codeLength, expiryMinutes } = req.body;

    // Input validation
    if (!email?.trim()) {
      throw new BadRequestError('Email is required');
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email.trim())) {
      throw new BadRequestError('Invalid email format');
    }

    // Extract user ID
    const targetUserId = await extractUserId(req);
    if (!targetUserId) {
      throw new UnauthorizedError('User ID is required or user must be authenticated');
    }

    // Validate type
    const validTypes = ['email_verification', 'password_reset', 'login_verification'];
    if (!validTypes.includes(type)) {
      throw new BadRequestError(`Invalid verification type. Must be one of: ${validTypes.join(', ')}`);
    }

    // Get service name from query params or use default
    const serviceName = req.query.service as string || undefined;

    // Initiate email verification
    const result = await initiateEmailVerification(targetUserId, email.trim(), {
      serviceName,
      codeLength: codeLength ? parseInt(codeLength) : undefined,
      expiryMinutes: expiryMinutes ? parseInt(expiryMinutes) : undefined,
      metadata: {
        type,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        appName: process.env.APP_NAME || 'Authrix App',
        timestamp: new Date().toISOString()
      }
    });

    res.json({
      success: true,
      data: {
        codeId: result.codeId,
        expiresAt: result.expiresAt,
        attemptsRemaining: result.attemptsRemaining,
        message: result.message
      }
    });

  } catch (error) {
    handleError(error, res, 'Failed to send verification code');
  }
}

/**
 * POST /api/auth/verify-code
 * Verify email verification code with enhanced security
 */
export async function verifyCodeHandler(req: Request, res: Response) {
  try {
    const { codeId, code, updateUserVerification = true } = req.body;

    // Input validation
    if (!codeId?.trim()) {
      throw new BadRequestError('Code ID is required');
    }

    if (!code?.trim()) {
      throw new BadRequestError('Verification code is required');
    }

    // Extract user ID (optional for verification)
    const targetUserId = await extractUserId(req);

    // Verify the code
    const result = await verifyTwoFactorCode(codeId.trim(), code.trim(), targetUserId || undefined);

    if (result.isValid) {
      // Update user email verification status if requested and user is identified
      if (updateUserVerification && targetUserId) {
        const db = authConfig.db;
        if (db && 'updateUser' in db) {
          try {
            await (db as any).updateUser(targetUserId, {
              emailVerified: true,
              emailVerifiedAt: new Date()
            });
          } catch (error) {
            console.warn('[AUTHRIX] Failed to update user email verification status:', error);
            // Don't fail the verification for this
          }
        }
      }

      res.json({
        success: true,
        data: {
          verified: true,
          message: 'Email verified successfully',
          metadata: result.metadata
        }
      });
    } else {
      const statusCode = result.isExpired ? 410 : 400; // 410 Gone for expired codes

      res.status(statusCode).json({
        success: false,
        error: {
          message: result.error || 'Invalid verification code',
          code: result.isExpired ? 'CODE_EXPIRED' : 'INVALID_CODE',
          isExpired: result.isExpired,
          attemptsRemaining: result.attemptsRemaining
        }
      });
    }

  } catch (error) {
    handleError(error, res, 'Failed to verify code');
  }
}

/**
 * GET /api/auth/email-services
 * Get available email services and configuration status
 */
export async function getEmailServicesHandler(req: Request, res: Response) {
  try {
    // Get available email services and their configuration status
    const emailServicesInfo = getAvailableEmailServices();
    const instructions = getEmailServiceInstructions();

    // Get currently registered services
    const registeredServices = EmailServiceRegistry.list();
    const defaultService = EmailServiceRegistry.getDefault();

    res.json({
      success: true,
      data: {
        email: {
          available: emailServicesInfo.available,
          configured: emailServicesInfo.configured,
          registered: registeredServices,
          default: defaultService ? 'configured' : 'not configured',
          defaultServiceName: defaultService ? 'default' : null
        },
        instructions,
        environment: {
          nodeEnv: process.env.NODE_ENV,
          defaultEmailService: process.env.DEFAULT_EMAIL_SERVICE || 'none',
          appName: process.env.APP_NAME || 'Authrix App'
        }
      }
    });

  } catch (error) {
    handleError(error, res, 'Failed to get email services information');
  }
}

/**
 * POST /api/auth/test-email-service
 * Test email service configuration (development/admin only)
 */
export async function testEmailServiceHandler(req: Request, res: Response) {
  try {
    // Security check - only allow in development or if explicitly enabled
    if (process.env.NODE_ENV === 'production' && !process.env.ALLOW_EMAIL_SERVICE_TESTING) {
      throw new ForbiddenError('Email service testing not allowed in production');
    }

    const { email, serviceName = 'default', testType = 'verification' } = req.body;

    // Input validation
    if (!email?.trim()) {
      throw new BadRequestError('Email is required for testing');
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email.trim())) {
      throw new BadRequestError('Invalid email format');
    }

    // Generate test code
    const testCode = Math.floor(100000 + Math.random() * 900000).toString();

    // Prepare test email content based on type
    let subject = 'Test Email Service - Authrix';
    let metadata: Record<string, any> = {
      appName: 'Authrix Test',
      isTest: true,
      testType,
      timestamp: new Date().toISOString()
    };

    if (testType === 'password_reset') {
      subject = 'Test Password Reset - Authrix';
      metadata.purpose = 'password_reset_test';
    } else if (testType === 'welcome') {
      subject = 'Test Welcome Email - Authrix';
      metadata.purpose = 'welcome_test';
    }

    // Get the email service
    const emailService = EmailServiceRegistry.get(serviceName) || EmailServiceRegistry.getDefault();
    if (!emailService) {
      throw new BadRequestError(`Email service '${serviceName}' not configured`);
    }

    // Send test email
    await emailService.sendVerificationEmail(email.trim(), testCode, {
      subject,
      metadata
    });

    res.json({
      success: true,
      data: {
        message: `Test email sent to ${email} using '${serviceName}' service`,
        testCode: process.env.NODE_ENV === 'development' ? testCode : '[HIDDEN]',
        serviceName,
        testType,
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    handleError(error, res, 'Failed to test email service');
  }
}

/**
 * Enhanced signup with email verification
 * POST /api/auth/signup-with-verification
 */
export async function signupWithVerificationHandler(req: Request, res: Response) {
  try {
    const {
      email,
      password,
      autoSendVerification = true,
      requireEmailVerification = true,
      ...additionalData
    } = req.body;

    // Input validation
    if (!email?.trim()) {
      throw new BadRequestError('Email is required');
    }

    if (!password?.trim()) {
      throw new BadRequestError('Password is required');
    }

    // Create the user with email verification requirement
    const { signupCore } = await import("../core/signup");
    const signupResult = await signupCore(email.trim(), password, {
      requireEmailVerification,
      customUserData: additionalData,
      generateUsername: true
    });

    // Set auth cookie if auto-signin is enabled
    res.cookie(authConfig.cookieName, signupResult.token, signupResult.cookieOptions);

    let verificationResult = null;

    // Automatically send verification email if requested
    if (autoSendVerification) {
      try {
        const serviceName = req.query.service as string || undefined;
        verificationResult = await initiateEmailVerification(signupResult.user.id, email.trim(), {
          serviceName,
          subject: 'Welcome! Please verify your email',
          metadata: {
            purpose: 'signup_verification',
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            appName: process.env.APP_NAME || 'Authrix App',
            username: signupResult.user.username
          }
        });
      } catch (verificationError) {
        console.warn('[AUTHRIX] Failed to send verification email during signup:', verificationError);
        // Don't fail the signup, just warn
      }
    }

    res.status(201).json({
      success: true,
      data: {
        user: signupResult.user,
        isNewUser: signupResult.isNewUser,
        emailVerified: signupResult.user.emailVerified || false,
        requiresEmailVerification: signupResult.requiresEmailVerification,
        verification: verificationResult ? {
          codeId: verificationResult.codeId,
          expiresAt: verificationResult.expiresAt,
          attemptsRemaining: verificationResult.attemptsRemaining,
          message: verificationResult.message
        } : null
      }
    });

  } catch (error) {
    handleError(error, res, 'Signup failed');
  }
}

/**
 * POST /api/auth/resend-verification
 * Resend verification code for authenticated user
 */
export async function resendVerificationHandler(req: Request, res: Response) {
  try {
    const { email, type = 'email_verification' } = req.body;

    // Get authenticated user
    const token = req.cookies?.[authConfig.cookieName] ||
      req.headers.authorization?.replace('Bearer ', '');

    if (!token) {
      throw new UnauthorizedError('Authentication required');
    }

    const user = await getCurrentUserFromToken(token);
    if (!user) {
      throw new UnauthorizedError('Invalid authentication');
    }

    // Use user's email if not provided
    const targetEmail = email?.trim() || user.email;

    // Send verification code
    const result = await initiateEmailVerification(user.id, targetEmail, {
      metadata: {
        type,
        purpose: 'resend_verification',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        userId: user.id
      }
    });

    res.json({
      success: true,
      data: {
        codeId: result.codeId,
        expiresAt: result.expiresAt,
        attemptsRemaining: result.attemptsRemaining,
        message: result.message
      }
    });

  } catch (error) {
    handleError(error, res, 'Failed to resend verification code');
  }
}

/**
 * POST /api/auth/cleanup-codes
 * Clean up expired verification codes (admin endpoint)
 */
export async function cleanupCodesHandler(req: Request, res: Response) {
  try {
    // This could be protected with admin authentication
    const result = await cleanupExpiredCodes();

    res.json({
      success: true,
      data: {
        codesDeleted: result.codesDeleted,
        rateLimitEntriesCleared: result.rateLimitEntriesCleared,
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    handleError(error, res, 'Failed to cleanup expired codes');
  }
}
