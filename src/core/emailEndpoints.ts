import type { Request, Response } from "express";
import { 
  initiateEmailVerification, 
  verifyTwoFactorCode,
  generateTwoFactorCode,
  sendVerificationEmail 
} from "../core/twoFactor";
import { authConfig } from "../config";
import { getCurrentUserFromToken } from "../core/session";

/**
 * POST /api/auth/send-verification-code
 * Send email verification code to user's email
 */
export async function sendVerificationCodeHandler(req: Request, res: Response) {
  try {
    const { email, userId, type = 'email_verification' } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        error: { message: 'Email is required' }
      });
    }
    
    // If userId not provided, try to get from auth token
    let targetUserId = userId;
    if (!targetUserId) {
      const token = req.cookies[authConfig.cookieName] || 
                   req.headers.authorization?.replace('Bearer ', '');
      const user = await getCurrentUserFromToken(token);
      if (user) {
        targetUserId = user.id;
      }
    }
    
    if (!targetUserId) {
      return res.status(400).json({
        success: false,
        error: { message: 'User ID is required or user must be authenticated' }
      });
    }
    
    // Get service name from query params or use default
    const serviceName = req.query.service as string || undefined;
    
    const result = await initiateEmailVerification(targetUserId, email, {
      serviceName,
      metadata: {
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        appName: process.env.APP_NAME || 'Authrix App'
      }
    });
    
    res.json({
      success: true,
      data: {
        codeId: result.codeId,
        expiresAt: result.expiresAt,
        message: result.message
      }
    });
    
  } catch (error) {
    console.error('Send verification code error:', error);
    res.status(500).json({
      success: false,
      error: { 
        message: error instanceof Error ? error.message : 'Failed to send verification code' 
      }
    });
  }
}

/**
 * POST /api/auth/verify-code
 * Verify email verification code
 */
export async function verifyCodeHandler(req: Request, res: Response) {
  try {
    const { codeId, code, userId } = req.body;
    
    if (!codeId || !code) {
      return res.status(400).json({
        success: false,
        error: { message: 'Code ID and verification code are required' }
      });
    }
    
    // If userId not provided, try to get from auth token
    let targetUserId = userId;
    if (!targetUserId) {
      const token = req.cookies[authConfig.cookieName] || 
                   req.headers.authorization?.replace('Bearer ', '');
      const user = await getCurrentUserFromToken(token);
      if (user) {
        targetUserId = user.id;
      }
    }
    
    const result = await verifyTwoFactorCode(codeId, code, targetUserId);
    
    if (result.isValid) {
      // If this was email verification, mark user's email as verified
      if (targetUserId) {
        const db = authConfig.db;
        if (db && 'updateUser' in db) {
          try {
            await (db as any).updateUser(targetUserId, {
              emailVerified: true,
              emailVerifiedAt: new Date()
            });
          } catch (error) {
            console.warn('Failed to update user email verification status:', error);
          }
        }
      }
      
      res.json({
        success: true,
        data: {
          verified: true,
          message: 'Email verified successfully'
        }
      });
    } else {
      res.status(400).json({
        success: false,
        error: {
          message: result.error || 'Invalid verification code',
          isExpired: result.isExpired,
          attemptsRemaining: result.attemptsRemaining
        }
      });
    }
    
  } catch (error) {
    console.error('Verify code error:', error);
    res.status(500).json({
      success: false,
      error: { 
        message: error instanceof Error ? error.message : 'Failed to verify code' 
      }
    });
  }
}

/**
 * GET /api/auth/email-services
 * Get available email services and configuration instructions
 */
export async function getEmailServicesHandler(req: Request, res: Response) {
  try {
    const { getAvailableEmailServices } = await import("../email");
    const services = getAvailableEmailServices();
    
    res.json({
      success: true,
      data: {
        availableServices: services.available,
        configuredServices: services.configured,
        instructions: services.instructions,
        currentDefault: process.env.DEFAULT_EMAIL_SERVICE || 'none'
      }
    });
    
  } catch (error) {
    console.error('Get email services error:', error);
    res.status(500).json({
      success: false,
      error: { 
        message: 'Failed to get email services information' 
      }
    });
  }
}

/**
 * POST /api/auth/test-email-service
 * Test email service configuration (admin/development only)
 */
export async function testEmailServiceHandler(req: Request, res: Response) {
  try {
    // Only allow in development or if explicitly enabled
    if (process.env.NODE_ENV === 'production' && !process.env.ALLOW_EMAIL_SERVICE_TESTING) {
      return res.status(403).json({
        success: false,
        error: { message: 'Email service testing not allowed in production' }
      });
    }
    
    const { email, serviceName = 'default' } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        error: { message: 'Email is required for testing' }
      });
    }
    
    // Generate a test code
    const testCode = '123456';
    
    await sendVerificationEmail(email, testCode, {
      serviceName,
      subject: 'Test Email Service - Authrix',
      metadata: {
        appName: 'Authrix Test',
        isTest: true
      }
    });
    
    res.json({
      success: true,
      data: {
        message: `Test email sent to ${email} using ${serviceName} service`,
        testCode // Include in response for development
      }
    });
    
  } catch (error) {
    console.error('Test email service error:', error);
    res.status(500).json({
      success: false,
      error: { 
        message: error instanceof Error ? error.message : 'Failed to test email service' 
      }
    });
  }
}

/**
 * Enhanced signup with email verification
 * POST /api/auth/signup-with-verification
 */
export async function signupWithVerificationHandler(req: Request, res: Response) {
  try {
    const { email, password, autoSendVerification = true } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: { message: 'Email and password are required' }
      });
    }
    
    // First create the user (but mark as unverified)
    const { signupCore } = await import("../core/signup");
    const signupResult = await signupCore(email, password);
    
    // Set auth cookie
    res.cookie(authConfig.cookieName, signupResult.token, signupResult.cookieOptions);
    
    let verificationResult = null;
    
    // Automatically send verification email if requested
    if (autoSendVerification) {
      try {
        const serviceName = req.query.service as string || undefined;
        verificationResult = await initiateEmailVerification(signupResult.user.id, email, {
          serviceName,
          metadata: {
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            appName: process.env.APP_NAME || 'Authrix App'
          }
        });
      } catch (verificationError) {
        console.warn('Failed to send verification email during signup:', verificationError);
        // Don't fail the signup, just warn
      }
    }
    
    res.status(201).json({
      success: true,
      data: {
        user: signupResult.user,
        emailVerified: false,
        verification: verificationResult ? {
          codeId: verificationResult.codeId,
          expiresAt: verificationResult.expiresAt,
          message: verificationResult.message
        } : null
      }
    });
    
  } catch (error) {
    console.error('Signup with verification error:', error);
    res.status(400).json({
      success: false,
      error: { 
        message: error instanceof Error ? error.message : 'Signup failed' 
      }
    });
  }
}
