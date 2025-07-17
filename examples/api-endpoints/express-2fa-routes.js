// Express.js - Complete 2FA Email Verification Routes
// Copy this to your Express.js routes file

import express from 'express';
import { initAuth, signupCore, generateTwoFactorCode, verifyTwoFactorCode } from 'authrix';
import { mongoAdapter } from 'authrix/adapters/mongo'; // or your chosen adapter

// Initialize your email service
import { 
  GmailEmailService, 
  ResendEmailService, 
  SendGridEmailService,
  ConsoleEmailService 
} from 'authrix/email';

const router = express.Router();

// Choose your email service
const emailService = process.env.NODE_ENV === 'development' 
  ? new ConsoleEmailService() 
  : new GmailEmailService(); // Change to your preferred service

// Initialize Authrix
initAuth({
  jwtSecret: process.env.JWT_SECRET,
  db: mongoAdapter,
});

// Send verification code
router.post('/send-verification-code', async (req, res) => {
  try {
    const { email, type = 'email_verification' } = req.body;

    // Validation
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    if (!email.includes('@')) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Generate verification code
    const { code, codeData } = await generateTwoFactorCode(
      { email },
      {
        type,
        expiryMinutes: 10,
        maxAttempts: 3,
        metadata: {
          email,
          ipAddress: req.ip || req.connection.remoteAddress,
          userAgent: req.get('User-Agent'),
        }
      }
    );

    // Send email
    await emailService.sendVerificationEmail(email, code, {
      subject: type === 'email_verification' ? 'Verify your email address' : 'Password reset code',
      metadata: {
        appName: process.env.APP_NAME || 'Your App',
        type,
      }
    });

    res.json({
      success: true,
      codeId: codeData.id,
      expiresAt: codeData.expiresAt,
      message: 'Verification code sent successfully',
      // Include code in development for testing
      ...(process.env.NODE_ENV === 'development' && { code })
    });

  } catch (error) {
    console.error('Send verification code error:', error);
    
    const errorMessage = process.env.NODE_ENV === 'development' 
      ? error.message || 'Unknown error'
      : 'Failed to send verification code';

    res.status(500).json({ error: errorMessage });
  }
});

// Verify code
router.post('/verify-code', async (req, res) => {
  try {
    const { codeId, code } = req.body;

    // Validation
    if (!codeId || !code) {
      return res.status(400).json({ error: 'Code ID and verification code are required' });
    }

    if (typeof code !== 'string' || !/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: 'Verification code must be 6 digits' });
    }

    // Verify the code
    const result = await verifyTwoFactorCode(codeId, code, {
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent'),
    });

    if (result.success) {
      res.json({
        success: true,
        message: 'Code verified successfully',
        type: result.type,
        metadata: result.metadata
      });
    } else {
      res.status(400).json({
        error: result.error,
        attemptsRemaining: result.attemptsRemaining
      });
    }

  } catch (error) {
    console.error('Verify code error:', error);
    
    const errorMessage = process.env.NODE_ENV === 'development' 
      ? error.message || 'Unknown error'
      : 'Failed to verify code';

    res.status(500).json({ error: errorMessage });
  }
});

// Signup with email verification
router.post('/signup-with-verification', async (req, res) => {
  try {
    const { email, password, autoSendVerification = true } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Create user account
    const userResult = await signupCore(email, password);

    let verificationCodeId;
    let verificationMessage = 'Account created successfully!';

    if (autoSendVerification) {
      try {
        // Generate and send verification code
        const { code, codeData } = await generateTwoFactorCode(
          userResult.user,
          {
            type: 'email_verification',
            expiryMinutes: 10,
            maxAttempts: 3,
            metadata: {
              email,
              ipAddress: req.ip || req.connection.remoteAddress,
              userAgent: req.get('User-Agent'),
            }
          }
        );

        await emailService.sendVerificationEmail(email, code, {
          subject: 'Welcome! Verify your email address',
          metadata: {
            appName: process.env.APP_NAME || 'Your App',
            userName: email.split('@')[0],
          }
        });

        verificationCodeId = codeData.id;
        verificationMessage = 'Account created! Please check your email for verification code.';

        // In development, include the code for testing
        if (process.env.NODE_ENV === 'development') {
          verificationMessage += ` (Dev: code is ${code})`;
        }

      } catch (emailError) {
        console.error('Failed to send verification email:', emailError);
        // Don't fail the signup if email fails
        verificationMessage = 'Account created! Please try requesting a verification code manually.';
      }
    }

    // Set authentication cookie
    res.cookie('auth_token', userResult.token, userResult.cookieOptions);

    res.status(201).json({
      success: true,
      user: userResult.user,
      verificationCodeId,
      message: verificationMessage,
      requiresVerification: autoSendVerification
    });

  } catch (error) {
    console.error('Signup with verification error:', error);
    
    // Handle specific errors
    if (error.message && error.message.includes('already registered')) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }
    
    if (error.message && error.message.includes('password') && error.message.includes('requirements')) {
      return res.status(400).json({ error: error.message });
    }
    
    // Generic error response
    const errorMessage = process.env.NODE_ENV === 'development' 
      ? error.message || 'Unknown error'
      : 'Failed to create account';

    res.status(500).json({ error: errorMessage });
  }
});

export default router;
