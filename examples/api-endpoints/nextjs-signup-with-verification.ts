// Next.js App Router - Signup with Email Verification
// Copy this to: app/api/auth/signup-with-verification/route.ts

import { NextRequest, NextResponse } from 'next/server';
import { initAuth, signupCore, generateTwoFactorCode } from 'authrix';
import { mongoAdapter } from 'authrix/adapters/mongo'; // or your chosen adapter

// Initialize your email service
import { 
  GmailEmailService, 
  ResendEmailService, 
  SendGridEmailService,
  ConsoleEmailService 
} from 'authrix/email';

// Choose your email service
const emailService = process.env.NODE_ENV === 'development' 
  ? new ConsoleEmailService() 
  : new GmailEmailService(); // Change to your preferred service

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter,
});

export async function POST(request: NextRequest) {
  try {
    const { email, password, autoSendVerification = true } = await request.json();

    // Validation
    if (!email || !password) {
      return NextResponse.json(
        { error: 'Email and password are required' }, 
        { status: 400 }
      );
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
              ipAddress: request.ip || 'unknown',
              userAgent: request.headers.get('user-agent') || 'unknown',
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

    // Create response with user data
    const response = NextResponse.json({
      success: true,
      user: userResult.user,
      verificationCodeId,
      message: verificationMessage,
      requiresVerification: autoSendVerification
    });

    // Set authentication cookie
    response.cookies.set(
      'auth_token', // or use authConfig.cookieName
      userResult.token,
      {
        ...userResult.cookieOptions,
        sameSite: 'lax',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
      }
    );

    return response;

  } catch (error) {
    console.error('Signup with verification error:', error);
    
    // Handle specific errors
    if (error instanceof Error) {
      if (error.message.includes('already registered') || error.message.includes('already exists')) {
        return NextResponse.json(
          { error: 'An account with this email already exists' },
          { status: 409 }
        );
      }
      
      if (error.message.includes('password') && error.message.includes('requirements')) {
        return NextResponse.json(
          { error: error.message },
          { status: 400 }
        );
      }
    }
    
    // Generic error response
    const errorMessage = process.env.NODE_ENV === 'development' 
      ? error instanceof Error ? error.message : 'Unknown error'
      : 'Failed to create account';

    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}
