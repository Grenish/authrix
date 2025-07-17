// Next.js App Router - Send Verification Code
// Copy this to: app/api/auth/send-verification-code/route.ts

import { NextRequest, NextResponse } from 'next/server';
import { initAuth, generateTwoFactorCode } from 'authrix';
import { mongoAdapter } from 'authrix/adapters/mongo'; // or your chosen adapter

// Initialize your email service
import { 
  GmailEmailService, 
  ResendEmailService, 
  SendGridEmailService,
  ConsoleEmailService 
} from 'authrix/email';

// Choose your email service based on environment
const emailService = process.env.NODE_ENV === 'development' 
  ? new ConsoleEmailService() 
  : new GmailEmailService(); // Change to your preferred service

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter,
});

export async function POST(request: NextRequest) {
  try {
    const { email, type = 'email_verification' } = await request.json();

    // Validation
    if (!email) {
      return NextResponse.json({ error: 'Email is required' }, { status: 400 });
    }

    if (!email.includes('@')) {
      return NextResponse.json({ error: 'Invalid email format' }, { status: 400 });
    }

    // Generate verification code
    const { code, codeData } = await generateTwoFactorCode(
      { email }, // Use email as identifier for users without accounts
      {
        type,
        expiryMinutes: 10,
        maxAttempts: 3,
        metadata: {
          email,
          ipAddress: request.ip || 'unknown',
          userAgent: request.headers.get('user-agent') || 'unknown',
        }
      }
    );

    // Send email with verification code
    await emailService.sendVerificationEmail(email, code, {
      subject: type === 'email_verification' ? 'Verify your email address' : 'Password reset code',
      metadata: {
        appName: process.env.APP_NAME || 'Your App',
        type,
      }
    });

    return NextResponse.json({
      success: true,
      codeId: codeData.id,
      expiresAt: codeData.expiresAt,
      message: 'Verification code sent successfully',
      // Don't send the actual code in production
      ...(process.env.NODE_ENV === 'development' && { code })
    });

  } catch (error) {
    console.error('Send verification code error:', error);
    
    // Return generic error in production, detailed in development
    const errorMessage = process.env.NODE_ENV === 'development' 
      ? error instanceof Error ? error.message : 'Unknown error'
      : 'Failed to send verification code';

    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}
