// Next.js App Router - Verify Code
// Copy this to: app/api/auth/verify-code/route.ts

import { NextRequest, NextResponse } from 'next/server';
import { initAuth, verifyTwoFactorCode } from 'authrix';
import { mongoAdapter } from 'authrix/adapters/mongo'; // or your chosen adapter

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter,
});

export async function POST(request: NextRequest) {
  try {
    const { codeId, code } = await request.json();

    // Validation
    if (!codeId || !code) {
      return NextResponse.json(
        { error: 'Code ID and verification code are required' }, 
        { status: 400 }
      );
    }

    if (typeof code !== 'string' || !/^\d{6}$/.test(code)) {
      return NextResponse.json(
        { error: 'Verification code must be 6 digits' }, 
        { status: 400 }
      );
    }

    // Verify the code
    const result = await verifyTwoFactorCode(codeId, code, {
      ipAddress: request.ip || 'unknown',
      userAgent: request.headers.get('user-agent') || 'unknown',
    });

    if (result.success) {
      return NextResponse.json({
        success: true,
        message: 'Code verified successfully',
        type: result.type,
        metadata: result.metadata
      });
    } else {
      return NextResponse.json(
        { 
          error: result.error,
          attemptsRemaining: result.attemptsRemaining 
        },
        { status: 400 }
      );
    }

  } catch (error) {
    console.error('Verify code error:', error);
    
    // Return generic error in production, detailed in development
    const errorMessage = process.env.NODE_ENV === 'development' 
      ? error instanceof Error ? error.message : 'Unknown error'
      : 'Failed to verify code';

    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}
