# 2FA Email Verification Setup Guide

This guide shows you how to implement 2FA email verification in your application using Authrix.

## Quick Start

### 1. Install Dependencies

Choose your preferred email service:

```bash
# For Gmail (using nodemailer)
npm install nodemailer @types/nodemailer

# For Resend
npm install resend

# For SendGrid
npm install @sendgrid/mail

# For custom SMTP (using nodemailer)
npm install nodemailer @types/nodemailer
```

### 2. Environment Variables

Add the required environment variables for your chosen email service:

#### Gmail Setup
```env
GMAIL_USER=your-email@gmail.com
GMAIL_APP_PASSWORD=your-app-password
```

**Setup Instructions:**
1. Enable 2-Step Verification in your Google Account
2. Generate an App Password: https://myaccount.google.com/apppasswords
3. Use the generated password in `GMAIL_APP_PASSWORD`

#### Resend Setup
```env
RESEND_API_KEY=your-api-key
RESEND_FROM_EMAIL=noreply@yourdomain.com
```

**Setup Instructions:**
1. Sign up at https://resend.com
2. Get your API key from the dashboard
3. Verify your domain or use their test domain

#### SendGrid Setup
```env
SENDGRID_API_KEY=your-api-key
SENDGRID_FROM_EMAIL=verified-sender@yourdomain.com
```

**Setup Instructions:**
1. Sign up at https://sendgrid.com
2. Create an API key in the dashboard
3. Verify your sender email address

#### Custom SMTP Setup
```env
SMTP_HOST=smtp.yourprovider.com
SMTP_PORT=587
SMTP_USER=your-username
SMTP_PASS=your-password
SMTP_FROM=noreply@yourdomain.com
```

### 3. Initialize Email Service

```typescript
// src/lib/email.ts
import { 
  GmailEmailService, 
  ResendEmailService, 
  SendGridEmailService,
  SMTPEmailService,
  ConsoleEmailService 
} from 'authrix/email';

// Choose your email service
export const emailService = process.env.NODE_ENV === 'development' 
  ? new ConsoleEmailService() // Logs to console in development
  : new GmailEmailService();   // Use Gmail in production

// Or use Resend
// export const emailService = new ResendEmailService();

// Or use SendGrid
// export const emailService = new SendGridEmailService();

// Or use custom SMTP
// export const emailService = new SMTPEmailService();
```

## API Endpoints

Copy these endpoints into your application:

### Next.js App Router

#### Send Verification Code
```typescript
// app/api/auth/send-verification-code/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { initAuth, generateTwoFactorCode } from 'authrix';
import { mongoAdapter } from 'authrix/adapters/mongo'; // MongoDB
// OR
import { postgresqlAdapter, initializePostgreSQLTables } from 'authrix/adapters/postgresql'; // PostgreSQL
import { emailService } from '@/lib/email';

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter, // or postgresqlAdapter
});

export async function POST(request: NextRequest) {
  try {
    const { email, type = 'email_verification' } = await request.json();

    if (!email) {
      return NextResponse.json({ error: 'Email is required' }, { status: 400 });
    }

    // Generate verification code
    const { code, codeData } = await generateTwoFactorCode(
      { email }, // Use email as identifier for users without accounts
      {
        type,
        expiryMinutes: 10,
        metadata: {
          email,
          ipAddress: request.ip,
          userAgent: request.headers.get('user-agent'),
        }
      }
    );

    // Send email
    await emailService.sendVerificationEmail(email, code, {
      subject: type === 'email_verification' ? 'Verify your email' : 'Password reset code',
      metadata: {
        appName: 'Your App Name',
      }
    });

    return NextResponse.json({
      success: true,
      codeId: codeData.id,
      expiresAt: codeData.expiresAt,
      message: 'Verification code sent successfully'
    });

  } catch (error) {
    console.error('Send verification code error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to send verification code' },
      { status: 500 }
    );
  }
}
```

#### Verify Code
```typescript
// app/api/auth/verify-code/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { initAuth, verifyTwoFactorCode } from 'authrix';
import { mongoAdapter } from 'authrix/adapters/mongo';

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter,
});

export async function POST(request: NextRequest) {
  try {
    const { codeId, code } = await request.json();

    if (!codeId || !code) {
      return NextResponse.json({ error: 'Code ID and code are required' }, { status: 400 });
    }

    const result = await verifyTwoFactorCode(codeId, code);

    if (result.success) {
      return NextResponse.json({
        success: true,
        message: 'Code verified successfully',
        metadata: result.metadata
      });
    } else {
      return NextResponse.json(
        { error: result.error },
        { status: 400 }
      );
    }

  } catch (error) {
    console.error('Verify code error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to verify code' },
      { status: 500 }
    );
  }
}
```

#### Signup with Email Verification
```typescript
// app/api/auth/signup-with-verification/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { initAuth, signupCore, generateTwoFactorCode } from 'authrix';
import { mongoAdapter } from 'authrix/adapters/mongo';
import { emailService } from '@/lib/email';

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter,
});

export async function POST(request: NextRequest) {
  try {
    const { email, password, autoSendVerification = true } = await request.json();

    if (!email || !password) {
      return NextResponse.json({ error: 'Email and password are required' }, { status: 400 });
    }

    // Create user account
    const result = await signupCore(email, password);

    let verificationCodeId;
    if (autoSendVerification) {
      // Generate and send verification code
      const { code, codeData } = await generateTwoFactorCode(
        result.user,
        {
          type: 'email_verification',
          expiryMinutes: 10,
          metadata: {
            email,
            ipAddress: request.ip,
            userAgent: request.headers.get('user-agent'),
          }
        }
      );

      await emailService.sendVerificationEmail(email, code, {
        subject: 'Welcome! Verify your email',
        metadata: {
          appName: 'Your App Name',
        }
      });

      verificationCodeId = codeData.id;
    }

    // Set authentication cookie
    const response = NextResponse.json({
      success: true,
      user: result.user,
      verificationCodeId,
      message: autoSendVerification 
        ? 'Account created! Please check your email for verification code.'
        : 'Account created successfully!'
    });

    response.cookies.set(
      'auth_token',
      result.token,
      {
        ...result.cookieOptions,
        sameSite: 'lax',
      }
    );

    return response;

  } catch (error) {
    console.error('Signup with verification error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Signup failed' },
      { status: 500 }
    );
  }
}
```

### Express.js

#### Send Verification Code
```typescript
// routes/auth.js
import express from 'express';
import { initAuth, generateTwoFactorCode } from 'authrix';
import { mongoAdapter } from 'authrix/adapters/mongo';
import { emailService } from '../lib/email.js';

const router = express.Router();

initAuth({
  jwtSecret: process.env.JWT_SECRET,
  db: mongoAdapter,
});

router.post('/send-verification-code', async (req, res) => {
  try {
    const { email, type = 'email_verification' } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const { code, codeData } = await generateTwoFactorCode(
      { email },
      {
        type,
        expiryMinutes: 10,
        metadata: {
          email,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
        }
      }
    );

    await emailService.sendVerificationEmail(email, code, {
      subject: type === 'email_verification' ? 'Verify your email' : 'Password reset code',
      metadata: { appName: 'Your App Name' }
    });

    res.json({
      success: true,
      codeId: codeData.id,
      expiresAt: codeData.expiresAt,
      message: 'Verification code sent successfully'
    });

  } catch (error) {
    console.error('Send verification code error:', error);
    res.status(500).json({
      error: error.message || 'Failed to send verification code'
    });
  }
});

router.post('/verify-code', async (req, res) => {
  try {
    const { codeId, code } = req.body;

    if (!codeId || !code) {
      return res.status(400).json({ error: 'Code ID and code are required' });
    }

    const result = await verifyTwoFactorCode(codeId, code);

    if (result.success) {
      res.json({
        success: true,
        message: 'Code verified successfully',
        metadata: result.metadata
      });
    } else {
      res.status(400).json({ error: result.error });
    }

  } catch (error) {
    console.error('Verify code error:', error);
    res.status(500).json({
      error: error.message || 'Failed to verify code'
    });
  }
});

export default router;
```

## Frontend Integration

### React Hook

```typescript
// hooks/useEmailVerification.ts
import { useState } from 'react';

interface EmailVerificationResult {
  success: boolean;
  codeId?: string;
  expiresAt?: string;
  error?: string;
}

interface CodeVerificationResult {
  success: boolean;
  error?: string;
}

export function useEmailVerification() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const sendCode = async (email: string, type: 'email_verification' | 'password_reset' = 'email_verification'): Promise<EmailVerificationResult> => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/auth/send-verification-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, type }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to send verification code');
      }

      return data;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to send code';
      setError(errorMessage);
      return { success: false, error: errorMessage };
    } finally {
      setLoading(false);
    }
  };

  const verifyCode = async (codeId: string, code: string): Promise<CodeVerificationResult> => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/auth/verify-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ codeId, code }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to verify code');
      }

      return data;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to verify code';
      setError(errorMessage);
      return { success: false, error: errorMessage };
    } finally {
      setLoading(false);
    }
  };

  return {
    sendCode,
    verifyCode,
    loading,
    error,
  };
}
```

### Email Verification Component

```typescript
// components/EmailVerification.tsx
import React, { useState, useEffect } from 'react';
import { useEmailVerification } from '../hooks/useEmailVerification';

interface EmailVerificationProps {
  email: string;
  onSuccess: () => void;
  type?: 'email_verification' | 'password_reset';
}

export function EmailVerification({ email, onSuccess, type = 'email_verification' }: EmailVerificationProps) {
  const [code, setCode] = useState('');
  const [codeId, setCodeId] = useState<string | null>(null);
  const [timeLeft, setTimeLeft] = useState(0);
  const [canResend, setCanResend] = useState(false);
  
  const { sendCode, verifyCode, loading, error } = useEmailVerification();

  // Timer for resend functionality
  useEffect(() => {
    if (timeLeft > 0) {
      const timer = setTimeout(() => setTimeLeft(timeLeft - 1), 1000);
      return () => clearTimeout(timer);
    } else {
      setCanResend(true);
    }
  }, [timeLeft]);

  // Send initial code
  useEffect(() => {
    handleSendCode();
  }, []);

  const handleSendCode = async () => {
    const result = await sendCode(email, type);
    if (result.success && result.codeId) {
      setCodeId(result.codeId);
      setTimeLeft(600); // 10 minutes
      setCanResend(false);
    }
  };

  const handleVerifyCode = async () => {
    if (!codeId || !code) return;

    const result = await verifyCode(codeId, code);
    if (result.success) {
      onSuccess();
    }
  };

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return \`\${mins}:\${secs.toString().padStart(2, '0')}\`;
  };

  return (
    <div className="max-w-md mx-auto p-6 bg-white rounded-lg shadow-md">
      <h2 className="text-2xl font-bold mb-4">
        {type === 'email_verification' ? 'Verify Your Email' : 'Reset Password'}
      </h2>
      
      <p className="text-gray-600 mb-4">
        We've sent a verification code to <strong>{email}</strong>
      </p>

      <div className="mb-4">
        <label htmlFor="code" className="block text-sm font-medium text-gray-700 mb-2">
          Verification Code
        </label>
        <input
          id="code"
          type="text"
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
          placeholder="Enter 6-digit code"
          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          maxLength={6}
        />
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
          {error}
        </div>
      )}

      <button
        onClick={handleVerifyCode}
        disabled={loading || code.length !== 6}
        className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed mb-4"
      >
        {loading ? 'Verifying...' : 'Verify Code'}
      </button>

      <div className="text-center">
        {timeLeft > 0 ? (
          <p className="text-gray-600">
            Resend code in {formatTime(timeLeft)}
          </p>
        ) : (
          <button
            onClick={handleSendCode}
            disabled={loading}
            className="text-blue-600 hover:text-blue-800 disabled:opacity-50"
          >
            {loading ? 'Sending...' : 'Resend Code'}
          </button>
        )}
      </div>
    </div>
  );
}
```

## Security Best Practices

1. **Rate Limiting**: Implement rate limiting on your endpoints
2. **Code Expiry**: Codes expire after 10 minutes by default
3. **Attempt Limits**: Codes can only be used 3 times before being invalidated
4. **Secure Storage**: Codes are hashed before storage
5. **Cleanup**: Expired codes are automatically cleaned up

## Customization

### Custom Email Templates

```typescript
const customTemplate = \`
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Your Custom Template</title>
</head>
<body>
  <h1>Your App Name</h1>
  <p>Your verification code is: <strong>\${code}</strong></p>
  <p>This code expires in 10 minutes.</p>
</body>
</html>
\`;

await emailService.sendVerificationEmail(email, code, {
  subject: 'Custom Subject',
  template: customTemplate,
  metadata: { appName: 'Your App' }
});
```

### Custom Email Service

```typescript
import { EmailService } from 'authrix/email';

export class CustomEmailService implements EmailService {
  async sendVerificationEmail(to: string, code: string, options = {}) {
    // Your custom email sending logic
    console.log(\`Sending code \${code} to \${to}\`);
  }
}
```

This setup provides a complete 2FA email verification system that's secure, customizable, and easy to integrate into any application.
