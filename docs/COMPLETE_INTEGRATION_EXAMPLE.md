# Complete 2FA Email Verification Integration Example

This example shows how to integrate the Authrix 2FA email verification system into your application.

## Quick Start

### 1. Install Dependencies

```bash
npm install authrix bcryptjs nodemailer
# For specific email providers:
npm install @sendgrid/mail  # For SendGrid
npm install resend          # For Resend
```

### 2. Environment Variables

Create a `.env.local` file:

```env
# Email Provider Configuration (choose one)

# Gmail Configuration
EMAIL_PROVIDER=gmail
GMAIL_USER=your-email@gmail.com
GMAIL_APP_PASSWORD=your-app-password

# Resend Configuration
EMAIL_PROVIDER=resend
RESEND_API_KEY=re_your_api_key

# SendGrid Configuration
EMAIL_PROVIDER=sendgrid
SENDGRID_API_KEY=SG.your_api_key

# Custom SMTP Configuration
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.your-provider.com
SMTP_PORT=587
SMTP_USER=your-username
SMTP_PASS=your-password
SMTP_SECURE=false

# Development (Console logging)
EMAIL_PROVIDER=console

# Application Settings
JWT_SECRET=your-super-secret-jwt-key
MONGODB_URI=mongodb://localhost:27017/your-database
```

### 3. Database Setup (MongoDB)

```javascript
// collections/users.js
db.users.createIndex({ email: 1 }, { unique: true });
db.users.createIndex({ createdAt: 1 }, { expireAfterSeconds: 86400 }); // Optional: expire unverified users

// collections/twoFactorCodes.js
db.twoFactorCodes.createIndex({ codeId: 1 }, { unique: true });
db.twoFactorCodes.createIndex({ createdAt: 1 }, { expireAfterSeconds: 600 }); // Expire after 10 minutes
db.twoFactorCodes.createIndex({ email: 1 });
```

## Next.js Implementation

### API Routes

Create these files in your `app/api/auth/` directory:

```typescript
// app/api/auth/send-verification-code/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { rateLimit } from '@/lib/rate-limit';
import { TwoFactorService } from 'authrix/core/twoFactor';
import { getEmailService } from '@/lib/email-service';

const limiter = rateLimit({
  interval: 60 * 1000, // 1 minute
  uniqueTokenPerInterval: 500,
});

export async function POST(request: NextRequest) {
  try {
    // Rate limiting
    await limiter.check(request, 5, 'send-verification-code');

    const { email, type = 'email_verification' } = await request.json();

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return NextResponse.json(
        { error: 'Valid email is required' },
        { status: 400 }
      );
    }

    const emailService = getEmailService();
    const twoFactorService = new TwoFactorService(emailService);

    const result = await twoFactorService.sendVerificationCode(email, type);

    // In development, include the code for testing
    const response: any = { codeId: result.codeId };
    if (process.env.NODE_ENV === 'development') {
      response.code = result.code;
    }

    return NextResponse.json(response);

  } catch (error: any) {
    console.error('Send verification code error:', error);
    
    if (error.message === 'Rate limit exceeded') {
      return NextResponse.json(
        { error: 'Too many requests. Please try again later.' },
        { status: 429 }
      );
    }

    return NextResponse.json(
      { error: error.message || 'Failed to send verification code' },
      { status: 500 }
    );
  }
}
```

```typescript
// app/api/auth/verify-code/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { rateLimit } from '@/lib/rate-limit';
import { TwoFactorService } from 'authrix/core/twoFactor';
import { getEmailService } from '@/lib/email-service';

const limiter = rateLimit({
  interval: 60 * 1000, // 1 minute
  uniqueTokenPerInterval: 500,
});

export async function POST(request: NextRequest) {
  try {
    // Rate limiting
    await limiter.check(request, 10, 'verify-code');

    const { codeId, code } = await request.json();

    if (!codeId || !code) {
      return NextResponse.json(
        { error: 'Code ID and verification code are required' },
        { status: 400 }
      );
    }

    if (!/^\d{6}$/.test(code)) {
      return NextResponse.json(
        { error: 'Invalid code format. Must be 6 digits.' },
        { status: 400 }
      );
    }

    const emailService = getEmailService();
    const twoFactorService = new TwoFactorService(emailService);

    const result = await twoFactorService.verifyCode(codeId, code);

    return NextResponse.json({
      verified: true,
      email: result.email,
      type: result.type
    });

  } catch (error: any) {
    console.error('Verify code error:', error);
    
    if (error.message === 'Rate limit exceeded') {
      return NextResponse.json(
        { error: 'Too many requests. Please try again later.' },
        { status: 429 }
      );
    }

    return NextResponse.json(
      { error: error.message || 'Failed to verify code' },
      { status: 400 }
    );
  }
}
```

### Email Service Configuration

```typescript
// lib/email-service.ts
import { 
  GmailEmailService, 
  ResendEmailService, 
  SendGridEmailService, 
  SMTPEmailService, 
  ConsoleEmailService 
} from 'authrix/email/providers';

export function getEmailService() {
  const provider = process.env.EMAIL_PROVIDER;

  switch (provider) {
    case 'gmail':
      return new GmailEmailService({
        user: process.env.GMAIL_USER!,
        pass: process.env.GMAIL_APP_PASSWORD!
      });

    case 'resend':
      return new ResendEmailService({
        apiKey: process.env.RESEND_API_KEY!
      });

    case 'sendgrid':
      return new SendGridEmailService({
        apiKey: process.env.SENDGRID_API_KEY!
      });

    case 'smtp':
      return new SMTPEmailService({
        host: process.env.SMTP_HOST!,
        port: parseInt(process.env.SMTP_PORT!),
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER!,
          pass: process.env.SMTP_PASS!
        }
      });

    case 'console':
    default:
      return new ConsoleEmailService();
  }
}
```

### React Components

```typescript
// components/EmailVerificationForm.tsx
'use client';

import { useState } from 'react';
import { useEmailVerification } from '@/hooks/useEmailVerification';

interface EmailVerificationFormProps {
  email: string;
  onSuccess: (result: any) => void;
  onCancel?: () => void;
  type?: 'email_verification' | 'password_reset';
}

export function EmailVerificationForm({
  email,
  onSuccess,
  onCancel,
  type = 'email_verification'
}: EmailVerificationFormProps) {
  const [code, setCode] = useState('');
  
  const {
    isLoading,
    error,
    formattedTimeLeft,
    shouldShowResendButton,
    canSendCode,
    sendCode,
    verifyCode,
    isCodeSent
  } = useEmailVerification(email, type, { autoSendOnMount: true });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const result = await verifyCode(code);
    if (result.success) {
      onSuccess(result.data);
    }
  };

  const handleCodeChange = (value: string) => {
    // Only allow digits, limit to 6 characters
    const sanitized = value.replace(/\D/g, '').slice(0, 6);
    setCode(sanitized);
  };

  return (
    <div className="max-w-md mx-auto p-6 bg-white rounded-lg shadow-lg">
      <div className="text-center mb-6">
        <h2 className="text-2xl font-bold mb-2">
          {type === 'password_reset' ? 'Reset Password' : 'Verify Email'}
        </h2>
        <p className="text-gray-600">
          We've sent a verification code to {email}
        </p>
      </div>

      {isCodeSent && (
        <div className="mb-4 p-3 bg-green-50 border border-green-200 rounded">
          <p className="text-green-700 text-sm">
            Verification code sent successfully!
          </p>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-2">
            Verification Code
          </label>
          <input
            type="text"
            value={code}
            onChange={(e) => handleCodeChange(e.target.value)}
            placeholder="Enter 6-digit code"
            className="w-full px-4 py-3 text-center text-lg font-mono border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            maxLength={6}
            disabled={isLoading}
            autoComplete="one-time-code"
          />
        </div>

        {error && (
          <div className="p-3 bg-red-50 border border-red-200 rounded">
            <p className="text-red-700 text-sm">{error}</p>
          </div>
        )}

        <button
          type="submit"
          disabled={isLoading || code.length !== 6}
          className="w-full bg-blue-600 text-white py-3 rounded-lg font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isLoading ? 'Verifying...' : 'Verify Code'}
        </button>

        {shouldShowResendButton && (
          <div className="text-center">
            {canSendCode ? (
              <button
                type="button"
                onClick={sendCode}
                disabled={isLoading}
                className="text-blue-600 hover:text-blue-800 text-sm font-medium"
              >
                Resend Code
              </button>
            ) : (
              <p className="text-gray-600 text-sm">
                Resend code in {formattedTimeLeft}
              </p>
            )}
          </div>
        )}

        {onCancel && (
          <button
            type="button"
            onClick={onCancel}
            disabled={isLoading}
            className="w-full bg-gray-100 text-gray-700 py-2 rounded-lg hover:bg-gray-200"
          >
            Cancel
          </button>
        )}
      </form>

      {process.env.NODE_ENV === 'development' && (
        <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded">
          <p className="text-yellow-700 text-xs">
            <strong>Dev Mode:</strong> Check console for verification code
          </p>
        </div>
      )}
    </div>
  );
}
```

### Complete Signup Flow

```typescript
// app/signup/page.tsx
'use client';

import { useState } from 'react';
import { EmailVerificationForm } from '@/components/EmailVerificationForm';

export default function SignupPage() {
  const [step, setStep] = useState<'signup' | 'verify' | 'complete'>('signup');
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    name: ''
  });

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      // Create user account (unverified)
      const response = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      });

      if (response.ok) {
        setStep('verify');
      } else {
        const error = await response.json();
        alert(error.message);
      }
    } catch (error) {
      console.error('Signup error:', error);
      alert('Signup failed. Please try again.');
    }
  };

  const handleVerificationSuccess = async (result: any) => {
    try {
      // Mark user as verified
      const response = await fetch('/api/auth/verify-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: formData.email })
      });

      if (response.ok) {
        setStep('complete');
      }
    } catch (error) {
      console.error('Verification completion error:', error);
    }
  };

  if (step === 'verify') {
    return (
      <EmailVerificationForm
        email={formData.email}
        onSuccess={handleVerificationSuccess}
        onCancel={() => setStep('signup')}
        type="email_verification"
      />
    );
  }

  if (step === 'complete') {
    return (
      <div className="text-center">
        <h1 className="text-2xl font-bold mb-4">Account Created!</h1>
        <p className="text-gray-600 mb-6">
          Your email has been verified successfully.
        </p>
        <a 
          href="/login" 
          className="bg-blue-600 text-white px-6 py-3 rounded-lg font-medium hover:bg-blue-700"
        >
          Continue to Login
        </a>
      </div>
    );
  }

  return (
    <form onSubmit={handleSignup} className="max-w-md mx-auto space-y-4">
      <h1 className="text-2xl font-bold text-center mb-6">Create Account</h1>
      
      <div>
        <label className="block text-sm font-medium mb-1">Name</label>
        <input
          type="text"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          required
        />
      </div>

      <div>
        <label className="block text-sm font-medium mb-1">Email</label>
        <input
          type="email"
          value={formData.email}
          onChange={(e) => setFormData({ ...formData, email: e.target.value })}
          className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          required
        />
      </div>

      <div>
        <label className="block text-sm font-medium mb-1">Password</label>
        <input
          type="password"
          value={formData.password}
          onChange={(e) => setFormData({ ...formData, password: e.target.value })}
          className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          required
        />
      </div>

      <button
        type="submit"
        className="w-full bg-blue-600 text-white py-3 rounded-lg font-medium hover:bg-blue-700"
      >
        Create Account
      </button>
    </form>
  );
}
```

## Testing

### Unit Tests

```typescript
// __tests__/email-verification.test.ts
import { TwoFactorService } from 'authrix/core/twoFactor';
import { ConsoleEmailService } from 'authrix/email/providers';

describe('Email Verification', () => {
  let twoFactorService: TwoFactorService;

  beforeEach(() => {
    const emailService = new ConsoleEmailService();
    twoFactorService = new TwoFactorService(emailService);
  });

  test('should send verification code', async () => {
    const result = await twoFactorService.sendVerificationCode(
      'test@example.com',
      'email_verification'
    );

    expect(result.codeId).toBeDefined();
    expect(result.code).toMatch(/^\d{6}$/);
  });

  test('should verify correct code', async () => {
    const sendResult = await twoFactorService.sendVerificationCode(
      'test@example.com',
      'email_verification'
    );

    const verifyResult = await twoFactorService.verifyCode(
      sendResult.codeId,
      sendResult.code
    );

    expect(verifyResult.email).toBe('test@example.com');
    expect(verifyResult.type).toBe('email_verification');
  });

  test('should reject invalid code', async () => {
    const sendResult = await twoFactorService.sendVerificationCode(
      'test@example.com',
      'email_verification'
    );

    await expect(
      twoFactorService.verifyCode(sendResult.codeId, '000000')
    ).rejects.toThrow('Invalid verification code');
  });
});
```

### Manual Testing

1. **Development Mode**: Set `EMAIL_PROVIDER=console` to see codes in console
2. **Rate Limiting**: Test with multiple rapid requests
3. **Email Delivery**: Test with actual email providers
4. **UI Flow**: Test complete signup → verify → login flow

## Security Considerations

1. **Rate Limiting**: Implemented on both send and verify endpoints
2. **Code Expiry**: Codes expire after 10 minutes
3. **Attempt Limits**: Maximum 3 verification attempts per code
4. **Secure Storage**: Codes are hashed using bcryptjs
5. **Input Validation**: Email format and code format validation
6. **CSRF Protection**: Use CSRF tokens in production
7. **HTTPS Only**: Ensure all requests use HTTPS in production

## Production Deployment

1. **Environment Variables**: Set all production email provider credentials
2. **Database Indexes**: Ensure MongoDB indexes are created
3. **Rate Limiting**: Configure appropriate limits for your traffic
4. **Email Templates**: Customize email templates for your brand
5. **Monitoring**: Set up logging and monitoring for email delivery
6. **Backup Providers**: Configure fallback email providers

## Troubleshooting

### Common Issues

1. **Codes not received**: Check email provider credentials and spam folders
2. **Rate limit errors**: Reduce request frequency or increase limits
3. **Database errors**: Verify MongoDB connection and indexes
4. **TypeScript errors**: Ensure all required dependencies are installed

### Debug Mode

Set `NODE_ENV=development` to:
- See verification codes in console
- Get detailed error messages
- Enable debug logging

This completes your 2FA email verification setup with Authrix!
