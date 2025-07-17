# 2FA Email Verification Guide

This guide explains how to set up and use 2FA email verification with Authrix.

## Overview

Authrix provides a comprehensive 2FA (Two-Factor Authentication) email verification system that:

- ✅ Generates secure verification codes
- ✅ Supports multiple email providers (Gmail, Resend, SendGrid, SMTP)
- ✅ Includes rate limiting and security features
- ✅ Provides ready-to-use API endpoints
- ✅ Works with any database adapter

## Quick Setup

### 1. Choose an Email Provider

Pick one of the supported email services:

#### Option A: Gmail (Recommended for development)
```bash
# Install dependencies
npm install nodemailer @types/nodemailer

# Set environment variables
GMAIL_USER=your-email@gmail.com
GMAIL_APP_PASSWORD=your-app-password  # Generate at https://myaccount.google.com/apppasswords
DEFAULT_EMAIL_SERVICE=gmail
```

#### Option B: Resend (Recommended for production)
```bash
# Install dependencies
npm install resend

# Set environment variables
RESEND_API_KEY=your-api-key  # Get from https://resend.com/api-keys
RESEND_FROM_EMAIL=noreply@yourdomain.com
DEFAULT_EMAIL_SERVICE=resend
```

#### Option C: SendGrid
```bash
# Install dependencies
npm install @sendgrid/mail

# Set environment variables
SENDGRID_API_KEY=your-api-key
SENDGRID_FROM_EMAIL=verified-sender@yourdomain.com
DEFAULT_EMAIL_SERVICE=sendgrid
```

#### Option D: Generic SMTP
```bash
# Install dependencies
npm install nodemailer @types/nodemailer

# Set environment variables
SMTP_HOST=smtp.yourprovider.com
SMTP_PORT=587
SMTP_USER=your-username
SMTP_PASS=your-password
SMTP_FROM=noreply@yourdomain.com
DEFAULT_EMAIL_SERVICE=smtp
```

### 2. Update Your Database Adapter

Ensure your database adapter supports 2FA operations. The MongoDB adapter is already updated.

For **MongoDB**, add these environment variables:
```bash
MONGO_URI=mongodb://localhost:27017
DB_NAME=your_database
AUTH_COLLECTION=users
TWO_FACTOR_COLLECTION=two_factor_codes  # Optional, defaults to 'two_factor_codes'
```

### 3. Initialize Authrix with 2FA Support

```typescript
import { initAuth } from 'authrix';
import { mongoAdapter } from 'authrix/adapters/mongo';
import 'authrix/email'; // This auto-initializes email services

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter, // Now includes 2FA support
});
```

## API Endpoints

### Setup Express Routes

```typescript
import express from 'express';
import { 
  sendVerificationCodeHandler,
  verifyCodeHandler,
  getEmailServicesHandler,
  testEmailServiceHandler,
  signupWithVerificationHandler
} from 'authrix/core/emailEndpoints';

const app = express();
app.use(express.json());

// 2FA Email Verification Routes
app.post('/api/auth/send-verification-code', sendVerificationCodeHandler);
app.post('/api/auth/verify-code', verifyCodeHandler);
app.post('/api/auth/signup-with-verification', signupWithVerificationHandler);

// Service Management Routes
app.get('/api/auth/email-services', getEmailServicesHandler);
app.post('/api/auth/test-email-service', testEmailServiceHandler); // Development only
```

### API Usage Examples

#### 1. Send Verification Code
```typescript
// POST /api/auth/send-verification-code
{
  "email": "user@example.com",
  "userId": "user123" // Optional if user is authenticated
}

// Response
{
  "success": true,
  "data": {
    "codeId": "uuid-code-id",
    "expiresAt": "2024-01-01T12:10:00.000Z",
    "message": "Verification code sent to user@example.com. Code expires in 10 minutes."
  }
}
```

#### 2. Verify Code
```typescript
// POST /api/auth/verify-code
{
  "codeId": "uuid-code-id",
  "code": "123456",
  "userId": "user123" // Optional if user is authenticated
}

// Response (Success)
{
  "success": true,
  "data": {
    "verified": true,
    "message": "Email verified successfully"
  }
}

// Response (Error)
{
  "success": false,
  "error": {
    "message": "Invalid verification code",
    "isExpired": false,
    "attemptsRemaining": 2
  }
}
```

#### 3. Signup with Email Verification
```typescript
// POST /api/auth/signup-with-verification
{
  "email": "newuser@example.com",
  "password": "SecurePassword123!",
  "autoSendVerification": true
}

// Response
{
  "success": true,
  "data": {
    "user": {
      "id": "user123",
      "email": "newuser@example.com"
    },
    "emailVerified": false,
    "verification": {
      "codeId": "uuid-code-id",
      "expiresAt": "2024-01-01T12:10:00.000Z",
      "message": "Verification code sent to newuser@example.com..."
    }
  }
}
```

#### 4. Check Email Services
```typescript
// GET /api/auth/email-services

// Response
{
  "success": true,
  "data": {
    "availableServices": ["gmail", "console", "default"],
    "configuredServices": ["gmail", "console"],
    "instructions": {
      "gmail": "// Gmail Email Service\n// 1. Enable 2-Step Verification...",
      // ... other service instructions
    },
    "currentDefault": "gmail"
  }
}
```

## Frontend Integration

### React Example

```typescript
import React, { useState } from 'react';

interface VerificationComponentProps {
  email: string;
  userId?: string;
}

function EmailVerification({ email, userId }: VerificationComponentProps) {
  const [code, setCode] = useState('');
  const [codeId, setCodeId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [attemptsRemaining, setAttemptsRemaining] = useState(3);

  const sendVerificationCode = async () => {
    setIsLoading(true);
    try {
      const response = await fetch('/api/auth/send-verification-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, userId }),
        credentials: 'include'
      });

      const data = await response.json();
      if (data.success) {
        setCodeId(data.data.codeId);
        setMessage(data.data.message);
      } else {
        setMessage(data.error.message);
      }
    } catch (error) {
      setMessage('Failed to send verification code');
    } finally {
      setIsLoading(false);
    }
  };

  const verifyCode = async () => {
    if (!codeId || !code) return;

    setIsLoading(true);
    try {
      const response = await fetch('/api/auth/verify-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ codeId, code, userId }),
        credentials: 'include'
      });

      const data = await response.json();
      if (data.success) {
        setMessage('Email verified successfully!');
        // Handle successful verification (e.g., redirect, update UI)
      } else {
        setMessage(data.error.message);
        setAttemptsRemaining(data.error.attemptsRemaining || 0);
      }
    } catch (error) {
      setMessage('Failed to verify code');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="email-verification">
      <h3>Verify Your Email</h3>
      <p>We need to verify your email address: <strong>{email}</strong></p>
      
      {!codeId ? (
        <button 
          onClick={sendVerificationCode} 
          disabled={isLoading}
          className="btn btn-primary"
        >
          {isLoading ? 'Sending...' : 'Send Verification Code'}
        </button>
      ) : (
        <div>
          <p>Enter the 6-digit code sent to your email:</p>
          <div className="code-input-group">
            <input
              type="text"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="Enter 6-digit code"
              maxLength={6}
              className="code-input"
            />
            <button 
              onClick={verifyCode} 
              disabled={isLoading || !code}
              className="btn btn-success"
            >
              {isLoading ? 'Verifying...' : 'Verify'}
            </button>
          </div>
          <p className="attempts-remaining">
            Attempts remaining: {attemptsRemaining}
          </p>
          <button 
            onClick={sendVerificationCode} 
            disabled={isLoading}
            className="btn btn-link"
          >
            Resend Code
          </button>
        </div>
      )}
      
      {message && (
        <div className={`message ${message.includes('success') ? 'success' : 'error'}`}>
          {message}
        </div>
      )}
    </div>
  );
}

export default EmailVerification;
```

### Next.js App Router Example

```typescript
// app/verify-email/page.tsx
'use client';

import { useState, useEffect } from 'react';
import { useSearchParams } from 'next/navigation';

export default function VerifyEmailPage() {
  const searchParams = useSearchParams();
  const email = searchParams.get('email');
  const [isVerified, setIsVerified] = useState(false);

  // ... verification logic similar to React example

  return (
    <div className="max-w-md mx-auto mt-8 p-6 bg-white rounded-lg shadow-md">
      {/* Verification form */}
    </div>
  );
}
```

## Advanced Usage

### Custom Email Templates

```typescript
import { EmailServiceRegistry, sendVerificationEmail } from 'authrix/core/twoFactor';

// Custom email template
const customTemplate = (code: string, metadata: any) => `
  <div style="font-family: Arial, sans-serif;">
    <h1>Welcome to ${metadata.appName}!</h1>
    <p>Your verification code is: <strong>${code}</strong></p>
    <p>This code expires in 10 minutes.</p>
  </div>
`;

// Send with custom template
await sendVerificationEmail('user@example.com', '123456', {
  serviceName: 'gmail',
  subject: 'Welcome! Verify your email',
  template: customTemplate('123456', { appName: 'My App' }),
  metadata: { appName: 'My App' }
});
```

### Programmatic Usage

```typescript
import { 
  generateTwoFactorCode, 
  verifyTwoFactorCode,
  initiateEmailVerification 
} from 'authrix/core/twoFactor';

// Generate a verification code
const { code, codeId, expiresAt } = await generateTwoFactorCode('user123', {
  type: 'email_verification',
  codeLength: 6,
  expiryMinutes: 10,
  metadata: { email: 'user@example.com' }
});

// Send email manually
await sendVerificationEmail('user@example.com', code, {
  serviceName: 'resend'
});

// Verify the code
const verification = await verifyTwoFactorCode(codeId, '123456', 'user123');
if (verification.isValid) {
  console.log('Email verified successfully!');
}

// Or use the complete workflow
const result = await initiateEmailVerification('user123', 'user@example.com', {
  serviceName: 'gmail',
  subject: 'Verify your account',
  codeLength: 8,
  expiryMinutes: 15
});
```

### Cleanup Expired Codes

```typescript
import { cleanupExpiredCodes } from 'authrix/core/twoFactor';

// Run periodically (e.g., via cron job)
setInterval(async () => {
  const deletedCount = await cleanupExpiredCodes();
  console.log(`Cleaned up ${deletedCount} expired verification codes`);
}, 60 * 60 * 1000); // Every hour
```

## Security Features

- **Rate Limiting**: Maximum 5 code generations per hour per email/user
- **Code Expiry**: Codes expire after 10 minutes (configurable)
- **Attempt Limiting**: Maximum 3 verification attempts per code
- **Secure Hashing**: Codes are hashed using bcrypt before storage
- **Single Use**: Codes can only be used once
- **IP Tracking**: Request IP addresses are logged for audit purposes

## Troubleshooting

### Common Issues

1. **"Email service not configured"**
   - Check that you've installed the required dependencies
   - Verify environment variables are set correctly
   - Use `GET /api/auth/email-services` to check configuration

2. **"Too many verification code requests"**
   - Rate limiting is active (5 requests per hour)
   - Wait or implement exponential backoff

3. **"Gmail authentication failed"**
   - Enable 2-Step Verification in Google Account
   - Generate App Password (not your regular password)
   - Use the App Password in `GMAIL_APP_PASSWORD`

4. **Emails not being sent**
   - Check your email service provider's logs
   - Verify sender email is verified/configured
   - Test with `POST /api/auth/test-email-service` in development

### Testing in Development

```typescript
// Use console service for development
process.env.DEFAULT_EMAIL_SERVICE = 'console';

// Enable email service testing in production
process.env.ALLOW_EMAIL_SERVICE_TESTING = 'true';

// Test email service
const response = await fetch('/api/auth/test-email-service', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ 
    email: 'test@example.com',
    serviceName: 'console'
  })
});
```

## Production Checklist

- [ ] Choose production email service (Resend, SendGrid, or SMTP)
- [ ] Configure domain verification for your email provider
- [ ] Set up proper DNS records (SPF, DKIM, DMARC)
- [ ] Configure rate limiting and monitoring
- [ ] Set up automated cleanup of expired codes
- [ ] Test email delivery and templates
- [ ] Configure error logging and monitoring
- [ ] Set secure environment variables
- [ ] Remove development-only features (`ALLOW_EMAIL_SERVICE_TESTING`)

## Environment Variables Reference

```bash
# Database (MongoDB example)
MONGO_URI=mongodb://localhost:27017
DB_NAME=authrix_production
AUTH_COLLECTION=users
TWO_FACTOR_COLLECTION=two_factor_codes

# Gmail Service
GMAIL_USER=your-email@gmail.com
GMAIL_APP_PASSWORD=your-app-password

# Resend Service
RESEND_API_KEY=your-api-key
RESEND_FROM_EMAIL=noreply@yourdomain.com

# SendGrid Service
SENDGRID_API_KEY=your-api-key
SENDGRID_FROM_EMAIL=verified-sender@yourdomain.com

# Generic SMTP
SMTP_HOST=smtp.yourprovider.com
SMTP_PORT=587
SMTP_USER=your-username
SMTP_PASS=your-password
SMTP_FROM=noreply@yourdomain.com

# General Settings
DEFAULT_EMAIL_SERVICE=resend
APP_NAME=Your App Name
NODE_ENV=production

# Development/Testing
ALLOW_EMAIL_SERVICE_TESTING=false
```

This comprehensive 2FA email verification system provides enterprise-grade security with developer-friendly APIs and extensive customization options.
