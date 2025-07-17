# SSO and Forgot Password Features Guide

This guide covers the Single Sign-On (SSO) and forgot password functionality added to Authrix.

## Table of Contents

1. [SSO (Single Sign-On)](#sso-single-sign-on)
2. [Forgot Password](#forgot-password)
3. [Framework Integration](#framework-integration)
4. [Configuration](#configuration)
5. [Examples](#examples)

## SSO (Single Sign-On)

Authrix now supports SSO authentication with Google and GitHub, with extensible support for custom providers.

### Core SSO Functions

#### `processSSOAuthentication(ssoUser, options)`

Processes SSO authentication and creates or updates users.

```typescript
import { processSSOAuthentication, SSOUser } from 'authrix';

const ssoUser: SSOUser = {
  id: 'google_123456789',
  email: 'user@example.com',
  name: 'John Doe',
  provider: 'google',
  verified: true
};

const result = await processSSOAuthentication(ssoUser, {
  autoCreateUser: true,
  updateExistingUser: true,
  requireVerifiedEmail: true
});

console.log(result.user); // User object
console.log(result.token); // JWT token
console.log(result.isNewUser); // Boolean
```

#### Options

- `autoCreateUser` (default: `true`) - Automatically create user if not exists
- `updateExistingUser` (default: `false`) - Update existing user data
- `requireVerifiedEmail` (default: `true`) - Require verified email from provider
- `mergeUserData` (default: `true`) - Merge SSO data with existing user
- `customUserMapping` - Function to customize user data mapping

#### `handleGoogleSSO(code, options)` & `handleGitHubSSO(code, options)`

Handle OAuth callbacks from Google and GitHub.

```typescript
import { handleGoogleSSO, handleGitHubSSO } from 'authrix';

// Handle Google OAuth
const googleResult = await handleGoogleSSO(authCode);

// Handle GitHub OAuth  
const githubResult = await handleGitHubSSO(authCode);
```

#### State Management

```typescript
import { generateSSOState, verifySSOState } from 'authrix';

// Generate secure state for OAuth
const state = generateSSOState({ redirect: '/dashboard' });

// Verify state in callback
const stateData = verifySSOState(state);
console.log(stateData.redirect); // '/dashboard'
```

### Custom SSO Providers

```typescript
import { handleCustomSSO, SSOUser } from 'authrix';

const customSSOUser: SSOUser = {
  id: 'provider_user_id',
  email: 'user@example.com',
  name: 'User Name',
  provider: 'custom_provider',
  verified: true
};

const result = await handleCustomSSO('custom_provider', customSSOUser);
```

## Forgot Password

Comprehensive forgot password functionality with email verification codes.

### Core Functions

#### `initiateForgotPassword(email, options)`

Initiates the forgot password process by sending a verification code.

```typescript
import { initiateForgotPassword } from 'authrix';

const result = await initiateForgotPassword('user@example.com', {
  codeLength: 6,
  codeExpiration: 15, // minutes
  maxAttempts: 5,
  requireExistingUser: true
});

console.log(result.message); // "Password reset code sent..."
```

#### `resetPasswordWithCode(email, code, newPassword, options)`

Resets password using the verification code.

```typescript
import { resetPasswordWithCode } from 'authrix';

const result = await resetPasswordWithCode(
  'user@example.com',
  '123456',
  'NewSecurePassword123!',
  {
    minPasswordLength: 8,
    requireStrongPassword: true,
    preventReuse: true
  }
);

console.log(result.user); // Updated user object
```

#### `generateTemporaryPassword(length)` & `sendTemporaryPassword(email, options)`

Alternative approach using temporary passwords.

```typescript
import { generateTemporaryPassword, sendTemporaryPassword } from 'authrix';

// Generate a secure temporary password
const tempPassword = generateTemporaryPassword(12);

// Send temporary password to user
const result = await sendTemporaryPassword('user@example.com', {
  temporaryPasswordLength: 16
});
```

### Options

#### Forgot Password Options
- `codeLength` (default: `6`) - Length of verification code
- `codeExpiration` (default: `15`) - Expiration time in minutes
- `maxAttempts` (default: `5`) - Maximum verification attempts
- `rateLimitDelay` (default: `60`) - Rate limit delay in seconds
- `requireExistingUser` (default: `true`) - Only send codes to existing users
- `customEmailTemplate` - Custom email template function

#### Reset Password Options
- `minPasswordLength` (default: `8`) - Minimum password length
- `requireStrongPassword` (default: `true`) - Enforce strong password rules
- `invalidateAllSessions` (default: `true`) - Invalidate existing sessions
- `preventReuse` (default: `false`) - Prevent reusing current password

### Custom Email Templates

```typescript
const customTemplate = (email: string, code: string, username?: string) => ({
  subject: 'Your Password Reset Code',
  text: `Hi ${username || 'there'}, your reset code is: ${code}`,
  html: `
    <div>
      <h2>Password Reset</h2>
      <p>Hi ${username || 'there'},</p>
      <p>Your reset code is: <strong>${code}</strong></p>
    </div>
  `
});

await initiateForgotPassword('user@example.com', {
  customEmailTemplate: customTemplate
});
```

## Framework Integration

Authrix provides helpers for easy integration with popular frameworks.

### Universal Helpers

```typescript
import { ssoHelpers, forgotPasswordHelpers } from 'authrix';

// SSO helpers
const googleUrl = ssoHelpers.getGoogleAuthUrl('/dashboard');
const githubUrl = ssoHelpers.getGitHubAuthUrl('/profile');

const result = await ssoHelpers.handleCallback('google', code, state);

// Forgot password helpers
await forgotPasswordHelpers.initiate('user@example.com');
await forgotPasswordHelpers.reset('user@example.com', '123456', 'newPass');
```

### Next.js App Router

```typescript
// app/api/auth/google/route.ts
import { ssoHelpers } from 'authrix';
import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  const url = new URL(request.url);
  const redirectUrl = url.searchParams.get('redirect') || '/dashboard';
  const authUrl = ssoHelpers.getGoogleAuthUrl(redirectUrl);
  return NextResponse.redirect(authUrl);
}

// app/api/auth/google/callback/route.ts
export async function GET(request: NextRequest) {
  try {
    const url = new URL(request.url);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    
    if (!code || !state) {
      return NextResponse.json({ error: 'Missing parameters' }, { status: 400 });
    }

    const result = await ssoHelpers.handleCallback('google', code, state);
    
    const response = NextResponse.redirect(result.redirectUrl);
    response.cookies.set('auth_token', result.token, result.cookieOptions);
    return response;
  } catch (error) {
    return NextResponse.redirect('/auth/error?message=' + encodeURIComponent(error.message));
  }
}

// app/api/auth/forgot-password/route.ts
import { forgotPasswordHelpers } from 'authrix';

export async function POST(request: NextRequest) {
  try {
    const { email } = await request.json();
    const result = await forgotPasswordHelpers.initiate(email);
    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
```

### Express.js

```typescript
import express from 'express';
import { ssoHelpers, forgotPasswordHelpers } from 'authrix';

const router = express.Router();

// Google OAuth initiation
router.get('/auth/google', (req, res) => {
  const redirectUrl = req.query.redirect || '/dashboard';
  const authUrl = ssoHelpers.getGoogleAuthUrl(redirectUrl);
  res.redirect(authUrl);
});

// Google OAuth callback
router.get('/auth/google/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const result = await ssoHelpers.handleCallback('google', code, state);
    
    res.cookie('auth_token', result.token, result.cookieOptions);
    res.redirect(result.redirectUrl);
  } catch (error) {
    res.redirect('/auth/error?message=' + encodeURIComponent(error.message));
  }
});

// Forgot password
router.post('/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const result = await forgotPasswordHelpers.initiate(email);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
```

### React Components

```typescript
import React, { useState } from 'react';
import { ssoHelpers } from 'authrix';

// Social login buttons
export function SocialLoginButtons() {
  const handleGoogleLogin = () => {
    const authUrl = ssoHelpers.getGoogleAuthUrl(window.location.pathname);
    window.location.href = authUrl;
  };

  const handleGitHubLogin = () => {
    const authUrl = ssoHelpers.getGitHubAuthUrl(window.location.pathname);
    window.location.href = authUrl;
  };

  return (
    <div className="social-login">
      <button onClick={handleGoogleLogin} className="google-btn">
        Login with Google
      </button>
      <button onClick={handleGitHubLogin} className="github-btn">
        Login with GitHub
      </button>
    </div>
  );
}

// Forgot password form
export function ForgotPasswordForm() {
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [step, setStep] = useState('email'); // 'email' or 'reset'
  const [isLoading, setIsLoading] = useState(false);

  const handleRequestCode = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    
    try {
      const response = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      
      const result = await response.json();
      if (result.success) {
        setStep('reset');
        alert('Reset code sent to your email');
      }
    } catch (error) {
      alert('Error: ' + error.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    
    try {
      const response = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code, newPassword })
      });
      
      const result = await response.json();
      if (result.success) {
        alert('Password reset successfully');
        setStep('email');
        setEmail('');
        setCode('');
        setNewPassword('');
      }
    } catch (error) {
      alert('Error: ' + error.message);
    } finally {
      setIsLoading(false);
    }
  };

  if (step === 'email') {
    return (
      <form onSubmit={handleRequestCode}>
        <h3>Forgot Password</h3>
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="Enter your email"
          required
        />
        <button type="submit" disabled={isLoading}>
          {isLoading ? 'Sending...' : 'Send Reset Code'}
        </button>
      </form>
    );
  }

  return (
    <form onSubmit={handleResetPassword}>
      <h3>Reset Password</h3>
      <input
        type="text"
        value={code}
        onChange={(e) => setCode(e.target.value)}
        placeholder="Enter verification code"
        required
      />
      <input
        type="password"
        value={newPassword}
        onChange={(e) => setNewPassword(e.target.value)}
        placeholder="Enter new password"
        required
      />
      <button type="submit" disabled={isLoading}>
        {isLoading ? 'Resetting...' : 'Reset Password'}
      </button>
      <button type="button" onClick={() => setStep('email')}>
        Back
      </button>
    </form>
  );
}
```

## Configuration

### Environment Variables

For SSO functionality, ensure you have the required OAuth credentials:

```bash
# Google OAuth
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

# GitHub OAuth
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret

# Base URLs
NEXTAUTH_URL=http://localhost:3000
```

### Database Requirements

Your database adapter should support the `updateUser` method for forgot password functionality:

```typescript
interface AuthDbAdapter {
  // Required for basic auth
  findUserByEmail(email: string): Promise<AuthUser | null>;
  createUser(data: CreateUserData): Promise<AuthUser>;
  
  // Required for SSO and forgot password
  updateUser?(id: string, data: Partial<AuthUser>): Promise<AuthUser>;
  findUserByUsername?(username: string): Promise<AuthUser | null>;
}
```

## Security Considerations

1. **State Verification**: Always verify OAuth state parameters to prevent CSRF attacks
2. **Rate Limiting**: Implement rate limiting for forgot password requests
3. **Code Expiration**: Use short expiration times for verification codes
4. **Strong Passwords**: Enforce strong password requirements
5. **Session Management**: Consider invalidating existing sessions on password reset
6. **Email Security**: Use secure email services and templates
7. **Database Security**: Ensure secure storage of user data and verification codes

## Error Handling

The SSO and forgot password functions provide comprehensive error handling:

```typescript
try {
  const result = await initiateForgotPassword('user@example.com');
} catch (error) {
  if (error.message.includes('rate limit')) {
    // Handle rate limiting
  } else if (error.message.includes('Invalid email')) {
    // Handle invalid email format
  } else {
    // Handle other errors
  }
}
```

## Testing

Comprehensive test suites are included for both SSO and forgot password functionality. Run tests with:

```bash
npm test src/__tests__/core/sso.test.ts
npm test src/__tests__/core/forgotPassword.test.ts
```

This completes the SSO and forgot password implementation for Authrix, providing a robust, secure, and flexible authentication system that works across multiple frameworks.
