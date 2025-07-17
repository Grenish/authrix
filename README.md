# Authrix

<div align="center">
  <img src="./logo/logo.svg" alt="Authrix Logo" width="250" height="200">
</div>

> A production-ready, framework-agnostic authentication library for Node.js and TypeScript

[![npm version](https://img.shields.io/npm/v/authrix.svg)](https://www.npmjs.com/package/authrix)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/Tests-Jest-green.svg)](https://jestjs.io/)

**Authrix** is a comprehensive authentication library designed for enterprise-grade applications. Built with TypeScript-first architecture, it provides complete authentication flows including JWT tokens, OAuth SSO, 2FA email verification, forgot password systems, and user profile management across any JavaScript framework or runtime environment.

## 🏗️ Architecture Overview

Authrix follows a modular, adapter-based architecture that separates concerns and enables flexible integration:

```
┌─────────────────────────────────────────────────────┐
│                 Authrix Core                        │
├─────────────────────────────────────────────────────┤
│  Authentication  │  SSO/OAuth  │  Password Recovery │
│      Layer       │    Layer    │      Layer         │
├─────────────────────────────────────────────────────┤
│              Framework Adapters                     │
│  Next.js │ Express │ React │ Universal │ Custom     │
├─────────────────────────────────────────────────────┤
│              Database Adapters                      │
│         MongoDB │ PostgreSQL │ Custom               │
├─────────────────────────────────────────────────────┤
│              Email Service Layer                    │
│  Gmail │ SendGrid │ Resend │ SMTP │ Console         │
└─────────────────────────────────────────────────────┘
```

## ✨ Core Features

### 🔐 **Complete Authentication System**
- **JWT Token Management**: Secure token generation, verification, and refresh
- **Session Management**: Framework-agnostic session handling with HttpOnly cookies
- **Password Security**: bcryptjs hashing with configurable salt rounds and validation
- **Rate Limiting**: Built-in protection against brute force attacks

### 🔑 **SSO & OAuth Integration**
- **Multi-Provider Support**: Google, GitHub with extensible provider architecture
- **State Management**: Secure OAuth state verification and CSRF protection
- **User Provisioning**: Automatic user creation and profile syncing
- **Framework Integration**: Ready-to-use handlers for all supported frameworks

### 📧 **2FA & Email Verification**
- **Multi-Factor Authentication**: Email-based verification codes
- **Email Templates**: Customizable email templates with multiple providers
- **Code Management**: Secure code generation, hashing, and expiration
- **Rate Limiting**: Configurable request throttling and abuse prevention

### 🔒 **Password Recovery System**
- **Secure Reset Flow**: Verification code-based password reset
- **Rate Limiting**: Configurable delays between reset requests
- **Password Validation**: Prevent password reuse and enforce strength requirements
- **Email Integration**: Seamless integration with email service providers

### 👤 **User Profile Management**
- **Extended Profiles**: Username, firstName, lastName fields with validation
- **Flexible Updates**: Partial profile updates with conflict resolution
- **Database Migration**: Backwards-compatible schema evolution
- **Username System**: Unique usernames with case-insensitive lookups

### 🌐 **Framework Agnostic Design**
- **Universal Core**: Framework-independent authentication logic
- **Adapter Pattern**: Pluggable integrations for any framework or database
- **Edge Runtime**: Compatible with modern edge computing environments
- **TypeScript First**: Complete type safety and developer experience

## 📦 Installation & Setup

### Package Installation

```bash
# npm
npm install authrix

# yarn
yarn add authrix

# pnpm
pnpm add authrix

# bun
bun add authrix
```

### Environment Configuration

Create your environment configuration:

```bash
# .env
JWT_SECRET=your-super-secure-jwt-secret-key-min-32-chars
DATABASE_URL=mongodb://localhost:27017/myapp
# or
DATABASE_URL=postgresql://user:password@localhost:5432/myapp

# OAuth Configuration (optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
OAUTH_REDIRECT_URI=http://localhost:3000/api/auth/callback

# Email Configuration (optional)
EMAIL_PROVIDER=gmail # or sendgrid, resend, smtp
GMAIL_EMAIL=your-email@gmail.com
GMAIL_APP_PASSWORD=your-app-password
```

### Database Adapter Setup

Choose and configure your database adapter:

```typescript
// MongoDB Setup
import { mongoAdapter } from "authrix/adapters/mongo";

// PostgreSQL Setup
import { postgresqlAdapter, initializePostgreSQLTables } from "authrix/adapters/postgresql";

// Initialize PostgreSQL tables (run once)
await initializePostgreSQLTables();

// Supabase Setup
import { supabaseAdapter } from "authrix/adapters/supabase";
```

## 🚀 Quick Start Guide

### Basic Express.js Integration

```typescript
import express from "express";
import cookieParser from "cookie-parser";
import { initAuth, signup, signin, getCurrentUser, authMiddleware } from "authrix";
import { mongoAdapter } from "authrix/adapters/mongo";

const app = express();

// Initialize Authrix
initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter,
  cookieName: "auth_token" // optional, defaults to "auth_token"
});

app.use(express.json());
app.use(cookieParser());

// Authentication Routes
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { email, password, username, firstName, lastName } = req.body;
    
    const user = await signup(email, password, res, {
      username,
      firstName, 
      lastName
    });
    
    res.status(201).json({ 
      success: true, 
      user,
      message: "Account created successfully" 
    });
  } catch (error) {
    res.status(400).json({ 
      success: false, 
      error: { message: error.message } 
    });
  }
});

app.post("/api/auth/signin", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await signin(email, password, res);
    
    res.json({ 
      success: true, 
      user,
      message: "Signed in successfully" 
    });
  } catch (error) {
    res.status(401).json({ 
      success: false, 
      error: { message: error.message } 
    });
  }
});

app.get("/api/auth/me", async (req, res) => {
  try {
    const user = await getCurrentUser(req);
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        error: { message: "Not authenticated" } 
      });
    }
    
    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: { message: error.message } 
    });
  }
});

// Protected routes
app.get("/api/user/profile", authMiddleware, (req, res) => {
  res.json({ 
    success: true, 
    user: req.user,
    message: "Profile retrieved successfully" 
  });
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
```

## 🔐 Forgot Password & Recovery System

### Password Reset Configuration

```typescript
// config/forgot-password.ts
export const forgotPasswordConfig = {
  // Rate limiting configuration
  rateLimit: {
    maxAttempts: 3,
    windowMinutes: 15,
    cooldownMinutes: 60
  },
  
  // Verification code settings
  verificationCode: {
    length: 6,
    expirationMinutes: 15,
    numericOnly: true
  },
  
  // Security settings
  security: {
    preventPasswordReuse: true,
    requireStrongPassword: true,
    hashRounds: 12
  },
  
  // Email template settings
  emailTemplate: {
    from: process.env.FROM_EMAIL!,
    subject: 'Password Reset Code',
    template: 'forgot-password'
  }
};
```

### Complete Forgot Password Implementation

```typescript
// app/api/auth/forgot-password/route.ts
import { initiateForgotPassword } from "authrix";

export async function POST(request: Request) {
  try {
    const { email } = await request.json();
    
    if (!email) {
      return Response.json({ 
        error: { message: 'Email is required' } 
      }, { status: 400 });
    }
    
    // Initiate forgot password process
    await initiateForgotPassword(email, {
      rateLimitDelay: 60, // 1 minute between requests
      codeExpiration: 15 * 60, // 15 minutes code validity
      emailConfig: {
        from: process.env.FROM_EMAIL!,
        subject: 'Password Reset Code',
        template: 'forgot-password'
      }
    });
    
    return Response.json({ 
      message: "If an account with this email exists, a password reset code has been sent." 
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    
    // Return generic message for security
    if (error.message.includes('rate limit')) {
      return Response.json({ 
        error: { message: 'Too many requests. Please try again later.' } 
      }, { status: 429 });
    }
    
    return Response.json({ 
      error: { message: 'An error occurred. Please try again.' } 
    }, { status: 500 });
  }
}
```

```typescript
// app/api/auth/reset-password/route.ts
import { resetPasswordWithCode } from "authrix";

export async function POST(request: Request) {
  try {
    const { email, code, newPassword } = await request.json();
    
    if (!email || !code || !newPassword) {
      return Response.json({ 
        error: { message: 'Email, code, and new password are required' } 
      }, { status: 400 });
    }
    
    // Validate password strength
    if (newPassword.length < 8) {
      return Response.json({ 
        error: { message: 'Password must be at least 8 characters long' } 
      }, { status: 400 });
    }
    
    // Reset password with verification code
    const result = await resetPasswordWithCode(email, code, newPassword, {
      preventReuse: true,
      invalidateAllSessions: true
    });
    
    return Response.json({ 
      message: "Password reset successfully",
      user: {
        id: result.user.id,
        email: result.user.email,
        username: result.user.username
      }
    });
  } catch (error) {
    console.error('Reset password error:', error);
    
    if (error.message.includes('Invalid code')) {
      return Response.json({ 
        error: { message: 'Invalid or expired verification code' } 
      }, { status: 400 });
    }
    
    if (error.message.includes('User not found')) {
      return Response.json({ 
        error: { message: 'Invalid request' } 
      }, { status: 400 });
    }
    
    return Response.json({ 
      error: { message: 'An error occurred. Please try again.' } 
    }, { status: 500 });
  }
}
```

### Framework-Specific Implementations

```typescript
// Express.js Forgot Password Routes
import { nextForgotPassword, expressReset } from "authrix/frameworks";

// Initiate forgot password
app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    
    await initiateForgotPassword(email, {
      rateLimitDelay: 60,
      codeExpiration: 15 * 60,
      emailConfig: {
        from: process.env.FROM_EMAIL!,
        subject: 'Reset Your Password',
        template: 'password-reset'
      }
    });
    
    res.json({ 
      message: "Password reset instructions sent to your email" 
    });
  } catch (error) {
    if (error.message.includes('rate limit')) {
      return res.status(429).json({ 
        error: 'Too many requests. Please wait before trying again.' 
      });
    }
    res.status(500).json({ error: 'Failed to process request' });
  }
});

// Reset password with code
app.post("/reset-password", expressReset);
```

### React Forgot Password Components

```typescript
// components/ForgotPasswordForm.tsx
import { useState } from 'react';

interface ForgotPasswordFormProps {
  onSuccess?: () => void;
  onError?: (error: string) => void;
}

export function ForgotPasswordForm({ onSuccess, onError }: ForgotPasswordFormProps) {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });

      const data = await response.json();

      if (response.ok) {
        setSent(true);
        onSuccess?.();
      } else {
        onError?.(data.error?.message || 'Failed to send reset email');
      }
    } catch (error) {
      onError?.('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  if (sent) {
    return (
      <div className="forgot-password-success">
        <h3>Check Your Email</h3>
        <p>If an account with email <strong>{email}</strong> exists, we've sent password reset instructions.</p>
        <button onClick={() => setSent(false)}>Send Another Email</button>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="forgot-password-form">
      <h3>Reset Your Password</h3>
      <div className="form-group">
        <label htmlFor="email">Email Address</label>
        <input
          id="email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          placeholder="Enter your email address"
          disabled={loading}
        />
      </div>
      <button type="submit" disabled={loading || !email}>
        {loading ? 'Sending...' : 'Send Reset Instructions'}
      </button>
    </form>
  );
}

// components/ResetPasswordForm.tsx
import { useState } from 'react';

interface ResetPasswordFormProps {
  email: string;
  onSuccess?: (user: any) => void;
  onError?: (error: string) => void;
}

export function ResetPasswordForm({ email, onSuccess, onError }: ResetPasswordFormProps) {
  const [code, setCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (newPassword !== confirmPassword) {
      onError?.('Passwords do not match');
      return;
    }

    if (newPassword.length < 8) {
      onError?.('Password must be at least 8 characters long');
      return;
    }

    setLoading(true);

    try {
      const response = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code, newPassword })
      });

      const data = await response.json();

      if (response.ok) {
        onSuccess?.(data.user);
      } else {
        onError?.(data.error?.message || 'Failed to reset password');
      }
    } catch (error) {
      onError?.('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="reset-password-form">
      <h3>Reset Your Password</h3>
      <div className="form-group">
        <label htmlFor="code">Verification Code</label>
        <input
          id="code"
          type="text"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          required
          placeholder="Enter the 6-digit code"
          maxLength={6}
          disabled={loading}
        />
      </div>
      <div className="form-group">
        <label htmlFor="newPassword">New Password</label>
        <input
          id="newPassword"
          type="password"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          required
          placeholder="Enter new password"
          minLength={8}
          disabled={loading}
        />
      </div>
      <div className="form-group">
        <label htmlFor="confirmPassword">Confirm Password</label>
        <input
          id="confirmPassword"
          type="password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          required
          placeholder="Confirm new password"
          disabled={loading}
        />
      </div>
      <button type="submit" disabled={loading || !code || !newPassword || !confirmPassword}>
        {loading ? 'Resetting...' : 'Reset Password'}
      </button>
    </form>
  );
}
```

## 🔧 Next.js App Router Integration

```typescript
// app/api/auth/signup/route.ts
import { initAuth, signupNextApp } from "authrix/nextjs";
import { postgresqlAdapter } from "authrix/adapters/postgresql";

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: postgresqlAdapter,
});

export async function POST(request: Request) {
  try {
    const { email, password, username, firstName, lastName } = await request.json();
    
    const result = await signupNextApp(email, password, {
      username,
      firstName,
      lastName
    });
    
    const response = Response.json({ 
      success: true, 
      user: result.user 
    }, { status: 201 });
    
    // Set HTTP-only cookie
    response.headers.set('Set-Cookie', 
      `auth_token=${result.token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
    );
    
    return response;
  } catch (error) {
    return Response.json({ 
      success: false, 
      error: { message: error.message } 
    }, { status: 400 });
  }
}
```

```typescript
// app/api/auth/signin/route.ts
import { signinNextApp } from "authrix/nextjs";

export async function POST(request: Request) {
  try {
    const { email, password } = await request.json();
    const result = await signinNextApp(email, password);
    
    const response = Response.json({ 
      success: true, 
      user: result.user 
    });
    
    response.headers.set('Set-Cookie', 
      `auth_token=${result.token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
    );
    
    return response;
  } catch (error) {
    return Response.json({ 
      error: { message: error.message } 
    }, { status: 401 });
  }
}
```

```typescript
// app/api/auth/me/route.ts
import { getCurrentUserNextApp } from "authrix/nextjs";

export async function GET() {
  try {
    const user = await getCurrentUserNextApp();
    
    if (!user) {
      return Response.json({ 
        success: false, 
        error: { message: "Not authenticated" } 
      }, { status: 401 });
    }
    
    return Response.json({ success: true, user });
  } catch (error) {
    return Response.json({ 
      success: false, 
      error: { message: error.message } 
    }, { status: 500 });
  }
}
```

```typescript
// app/api/auth/logout/route.ts
import { logoutNextApp } from "authrix/nextjs";

export async function POST() {
  try {
    await logoutNextApp();
    
    const response = Response.json({ 
      success: true, 
      message: "Logged out successfully" 
    });
    
    // Clear the auth cookie
    response.headers.set('Set-Cookie', 
      `auth_token=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
    );
    
    return response;
  } catch (error) {
    return Response.json({ 
      success: false, 
      error: { message: error.message } 
    }, { status: 500 });
  }
}
```

### Protected Page Components

```typescript
// app/dashboard/page.tsx
import { getCurrentUserNextApp } from "authrix/nextjs";
import { redirect } from "next/navigation";

export default async function DashboardPage() {
  const user = await getCurrentUserNextApp();
  
  if (!user) {
    redirect('/login');
  }
  
  return (
    <div className="dashboard">
      <h1>Welcome to your Dashboard</h1>
      <div className="user-info">
        <h2>Hello, {user.firstName || user.username || user.email}!</h2>
        <p>Email: {user.email}</p>
        {user.username && <p>Username: {user.username}</p>}
      </div>
      
      <div className="dashboard-content">
        {/* Dashboard content here */}
      </div>
    </div>
  );
}
```

```typescript
// components/AuthButton.tsx
"use client";

import { useState, useEffect } from 'react';

interface User {
  id: string;
  email: string;
  username?: string;
}

export function useAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      const authenticated = await isAuthenticatedReact();
      setIsAuthenticated(authenticated);
      
      if (authenticated) {
        const currentUser = await getCurrentUserReact();
        setUser(currentUser);
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      setIsAuthenticated(false);
      setUser(null);
    }
  };

  const signup = async (
    email: string, 
    password: string, 
    options?: { 
      username?: string; 
      firstName?: string; 
      lastName?: string; 
    }
  ) => {
    setLoading(true);
    try {
      const result = await signupReact(email, password, options);
      setUser(result.user);
      setIsAuthenticated(true);
      return result;
    } catch (error) {
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const signin = async (email: string, password: string) => {
    setLoading(true);
    try {
      const result = await signinReact(email, password);
      setUser(result.user);
      setIsAuthenticated(true);
      return result;
    } catch (error) {
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    setLoading(true);
    try {
      await logoutReact();
      setUser(null);
      setIsAuthenticated(false);
    } catch (error) {
      console.error('Logout failed:', error);
    } finally {
      setLoading(false);
    }
  };

  return {
    user,
    loading,
    isAuthenticated,
    signup,
    signin,
    logout,
    checkAuthStatus
  };
}
```

### React Authentication Components

```typescript
// components/LoginForm.tsx
import { useState } from 'react';
import { useAuth } from '../hooks/useAuth';

interface LoginFormProps {
  onSuccess?: () => void;
  onError?: (error: string) => void;
}

export function LoginForm({ onSuccess, onError }: LoginFormProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const { signin, loading } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      await signin(email, password);
      onSuccess?.();
    } catch (error) {
      onError?.(error instanceof Error ? error.message : 'Login failed');
    }
  };

  return (
    <form onSubmit={handleSubmit} className="login-form">
      <h2>Sign In</h2>
      <div className="form-group">
        <label htmlFor="email">Email</label>
        <input
          id="email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          disabled={loading}
        />
      </div>
      <div className="form-group">
        <label htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          disabled={loading}
        />
      </div>
      <button type="submit" disabled={loading}>
        {loading ? 'Signing In...' : 'Sign In'}
      </button>
      <div className="form-links">
        <a href="/forgot-password">Forgot Password?</a>
        <a href="/signup">Don't have an account? Sign Up</a>
      </div>
    </form>
  );
}

// components/SignupForm.tsx
import { useState } from 'react';
import { useAuth } from '../hooks/useAuth';

interface SignupFormProps {
  onSuccess?: () => void;
  onError?: (error: string) => void;
}

export function SignupForm({ onSuccess, onError }: SignupFormProps) {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    username: '',
    firstName: '',
    lastName: ''
  });
  const { signup, loading } = useAuth();

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData(prev => ({
      ...prev,
      [e.target.name]: e.target.value
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (formData.password !== formData.confirmPassword) {
      onError?.('Passwords do not match');
      return;
    }

    try {
      await signup(formData.email, formData.password, {
        username: formData.username || undefined,
        firstName: formData.firstName || undefined,
        lastName: formData.lastName || undefined
      });
      onSuccess?.();
    } catch (error) {
      onError?.(error instanceof Error ? error.message : 'Signup failed');
    }
  };

  return (
    <form onSubmit={handleSubmit} className="signup-form">
      <h2>Create Account</h2>
      <div className="form-row">
        <div className="form-group">
          <label htmlFor="firstName">First Name</label>
          <input
            id="firstName"
            name="firstName"
            type="text"
            value={formData.firstName}
            onChange={handleChange}
            disabled={loading}
          />
        </div>
        <div className="form-group">
          <label htmlFor="lastName">Last Name</label>
          <input
            id="lastName"
            name="lastName"
            type="text"
            value={formData.lastName}
            onChange={handleChange}
            disabled={loading}
          />
        </div>
      </div>
      <div className="form-group">
        <label htmlFor="username">Username (optional)</label>
        <input
          id="username"
          name="username"
          type="text"
          value={formData.username}
          onChange={handleChange}
          disabled={loading}
        />
      </div>
      <div className="form-group">
        <label htmlFor="email">Email *</label>
        <input
          id="email"
          name="email"
          type="email"
          value={formData.email}
          onChange={handleChange}
          required
          disabled={loading}
        />
      </div>
      <div className="form-group">
        <label htmlFor="password">Password *</label>
        <input
          id="password"
          name="password"
          type="password"
          value={formData.password}
          onChange={handleChange}
          required
          minLength={8}
          disabled={loading}
        />
      </div>
      <div className="form-group">
        <label htmlFor="confirmPassword">Confirm Password *</label>
        <input
          id="confirmPassword"
          name="confirmPassword"
          type="password"
          value={formData.confirmPassword}
          onChange={handleChange}
          required
          disabled={loading}
        />
      </div>
      <button type="submit" disabled={loading}>
        {loading ? 'Creating Account...' : 'Create Account'}
      </button>
      <div className="form-links">
        <a href="/login">Already have an account? Sign In</a>
      </div>
    </form>
  );
}

// components/ProtectedRoute.tsx
import { useAuth } from '../hooks/useAuth';
import { useEffect, useState } from 'react';

interface ProtectedRouteProps {
  children: React.ReactNode;
  fallback?: React.ReactNode;
  redirectTo?: string;
}

export function ProtectedRoute({ 
  children, 
  fallback = <div>Loading...</div>,
  redirectTo = '/login'
}: ProtectedRouteProps) {
  const { isAuthenticated, loading } = useAuth();
  const [isChecking, setIsChecking] = useState(true);

  useEffect(() => {
    // Give auth check a moment to complete
    const timer = setTimeout(() => {
      setIsChecking(false);
    }, 100);

    return () => clearTimeout(timer);
  }, []);

  if (loading || isChecking) {
    return <>{fallback}</>;
  }

  if (!isAuthenticated) {
    window.location.href = redirectTo;
    return <>{fallback}</>;
  }

  return <>{children}</>;
}

export function AuthButton() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    try {
      const response = await fetch('/api/auth/me');
      const data = await response.json();
      
      if (data.success) {
        setUser(data.user);
      } else {
        setUser(null);
      }
    } catch (error) {
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
      setUser(null);
      window.location.href = '/';
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  if (loading) {
    return <div>Loading...</div>;
  };

  if (user) {
    return (
      <div className="auth-button">
        <span>Welcome, {user.firstName || user.username || user.email}</span>
        <button onClick={handleLogout}>Sign Out</button>
      </div>
    );
  };

  return (
    <div className="auth-button">
      <a href="/login">Sign In</a>
      <a href="/signup">Sign Up</a>
    </div>
  );
}
```

## 🗄️ Database Adapters & Configuration

### MongoDB Adapter

```typescript
// config/database.ts
import { mongoAdapter } from "authrix/adapters/mongo";

export const dbConfig = mongoAdapter({
  connectionString: process.env.MONGODB_URI!,
  options: {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    maxPoolSize: 10,
    bufferMaxEntries: 0,
  },
  collections: {
    users: 'users',
    sessions: 'sessions',
    passwordResets: 'password_resets',
    ssoProviders: 'sso_providers'
  }
});

// Initialize database
import { initAuth } from "authrix";

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: dbConfig,
  session: {
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax'
  }
});
```

### PostgreSQL Adapter

```typescript
// config/database.ts
import { postgresqlAdapter } from "authrix/adapters/postgresql";

export const dbConfig = postgresqlAdapter({
  host: process.env.DB_HOST!,
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME!,
  username: process.env.DB_USERNAME!,
  password: process.env.DB_PASSWORD!,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  tables: {
    users: 'users',
    sessions: 'sessions',
    passwordResets: 'password_resets',
    ssoProviders: 'sso_providers'
  },
  pool: {
    max: 20,
    min: 5,
    acquire: 30000,
    idle: 10000
  }
});

// Database migrations
export const runMigrations = async () => {
  try {
    await dbConfig.migrate();
    console.log('Database migrations completed successfully');
  } catch (error) {
    console.error('Migration failed:', error);
    process.exit(1);
  }
};
```

### Supabase Adapter

```typescript
// config/database.ts
import { supabaseAdapter } from "authrix/adapters/supabase";

export const dbConfig = supabaseAdapter({
  url: process.env.SUPABASE_URL!,
  anonKey: process.env.SUPABASE_ANON_KEY!,
  serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY!,
  options: {
    auth: {
      autoRefreshToken: true,
      persistSession: true,
      detectSessionInUrl: false
    },
    global: {
      headers: {
        'X-Client-Info': 'authrix-supabase-adapter'
      }
    }
  },
  tables: {
    users: 'auth_users',
    sessions: 'auth_sessions',
    passwordResets: 'auth_password_resets',
    ssoProviders: 'auth_sso_providers'
  }
});

// RLS (Row Level Security) policies
export const setupRLS = async () => {
  const { error } = await dbConfig.rpc('setup_authrix_rls');
  if (error) {
    console.error('RLS setup failed:', error);
  } else {
    console.log('RLS policies configured successfully');
  }
};
```

### Custom Database Adapter

```typescript
// adapters/custom.ts
import { DatabaseAdapter, User, Session } from "authrix/types";

export class CustomDatabaseAdapter implements DatabaseAdapter {
  private connection: any;

  constructor(connectionOptions: any) {
    this.connection = connectionOptions;
  }

  async connect(): Promise<void> {
    // Initialize your database connection
  }

  async disconnect(): Promise<void> {
    // Close database connection
  }

  async createUser(userData: {
    email: string;
    passwordHash: string;
    username?: string;
    firstName?: string;
    lastName?: string;
  }): Promise<User> {
    // Implement user creation logic
    const user = await this.connection.users.create(userData);
    return {
      id: user.id,
      email: user.email,
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      isActive: true,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    };
  }

  async getUserByEmail(email: string): Promise<User | null> {
    // Implement user retrieval by email
    const user = await this.connection.users.findByEmail(email);
    return user ? this.mapToUser(user) : null;
  }

  async getUserById(id: string): Promise<User | null> {
    // Implement user retrieval by ID
    const user = await this.connection.users.findById(id);
    return user ? this.mapToUser(user) : null;
  }

  async updateUser(id: string, updates: Partial<User>): Promise<User> {
    // Implement user update logic
    const user = await this.connection.users.update(id, updates);
    return this.mapToUser(user);
  }

  async deleteUser(id: string): Promise<void> {
    // Implement user deletion logic
    await this.connection.users.delete(id);
  }

  // Session management methods
  async createSession(session: Session): Promise<Session> {
    return await this.connection.sessions.create(session);
  }

  async getSession(sessionId: string): Promise<Session | null> {
    return await this.connection.sessions.findById(sessionId);
  }

  async deleteSession(sessionId: string): Promise<void> {
    await this.connection.sessions.delete(sessionId);
  }

  // Password reset methods
  async createPasswordReset(data: {
    email: string;
    code: string;
    expiresAt: Date;
  }): Promise<void> {
    await this.connection.passwordResets.create(data);
  }

  async getPasswordReset(email: string, code: string): Promise<any> {
    return await this.connection.passwordResets.findByEmailAndCode(email, code);
  }

  async deletePasswordReset(email: string): Promise<void> {
    await this.connection.passwordResets.deleteByEmail(email);
  }

  // SSO provider methods
  async createSSOUser(data: {
    email: string;
    provider: string;
    providerId: string;
    username?: string;
    firstName?: string;
    lastName?: string;
  }): Promise<User> {
    const user = await this.connection.users.create({
      ...data,
      isActive: true,
      isEmailVerified: true
    });
    
    await this.connection.ssoProviders.create({
      userId: user.id,
      provider: data.provider,
      providerId: data.providerId
    });
    
    return this.mapToUser(user);
  }

  async getSSOUser(provider: string, providerId: string): Promise<User | null> {
    const ssoRecord = await this.connection.ssoProviders.findByProvider(provider, providerId);
    if (!ssoRecord) return null;
    
    const user = await this.connection.users.findById(ssoRecord.userId);
    return user ? this.mapToUser(user) : null;
  }

  private mapToUser(userData: any): User {
    return {
      id: userData.id,
      email: userData.email,
      username: userData.username,
      firstName: userData.firstName,
      lastName: userData.lastName,
      isActive: userData.isActive,
      isEmailVerified: userData.isEmailVerified,
      role: userData.role,
      createdAt: userData.createdAt,
      updatedAt: userData.updatedAt
    };
  }
}

// Usage
import { initAuth } from "authrix";
import { CustomDatabaseAdapter } from "./adapters/custom";

const customDb = new CustomDatabaseAdapter({
  // Your connection options
});

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: customDb
});
```

## 🛡️ Security Features & Best Practices

### Password Security

```typescript
// config/security.ts
export const securityConfig = {
  password: {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSymbols: true,
    preventCommonPasswords: true,
    preventPasswordReuse: 5, // Last 5 passwords
    hashRounds: 12
  },
  
  session: {
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    renewalThreshold: 24 * 60 * 60 * 1000, // 24 hours
    maxConcurrentSessions: 3,
    invalidateOnPasswordChange: true
  },
  
  rateLimit: {
    loginAttempts: {
      maxAttempts: 5,
      windowMinutes: 15,
      lockoutMinutes: 30
    },
    passwordReset: {
      maxAttempts: 3,
      windowMinutes: 60,
      cooldownMinutes: 15
    },
    signupAttempts: {
      maxAttempts: 3,
      windowMinutes: 60
    }
  },
  
  jwt: {
    issuer: process.env.JWT_ISSUER || 'authrix',
    audience: process.env.JWT_AUDIENCE || 'authrix-app',
    algorithm: 'HS256',
    expiresIn: '7d'
  }
};
```

### Input Validation & Sanitization

```typescript
// utils/validation.ts
import { z } from 'zod';

export const userValidationSchemas = {
  signup: z.object({
    email: z.string()
      .email('Invalid email format')
      .max(255, 'Email too long')
      .trim()
      .toLowerCase(),
    
    password: z.string()
      .min(8, 'Password must be at least 8 characters')
      .max(128, 'Password too long')
      .regex(/[A-Z]/, 'Password must contain uppercase letter')
      .regex(/[a-z]/, 'Password must contain lowercase letter')
      .regex(/[0-9]/, 'Password must contain number')
      .regex(/[^A-Za-z0-9]/, 'Password must contain special character'),
    
    username: z.string()
      .min(3, 'Username must be at least 3 characters')
      .max(30, 'Username too long')
      .regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, hyphens, and underscores')
      .optional(),
    
    firstName: z.string()
      .min(1, 'First name is required')
      .max(50, 'First name too long')
      .regex(/^[a-zA-Z\s'-]+$/, 'First name contains invalid characters')
      .optional(),
    
    lastName: z.string()
      .min(1, 'Last name is required')
      .max(50, 'Last name too long')
      .regex(/^[a-zA-Z\s'-]+$/, 'Last name contains invalid characters')
      .optional()
  }),
  
  signin: z.object({
    email: z.string().email('Invalid email format').trim().toLowerCase(),
    password: z.string().min(1, 'Password is required')
  }),
  
  forgotPassword: z.object({
    email: z.string().email('Invalid email format').trim().toLowerCase()
  }),
  
  resetPassword: z.object({
    email: z.string().email('Invalid email format').trim().toLowerCase(),
    code: z.string().length(6, 'Code must be 6 digits').regex(/^[0-9]+$/, 'Code must be numeric'),
    newPassword: z.string()
      .min(8, 'Password must be at least 8 characters')
      .max(128, 'Password too long')
  })
};

// Validation middleware
export const validateInput = (schema: z.ZodSchema) => {
  return (req: any, res: any, next: any) => {
    try {
      const validated = schema.parse(req.body);
      req.body = validated;
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: {
            message: 'Validation failed',
            details: error.errors.map(err => ({
              field: err.path.join('.'),
              message: err.message
            }))
          }
        });
      }
      next(error);
    }
  };
};

// Usage in Express routes
import { validateInput, userValidationSchemas } from './utils/validation';

app.post('/api/auth/signup', 
  validateInput(userValidationSchemas.signup),
  async (req, res) => {
    // Request body is now validated and sanitized
    const { email, password, username, firstName, lastName } = req.body;
    // ... signup logic
  }
);
```

### CSRF Protection

```typescript
// middleware/csrf.ts
import { createHash, randomBytes } from 'crypto';

export const csrfProtection = {
  generateToken: (): string => {
    return randomBytes(32).toString('hex');
  },
  
  verifyToken: (token: string, sessionToken: string): boolean => {
    if (!token || !sessionToken) return false;
    return token === sessionToken;
  },
  
  middleware: (req: any, res: any, next: any) => {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
      return next();
    }
    
    const token = req.headers['x-csrf-token'] || req.body._csrf;
    const sessionToken = req.session?.csrfToken;
    
    if (!csrfProtection.verifyToken(token, sessionToken)) {
      return res.status(403).json({
        error: { message: 'Invalid CSRF token' }
      });
    }
    
    next();
  }
};

// Next.js CSRF implementation
// app/api/csrf/route.ts
export async function GET() {
  const token = csrfProtection.generateToken();
  
  const response = Response.json({ csrfToken: token });
  response.headers.set('Set-Cookie', 
    `csrf_token=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600`
  );
  
  return response;
}
```
```

## 🚀 React SPA Integration

```typescript
// hooks/useAuth.tsx
import { useState, useEffect } from 'react';
import { 
  signupReact, 
  signinReact, 
  logoutReact, 
  getCurrentUserReact,
  isAuthenticatedReact 
} from "authrix/react";

interface User {
  id: string;
  email: string;
  username?: string;
  firstName?: string;
  lastName?: string;
}

export function useAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      const currentUser = await getCurrentUserReact();
      setUser(currentUser);
      setIsAuthenticated(!!currentUser);
    } catch (error) {
      console.error('Auth check failed:', error);
      setUser(null);
      setIsAuthenticated(false);
    } finally {
      setLoading(false);
    }
  };

  const signup = async (userData: {
    email: string;
    password: string;
    username?: string;
    firstName?: string;
    lastName?: string;
  }) => {
    try {
      const result = await signupReact(
        userData.email, 
        userData.password,
        '/api/auth/signup'
      );
      setUser(result.user);
      setIsAuthenticated(true);
      return result;
    } catch (error) {
      throw error;
    }
  };

  const signin = async (email: string, password: string) => {
    try {
      const result = await signinReact(email, password, '/api/auth/signin');
      setUser(result.user);
      setIsAuthenticated(true);
      return result;
    } catch (error) {
      throw error;
    }
  };

  const logout = async () => {
    try {
      await logoutReact('/api/auth/logout');
      setUser(null);
      setIsAuthenticated(false);
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  return {
    user,
    loading,
    isAuthenticated,
    signup,
    signin,
    logout,
    checkAuthStatus
  };
}
```

```typescript
// components/AuthForm.tsx
import React, { useState } from 'react';
import { useAuth } from '../hooks/useAuth';

export function AuthForm() {
  const { signup, signin, isAuthenticated, user } = useAuth();
  const [isSignup, setIsSignup] = useState(false);
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    username: '',
    firstName: '',
    lastName: ''
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      if (isSignup) {
        await signup(formData);
      } else {
        await signin(formData.email, formData.password);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  if (isAuthenticated) {
    return (
      <div className="auth-success">
        <h2>Welcome, {user?.firstName || user?.email}!</h2>
        <p>You are successfully authenticated.</p>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="auth-form">
      <h2>{isSignup ? 'Sign Up' : 'Sign In'}</h2>
      
      {error && <div className="error">{error}</div>}
      
      <input
        type="email"
        placeholder="Email"
        value={formData.email}
        onChange={(e) => setFormData({...formData, email: e.target.value})}
        required
      />
      
      <input
        type="password"
        placeholder="Password"
        value={formData.password}
        onChange={(e) => setFormData({...formData, password: e.target.value})}
        required
      />
      
      {isSignup && (
        <>
          <input
            type="text"
            placeholder="Username (optional)"
            value={formData.username}
            onChange={(e) => setFormData({...formData, username: e.target.value})}
          />
          <input
            type="text"
            placeholder="First Name (optional)"
            value={formData.firstName}
            onChange={(e) => setFormData({...formData, firstName: e.target.value})}
          />
          <input
            type="text"
            placeholder="Last Name (optional)"
            value={formData.lastName}
            onChange={(e) => setFormData({...formData, lastName: e.target.value})}
          />
        </>
      )}
      
      <button type="submit" disabled={loading}>
        {loading ? 'Loading...' : (isSignup ? 'Sign Up' : 'Sign In')}
      </button>
      
      <button 
        type="button" 
        onClick={() => setIsSignup(!isSignup)}
        className="link-button"
      >
        {isSignup ? 'Already have an account? Sign In' : 'Need an account? Sign Up'}
      </button>
    </form>
  );
}
```

## 🔑 Complete SSO & OAuth Implementation

### OAuth Provider Configuration

```typescript
// config/oauth.ts
export const oAuthConfig = {
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    redirectUri: `${process.env.BASE_URL}/api/auth/google/callback`,
    scope: 'openid profile email'
  },
  github: {
    clientId: process.env.GITHUB_CLIENT_ID!,
    clientSecret: process.env.GITHUB_CLIENT_SECRET!,
    redirectUri: `${process.env.BASE_URL}/api/auth/github/callback`,
    scope: 'read:user user:email'
  }
};
```

### SSO Authentication Flow

```typescript
// app/api/auth/[provider]/route.ts
import { getGoogleOAuthURL, getGitHubOAuthURL } from "authrix/oauth";
import { generateSSOState } from "authrix";

export async function GET(
  request: Request,
  { params }: { params: { provider: string } }
) {
  try {
    const { provider } = params;
    const url = new URL(request.url);
    const redirectUrl = url.searchParams.get('redirect') || '/dashboard';
    
    // Generate secure state parameter
    const state = generateSSOState({
      provider,
      redirectUrl,
      timestamp: Date.now()
    });
    
    let authUrl: string;
    
    switch (provider) {
      case 'google':
        authUrl = getGoogleOAuthURL(state);
        break;
      case 'github':
        authUrl = getGitHubOAuthURL(state);
        break;
      default:
        return Response.json({ 
          error: { message: 'Unsupported provider' } 
        }, { status: 400 });
    }
    
    return Response.redirect(authUrl);
  } catch (error) {
    return Response.json({ 
      error: { message: error.message } 
    }, { status: 500 });
  }
}
```

```typescript
// app/api/auth/[provider]/callback/route.ts
import { processSSOAuthentication, verifySSOState } from "authrix";

export async function GET(
  request: Request,
  { params }: { params: { provider: string } }
) {
  try {
    const { provider } = params;
    const url = new URL(request.url);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    const error = url.searchParams.get('error');
    
    // Handle OAuth errors
    if (error) {
      return Response.redirect(`/auth/error?message=${encodeURIComponent(error)}`);
    }
    
    if (!code || !state) {
      return Response.redirect('/auth/error?message=Missing_parameters');
    }
    
    // Verify state parameter
    const stateData = verifySSOState(state);
    if (!stateData || stateData.provider !== provider) {
      return Response.redirect('/auth/error?message=Invalid_state');
    }
    
    // Process SSO authentication
    const result = await processSSOAuthentication(provider, code, state);
    
    // Create response with redirect
    const redirectUrl = stateData.redirectUrl || '/dashboard';
    const response = Response.redirect(redirectUrl);
    
    // Set authentication cookie
    response.headers.set('Set-Cookie',
      `auth_token=${result.token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
    );
    
    return response;
  } catch (error) {
    console.error('SSO callback error:', error);
    return Response.redirect(`/auth/error?message=${encodeURIComponent(error.message)}`);
  }
}
```

### Framework-Specific SSO Helpers

```typescript
// Express.js SSO Implementation
import { expressSSO, getGoogleOAuthURL, getGitHubOAuthURL } from "authrix/frameworks";

app.get("/auth/:provider", (req, res) => {
  const { provider } = req.params;
  const redirectUrl = req.query.redirect || '/dashboard';
  
  try {
    let authUrl: string;
    const state = generateSSOState({ provider, redirectUrl });
    
    switch (provider) {
      case 'google':
        authUrl = getGoogleOAuthURL(state);
        break;
      case 'github':
        authUrl = getGitHubOAuthURL(state);
        break;
      default:
        return res.status(400).json({ error: 'Unsupported provider' });
    }
    
    res.redirect(authUrl);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Use the built-in Express SSO handler
app.get("/auth/:provider/callback", expressSSO);
```

### React SSO Integration

```typescript
// hooks/useSSO.tsx
import { useState } from 'react';

export function useSSO() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const initiateSSO = async (provider: 'google' | 'github', redirectUrl = '/dashboard') => {
    setLoading(true);
    setError(null);
    
    try {
      // Redirect to SSO endpoint
      window.location.href = `/api/auth/${provider}?redirect=${encodeURIComponent(redirectUrl)}`;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'SSO initiation failed');
      setLoading(false);
    }
  };

  return { initiateSSO, loading, error };
}

// components/SSOButtons.tsx
import { useSSO } from '../hooks/useSSO';

export function SSOButtons() {
  const { initiateSSO, loading, error } = useSSO();

  return (
    <div className="sso-buttons">
      <h3>Sign in with:</h3>
      
      {error && <div className="error">{error}</div>}
      
      <button
        onClick={() => initiateSSO('google')}
        disabled={loading}
        className="sso-button google"
      >
        <GoogleIcon />
        Continue with Google
      </button>
      
      <button
        onClick={() => initiateSSO('github')}
        disabled={loading}
        className="sso-button github"
      >
        <GitHubIcon />
        Continue with GitHub
      </button>
      
      {loading && <div className="loading">Redirecting...</div>}
    </div>
  );
}
```

## � Latest Features

### Complete SSO Integration
- **Automatic user management**: Creates or updates users during SSO login
- **State verification**: Secure OAuth state parameter validation
- **Multiple providers**: Google and GitHub with extensible architecture
- **Framework integration**: Ready-to-use handlers for Next.js, Express, and React

### Forgot Password System
- **Verification codes**: Secure 6-digit codes with expiration
- **Rate limiting**: Prevents abuse with configurable delays
- **Email delivery**: Integrates with existing email providers
- **Password validation**: Prevents reuse of current passwords

### Enhanced User Profiles
- **Username support**: Unique usernames with automatic normalization
- **Name fields**: Optional first name and last name
- **Database migration**: Backwards compatible with existing databases
- **Flexible updates**: Partial profile updates supported

## �🏗️ Architecture

### Database Adapters

Authrix uses a simple adapter pattern for database integration:

```typescript
interface AuthDbAdapter {
  findUserByEmail(email: string): Promise<AuthUser | null>;
  findUserById(id: string): Promise<AuthUser | null>;
  findUserByUsername(username: string): Promise<AuthUser | null>;
  createUser(data: CreateUserData): Promise<AuthUser>;
  updateUser(id: string, data: Partial<AuthUser>): Promise<AuthUser>;
}

interface AuthUser {
  id: string;
  email: string;
  password: string;
  username?: string;
  firstName?: string;
  lastName?: string;
  createdAt?: Date;
  [key: string]: any; // Additional user fields
}

interface CreateUserData {
  email: string;
  password: string;
  username?: string;
  firstName?: string;
  lastName?: string;
}
```

### Available Adapters

```typescript
// MongoDB
import { mongoAdapter } from "authrix/adapters/mongo";

// PostgreSQL
import { postgresqlAdapter, initializePostgreSQLTables } from "authrix/adapters/postgresql";

// Custom adapter
const customAdapter: AuthDbAdapter = {
  async findUserByEmail(email) { /* your implementation */ },
  async findUserById(id) { /* your implementation */ },
  async findUserByUsername(username) { /* your implementation */ },
  async createUser(data) { /* your implementation */ },
  async updateUser(id, data) { /* your implementation */ },
};
```

## 🔐 Security Features

### Password Hashing
- **bcryptjs** for secure password hashing
- Configurable salt rounds (default: 12)
- Automatic password validation

### JWT Tokens
- **jsonwebtoken** for secure token generation
- Configurable expiration (default: 7 days)
- Automatic signature verification

### Cookie Security
- **HttpOnly** flags prevent XSS attacks
- **Secure** flag in production
- **SameSite** protection against CSRF
- Automatic cookie clearing on logout

### Input Validation
- Email format validation
- Password strength requirements  
- Automatic sanitization

## 🛠️ Framework Support

### Modular Imports

```typescript
// Core (7.8 kB) - Essential authentication
import { initAuth, signup, signin } from "authrix";

// SSO & Password Reset (+12.4 kB)
import { processSSOAuthentication, initiateForgotPassword, resetPasswordWithCode } from "authrix";

// Next.js support (+9.8 kB)
import { signupNextApp, getCurrentUserNextApp } from "authrix/nextjs";

// React support (+3.6 kB)
import { signupReact, getCurrentUserReact } from "authrix/react";

// OAuth providers (+7.8 kB)
import { getGoogleOAuthURL, handleGoogleCallback } from "authrix/oauth";

// Universal/Framework-agnostic
import { signupUniversal, validateAuth } from "authrix/universal";
```

### Next.js Edge Runtime

```typescript
// middleware.ts - Edge Runtime Compatible
import { checkAuthMiddleware } from 'authrix/nextjs';

export async function middleware(request: NextRequest) {
  const auth = await checkAuthMiddleware(request);
  
  if (!auth.isAuthenticated && request.nextUrl.pathname.startsWith('/dashboard')) {
    return NextResponse.redirect(new URL('/login', request.url));
  }
}
```

## 🔑 SSO & OAuth Integration

### Complete SSO Flow

```typescript
import { processSSOAuthentication, getGoogleOAuthURL, getGitHubOAuthURL } from "authrix";

// Generate OAuth URLs
const googleAuthUrl = getGoogleOAuthURL("random-state-string");
const githubAuthUrl = getGitHubOAuthURL("random-state-string");

// Handle OAuth callback (works for both Google and GitHub)
app.get("/auth/:provider/callback", async (req, res) => {
  try {
    const { provider } = req.params;
    const { code, state } = req.query;
    
    const result = await processSSOAuthentication(provider, code, state, res);
    
    if (result.isNewUser) {
      // First time login - redirect to profile setup
      res.redirect(`/onboarding?welcome=${result.user.email}`);
    } else {
      // Existing user - redirect to dashboard
      res.redirect('/dashboard');
    }
  } catch (error) {
    res.redirect(`/login?error=${encodeURIComponent(error.message)}`);
  }
});
```

### Framework-Specific SSO Integration

```typescript
// Next.js App Router SSO
import { nextSSO } from "authrix/frameworks";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const provider = url.searchParams.get('provider');
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  
  return await nextSSO(provider, code, state);
}

// Express.js SSO
import { expressSSO } from "authrix/frameworks";

app.get("/auth/:provider/callback", expressSSO);
```

## 📚 API Reference

### Core Functions

#### `initAuth(config)`
Initialize Authrix with your configuration.

```typescript
initAuth({
  jwtSecret: string;      // Required: JWT signing secret
  db: AuthDbAdapter;      // Required: Database adapter
  cookieName?: string;    // Optional: Cookie name (default: "auth_token")
});
```

#### `signup(email, password, res?, options?)`
Register a new user with optional profile data.

```typescript
const user = await signup("user@example.com", "password123", res, {
  username: "johndoe",
  firstName: "John",
  lastName: "Doe"
});
// Returns: { id: string, email: string, username?: string, firstName?: string, lastName?: string }
```

#### `signin(email, password, res?)`
Authenticate an existing user.

```typescript
const user = await signin("user@example.com", "password123", res);
// Returns: { id: string, email: string }
```

#### `getCurrentUser(req)`
Get the current authenticated user from request.

```typescript
const user = await getCurrentUser(req);
// Returns: { id: string, email: string, username?: string, firstName?: string, lastName?: string, createdAt?: Date } | null
```

### SSO Functions

#### `processSSOAuthentication(provider, code, state, res?)`
Complete SSO authentication flow for Google or GitHub.

```typescript
const result = await processSSOAuthentication("google", code, state, res);
// Returns: { user: AuthUser, isNewUser: boolean, provider: string }
```

#### `initiateForgotPassword(email, options?)`
Start the forgot password process.

```typescript
await initiateForgotPassword("user@example.com", {
  rateLimitDelay: 60,     // Seconds between requests
  codeExpiration: 900,    // Code validity in seconds
  emailTemplate: "custom" // Custom email template
});
```

#### `resetPasswordWithCode(email, code, newPassword, options?)`
Reset password using verification code.

```typescript
const result = await resetPasswordWithCode(
  "user@example.com", 
  "123456", 
  "NewPassword123!",
  { preventReuse: true }
);
// Returns: { user: AuthUser, message: string }
```

### Middleware

#### `authMiddleware`
Express.js middleware for route protection.

```typescript
app.get("/protected", authMiddleware, (req, res) => {
  // req.user is automatically available
  res.json({ user: req.user });
});
```

#### `createAuthMiddleware(options)`
Flexible middleware for any framework.

```typescript
const middleware = createAuthMiddleware({
  required: true,                    // Throw error if not authenticated
  tokenExtractor: (req) => string,   // Custom token extraction
  errorHandler: (error, req, res) => void  // Custom error handling
});
```

### Framework-Specific Functions

#### Next.js App Router
- `signupNextApp(email, password, options?)`
- `signinNextApp(email, password)`
- `getCurrentUserNextApp()`
- `checkAuthMiddleware(request)`
- `nextSSO(provider, code, state)` - SSO handler
- `nextForgotPassword(email, options?)` - Forgot password handler

#### Next.js Pages Router
- `signupNextPages(email, password, res, options?)`
- `signinNextPages(email, password, res)`
- `getCurrentUserNextPages(req)`
- `withAuth(handler)` - HOC for API routes

#### React
- `signupReact(email, password, options?)`
- `signinReact(email, password)`
- `getCurrentUserReact()`
- `logoutReact()`

## 🧪 Testing

Authrix includes comprehensive test coverage:

```bash
# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

## 📖 Documentation

- [📧 2FA Email Verification Guide](./docs/2FA_EMAIL_GUIDE.md)
- [🔑 SSO & Forgot Password Guide](./docs/SSO_FORGOT_PASSWORD_GUIDE.md)
- [🏗️ Framework Usage Examples](./docs/FRAMEWORK_USAGE.md)
- [🔐 OAuth Usage Guide](./docs/OAUTH_USAGE.md)
- [⚡ Edge Runtime Guide](./docs/EDGE_RUNTIME_GUIDE.md)
- [🚀 Next.js Production Guide](./docs/NEXTJS_PRODUCTION_GUIDE.md)
- [📦 Bundle Optimization](./docs/BUNDLE_OPTIMIZATION.md)
- [🗄️ PostgreSQL Adapter Guide](./docs/POSTGRESQL_ADAPTER_GUIDE.md)
- [👤 User Profile Enhancement](./docs/USER_PROFILE_ENHANCEMENT_SUMMARY.md)
- [🔧 Complete Integration Examples](./docs/COMPLETE_INTEGRATION_EXAMPLE.md)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](./docs/CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/Grenish/authrix.git
cd authrix

# Install dependencies
npm install

# Run tests
npm test

# Build the project
npm run build
```

### Adapter Development

Need support for a new database? Create a custom adapter:

```typescript
import type { AuthDbAdapter } from "authrix";

export const yourDbAdapter: AuthDbAdapter = {
  async findUserByEmail(email: string) {
    // Implementation for your database
  },
  async findUserById(id: string) {
    // Implementation for your database
  },
  async findUserByUsername(username: string) {
    // Implementation for your database
  },
  async createUser(data: CreateUserData) {
    // Implementation for your database
  },
  async updateUser(id: string, data: Partial<AuthUser>) {
    // Implementation for your database
  },
};
```

## � Testing & Quality Assurance

### Unit Tests

```typescript
// __tests__/auth.test.ts
import { signup, signin, getCurrentUser } from "authrix";
import { testDatabaseAdapter } from "authrix/testing";

describe('Authrix Authentication', () => {
  beforeEach(async () => {
    await testDatabaseAdapter.reset();
  });

  describe('User Registration', () => {
    it('should create a new user with valid data', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'SecurePass123!',
        username: 'testuser',
        firstName: 'Test',
        lastName: 'User'
      };

      const result = await signup(userData.email, userData.password, {
        username: userData.username,
        firstName: userData.firstName,
        lastName: userData.lastName
      });

      expect(result.user).toBeDefined();
      expect(result.user.email).toBe(userData.email);
      expect(result.user.username).toBe(userData.username);
      expect(result.token).toBeDefined();
    });

    it('should reject duplicate email addresses', async () => {
      const email = 'duplicate@example.com';
      const password = 'SecurePass123!';

      await signup(email, password);

      await expect(signup(email, password))
        .rejects
        .toThrow('User with this email already exists');
    });

    it('should validate password strength', async () => {
      await expect(signup('test@example.com', 'weak'))
        .rejects
        .toThrow('Password must be at least 8 characters');
    });
  });

  describe('User Authentication', () => {
    it('should authenticate with correct credentials', async () => {
      const email = 'auth@example.com';
      const password = 'SecurePass123!';

      await signup(email, password);
      const result = await signin(email, password);

      expect(result.user).toBeDefined();
      expect(result.user.email).toBe(email);
      expect(result.token).toBeDefined();
    });

    it('should reject invalid credentials', async () => {
      await expect(signin('nonexistent@example.com', 'password'))
        .rejects
        .toThrow('Invalid credentials');
    });
  });
});
```

### Integration Tests

```typescript
// __tests__/integration/sso.test.ts
import request from 'supertest';
import app from '../../src/app';

describe('SSO Integration', () => {
  describe('Google OAuth', () => {
    it('should redirect to Google OAuth URL', async () => {
      const response = await request(app)
        .get('/api/auth/google')
        .expect(302);

      expect(response.headers.location).toContain('accounts.google.com');
      expect(response.headers.location).toContain('client_id');
      expect(response.headers.location).toContain('state');
    });
  });

  describe('Forgot Password', () => {
    it('should initiate password reset process', async () => {
      // First create a user
      await request(app)
        .post('/api/auth/signup')
        .send({
          email: 'reset@example.com',
          password: 'SecurePass123!'
        })
        .expect(201);

      // Request password reset
      const response = await request(app)
        .post('/api/auth/forgot-password')
        .send({ email: 'reset@example.com' })
        .expect(200);

      expect(response.body.message).toContain('password reset code');
    });

    it('should reset password with valid code', async () => {
      // Implementation depends on your test setup
      // This would involve mocking email service and database
    });
  });
});
```

### Load Testing

```javascript
// load-tests/auth-load.js
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

export let errorRate = new Rate('errors');

export let options = {
  stages: [
    { duration: '2m', target: 100 }, // Ramp up
    { duration: '5m', target: 500 }, // Stay at 500 users
    { duration: '2m', target: 0 },   // Ramp down
  ],
  thresholds: {
    errors: ['rate<0.1'], // Error rate should be less than 10%
    http_req_duration: ['p(95)<2000'], // 95% of requests should be below 2s
  },
};

export default function() {
  // Test signup endpoint
  let signupResponse = http.post('http://localhost:3000/api/auth/signup', {
    email: `user${Math.random()}@example.com`,
    password: 'TestPass123!',
    username: `user${Math.random()}`
  }, {
    headers: { 'Content-Type': 'application/json' },
  });

  check(signupResponse, {
    'signup status is 201': (r) => r.status === 201,
    'signup response time < 2s': (r) => r.timings.duration < 2000,
  }) || errorRate.add(1);

  sleep(1);

  // Test signin endpoint
  let signinResponse = http.post('http://localhost:3000/api/auth/signin', {
    email: 'test@example.com',
    password: 'TestPass123!'
  }, {
    headers: { 'Content-Type': 'application/json' },
  });

  check(signinResponse, {
    'signin status is 200': (r) => r.status === 200,
    'signin response time < 2s': (r) => r.timings.duration < 2000,
  }) || errorRate.add(1);

  sleep(1);
}
```

## 🚀 Production Deployment

### Environment Configuration

```bash
# .env.production
NODE_ENV=production

# Database
DATABASE_URL=postgresql://username:password@host:port/database
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/database

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-minimum-32-characters
JWT_ISSUER=your-app-name
JWT_AUDIENCE=your-app-users

# OAuth Providers
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Email Service
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASS=your-sendgrid-api-key
FROM_EMAIL=noreply@yourdomain.com

# Security
BCRYPT_ROUNDS=12
SESSION_SECRET=your-session-secret-key
CSRF_SECRET=your-csrf-secret-key

# Rate Limiting
REDIS_URL=redis://localhost:6379

# Monitoring
SENTRY_DSN=your-sentry-dsn
LOG_LEVEL=info
```

### Docker Configuration

```dockerfile
# Dockerfile
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

FROM node:18-alpine AS runner

WORKDIR /app

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

USER nextjs

EXPOSE 3000

ENV PORT 3000
ENV NODE_ENV production

CMD ["npm", "start"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgresql://postgres:password@db:5432/authrix
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
    restart: unless-stopped

  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: authrix
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - app
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
```

### Kubernetes Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authrix-app
  labels:
    app: authrix
spec:
  replicas: 3
  selector:
    matchLabels:
      app: authrix
  template:
    metadata:
      labels:
        app: authrix
    spec:
      containers:
      - name: authrix
        image: your-registry/authrix:latest
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: "production"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: authrix-secrets
              key: database-url
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: authrix-secrets
              key: jwt-secret
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"

---
apiVersion: v1
kind: Service
metadata:
  name: authrix-service
spec:
  selector:
    app: authrix
  ports:
    - protocol: TCP
      port: 80
      targetPort: 3000
  type: LoadBalancer
```

### Monitoring & Observability

```typescript
// monitoring/metrics.ts
import { createPrometheusMetrics } from 'prom-client';

export const authMetrics = {
  loginAttempts: new Counter({
    name: 'authrix_login_attempts_total',
    help: 'Total number of login attempts',
    labelNames: ['status', 'method']
  }),
  
  signupAttempts: new Counter({
    name: 'authrix_signup_attempts_total',
    help: 'Total number of signup attempts',
    labelNames: ['status']
  }),
  
  activeUsers: new Gauge({
    name: 'authrix_active_users',
    help: 'Number of currently active users'
  }),
  
  authLatency: new Histogram({
    name: 'authrix_auth_duration_seconds',
    help: 'Authentication operation duration',
    labelNames: ['operation']
  })
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    version: process.env.npm_package_version
  });
});

// Readiness check
app.get('/ready', async (req, res) => {
  try {
    // Check database connection
    await dbAdapter.ping();
    
    // Check Redis connection (if using)
    await redisClient.ping();
    
    res.json({ status: 'ready' });
  } catch (error) {
    res.status(503).json({ 
      status: 'not ready',
      error: error.message
    });
  }
});
```

## �🐛 Issues & Support

- 🐛 [Report bugs](https://github.com/Grenish/authrix/issues/new?template=bug_report.md)
- 💡 [Request features](https://github.com/Grenish/authrix/issues/new?template=feature_request.md)
- ❓ [Ask questions](https://github.com/Grenish/authrix/discussions)
- 📖 [Documentation](https://authrix.dev/docs)
- 💬 [Discord Community](https://discord.gg/authrix)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](./CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/Grenish/authrix.git
cd authrix

# Install dependencies
npm install

# Set up environment
cp .env.example .env.local

# Run tests
npm test

# Start development server
npm run dev
```

### Code Standards

- **TypeScript**: Full type safety required
- **Testing**: Minimum 90% code coverage
- **Linting**: ESLint + Prettier configuration
- **Security**: All inputs validated and sanitized
- **Documentation**: JSDoc comments for all public APIs

## 📄 License

MIT License - see [LICENSE](./LICENSE) for details.

Copyright (c) 2025 [Grenish Rai](https://github.com/Grenish)

---

**Authrix** - Enterprise-grade authentication for modern applications.

[![npm](https://img.shields.io/npm/v/authrix)](https://www.npmjs.com/package/authrix)
[![downloads](https://img.shields.io/npm/dm/authrix)](https://www.npmjs.com/package/authrix)
[![license](https://img.shields.io/npm/l/authrix)](./LICENSE)
[![build](https://img.shields.io/github/workflow/status/Grenish/authrix/CI)](https://github.com/Grenish/authrix/actions)
[![coverage](https://img.shields.io/codecov/c/github/Grenish/authrix)](https://codecov.io/gh/Grenish/authrix)