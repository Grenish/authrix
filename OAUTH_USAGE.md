# OAuth Usage Guide

> **Important:** OAuth functionality has been separated from the core Authrix package to prevent environment variable validation errors when OAuth is not being used.

## Table of Contents

- [Overview](#overview)
- [Setup](#setup)
- [Environment Variables](#environment-variables)
- [Import Methods](#import-methods)
- [Google OAuth](#google-oauth)
- [GitHub OAuth](#github-oauth)
- [Framework Examples](#framework-examples)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

Authrix provides built-in support for OAuth authentication with popular providers like Google and GitHub. OAuth functions are exported separately to avoid requiring environment variables when OAuth features are not being used.

## Setup

### Google OAuth Setup

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API
4. Create credentials (OAuth 2.0 Client ID)
5. Add your redirect URIs:
   - Development: `http://localhost:3000/auth/google/callback`
   - Production: `https://yourdomain.com/auth/google/callback`

### GitHub OAuth Setup

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in the application details:
   - Application name: Your app name
   - Homepage URL: Your app URL
   - Authorization callback URL: `https://yourdomain.com/auth/github/callback`

## Environment Variables

Create a `.env` file in your project root:

```env
# Required for core authentication
JWT_SECRET=your-super-secret-jwt-key-here

# Google OAuth (optional - only needed if using Google OAuth)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# GitHub OAuth (optional - only needed if using GitHub OAuth)
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Database connection
MONGODB_URI=mongodb://localhost:27017/myapp
# OR
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key
```

## Import Methods

### Method 1: Import from the oauth module (Recommended)

```typescript
import { getGoogleOAuthURL, handleGoogleCallback, getGitHubOAuthURL, handleGitHubCallback } from 'authrix/oauth';
```

### Method 2: Import individual providers

```typescript
import { getGoogleOAuthURL, handleGoogleCallback } from 'authrix/providers/google';
import { getGitHubOAuthURL, handleGitHubCallback } from 'authrix/providers/github';
```

### Method 3: Import specific functions

```typescript
import { getGoogleOAuthURL } from 'authrix/providers/google';
import { getGitHubOAuthURL } from 'authrix/providers/github';
```

## Google OAuth

### Basic Usage

```typescript
import { getGoogleOAuthURL, handleGoogleCallback } from 'authrix/oauth';

// Generate OAuth URL
const state = crypto.randomUUID(); // Use a secure random string
const authUrl = getGoogleOAuthURL(state);

// Handle callback
const oauthUser = await handleGoogleCallback(code);
```

### API Reference

#### `getGoogleOAuthURL(state: string): string`

Generates a Google OAuth authorization URL.

**Parameters:**
- `state` (string): A random string to prevent CSRF attacks

**Returns:** Authorization URL string

**Example:**
```typescript
const state = crypto.randomUUID();
const url = getGoogleOAuthURL(state);
// Returns: https://accounts.google.com/oauth/authorize?client_id=...
```

#### `handleGoogleCallback(code: string): Promise<GoogleUser>`

Exchanges authorization code for user information.

**Parameters:**
- `code` (string): Authorization code from OAuth callback

**Returns:** Promise resolving to user object:
```typescript
interface GoogleUser {
  id: string;
  email: string;
  name?: string;
  picture?: string;
  verified_email?: boolean;
}
```

**Example:**
```typescript
const user = await handleGoogleCallback(authCode);
// user = { id: "123", email: "user@gmail.com", name: "John Doe", ... }
```

## GitHub OAuth

### Basic Usage

```typescript
import { getGitHubOAuthURL, handleGitHubCallback } from 'authrix/oauth';

// Generate OAuth URL
const state = crypto.randomUUID();
const authUrl = getGitHubOAuthURL(state);

// Handle callback
const oauthUser = await handleGitHubCallback(code);
```

### API Reference

#### `getGitHubOAuthURL(state: string): string`

Generates a GitHub OAuth authorization URL.

**Parameters:**
- `state` (string): A random string to prevent CSRF attacks

**Returns:** Authorization URL string

#### `handleGitHubCallback(code: string): Promise<GitHubUser>`

Exchanges authorization code for user information.

**Parameters:**
- `code` (string): Authorization code from OAuth callback

**Returns:** Promise resolving to user object:
```typescript
interface GitHubUser {
  id: number;
  login: string;
  email: string;
  name?: string;
  avatar_url?: string;
  bio?: string;
}
```

## Framework Examples

### Next.js App Router

#### OAuth Initiation Route

```typescript
// app/auth/google/route.ts
import { getGoogleOAuthURL } from 'authrix/oauth';

export async function GET() {
  try {
    const state = crypto.randomUUID();
    const url = getGoogleOAuthURL(state);
    
    // Store state in session or database for validation
    // For simplicity, we'll skip state validation in this example
    
    return Response.redirect(url);
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
}
```

#### OAuth Callback Route

```typescript
// app/auth/google/callback/route.ts
import { handleGoogleCallback } from 'authrix/oauth';
import { initAuth, signupCore, signinCore } from 'authrix';
import { mongoAdapter } from 'authrix/adapters/mongo';

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter,
});

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const code = searchParams.get('code');
  const state = searchParams.get('state');
  
  if (!code) {
    return Response.json({ error: 'No code provided' }, { status: 400 });
  }
  
  try {
    // Get user info from Google
    const oauthUser = await handleGoogleCallback(code);
    
    // Check if user exists in your database
    let user = await mongoAdapter.findUserByEmail(oauthUser.email);
    
    if (!user) {
      // Create new user (you might want to generate a random password)
      user = await signupCore(oauthUser.email, crypto.randomUUID());
    }
    
    // Generate JWT token and set cookie
    const token = createToken({ id: user.id, email: user.email });
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax' as const,
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    };
    
    const response = Response.redirect(new URL('/dashboard', request.url));
    response.headers.set('Set-Cookie', `auth_token=${token}; ${Object.entries(cookieOptions).map(([k, v]) => `${k}=${v}`).join('; ')}`);
    
    return response;
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
}
```

#### Complete OAuth Implementation

```typescript
// app/auth/oauth-handler.ts
import { handleGoogleCallback, handleGitHubCallback } from 'authrix/oauth';
import { createToken } from 'authrix/tokens';
import { mongoAdapter } from 'authrix/adapters/mongo';

export async function handleOAuthCallback(
  provider: 'google' | 'github',
  code: string,
  request: Request
) {
  try {
    // Get user info from OAuth provider
    const oauthUser = provider === 'google' 
      ? await handleGoogleCallback(code)
      : await handleGitHubCallback(code);
    
    const email = oauthUser.email;
    if (!email) {
      throw new Error('No email provided by OAuth provider');
    }
    
    // Check if user exists
    let user = await mongoAdapter.findUserByEmail(email);
    
    if (!user) {
      // Create new user with OAuth data
      user = await mongoAdapter.createUser({
        email,
        password: crypto.randomUUID(), // Random password for OAuth users
        oauthProvider: provider,
        oauthId: oauthUser.id.toString(),
        name: oauthUser.name,
        avatar: provider === 'google' ? oauthUser.picture : oauthUser.avatar_url,
        createdAt: new Date()
      });
    }
    
    // Generate JWT token
    const token = createToken({ 
      id: user.id, 
      email: user.email,
      provider 
    });
    
    // Create response with cookie
    const response = Response.redirect(new URL('/dashboard', request.url));
    const cookieString = `auth_token=${token}; HttpOnly; Secure; SameSite=Lax; Max-Age=${7 * 24 * 60 * 60}; Path=/`;
    response.headers.set('Set-Cookie', cookieString);
    
    return response;
  } catch (error) {
    console.error(`${provider} OAuth error:`, error);
    return Response.redirect(new URL(`/signin?error=${encodeURIComponent(error.message)}`, request.url));
  }
}
```

### Express.js

#### OAuth Routes

```typescript
import express from 'express';
import { getGoogleOAuthURL, handleGoogleCallback, getGitHubOAuthURL, handleGitHubCallback } from 'authrix/oauth';
import { initAuth, createToken } from 'authrix';
import { mongoAdapter } from 'authrix/adapters/mongo';

const app = express();

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter,
});

// Google OAuth routes
app.get('/auth/google', (req, res) => {
  try {
    const state = crypto.randomUUID();
    req.session.oauthState = state; // Store state in session
    const url = getGoogleOAuthURL(state);
    res.redirect(url);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/auth/google/callback', async (req, res) => {
  const { code, state } = req.query;
  
  // Validate state to prevent CSRF
  if (state !== req.session.oauthState) {
    return res.status(400).json({ error: 'Invalid state parameter' });
  }
  
  if (!code) {
    return res.status(400).json({ error: 'No code provided' });
  }
  
  try {
    const oauthUser = await handleGoogleCallback(code as string);
    
    // Handle user creation/authentication here
    let user = await mongoAdapter.findUserByEmail(oauthUser.email);
    
    if (!user) {
      user = await mongoAdapter.createUser({
        email: oauthUser.email,
        password: crypto.randomUUID(),
        name: oauthUser.name,
        avatar: oauthUser.picture,
        oauthProvider: 'google',
        oauthId: oauthUser.id
      });
    }
    
    // Generate JWT token and set cookie
    const token = createToken({ id: user.id, email: user.email });
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    
    res.redirect('/dashboard');
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GitHub OAuth routes (similar pattern)
app.get('/auth/github', (req, res) => {
  try {
    const state = crypto.randomUUID();
    req.session.oauthState = state;
    const url = getGitHubOAuthURL(state);
    res.redirect(url);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/auth/github/callback', async (req, res) => {
  const { code, state } = req.query;
  
  if (state !== req.session.oauthState) {
    return res.status(400).json({ error: 'Invalid state parameter' });
  }
  
  if (!code) {
    return res.status(400).json({ error: 'No code provided' });
  }
  
  try {
    const oauthUser = await handleGitHubCallback(code as string);
    
    // Similar user handling logic...
    
    res.redirect('/dashboard');
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
```

### React SPA (Client-Side OAuth)

> **Note:** For security reasons, OAuth flows should generally be handled server-side. This example shows how to integrate with OAuth data after server-side authentication.

```typescript
// hooks/useOAuth.ts
import { useState, useEffect } from 'react';

export function useOAuth() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const initiateOAuth = (provider: 'google' | 'github') => {
    setLoading(true);
    setError(null);
    
    // Redirect to your server's OAuth initiation endpoint
    window.location.href = `/auth/${provider}`;
  };

  // Handle OAuth callback results
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const error = urlParams.get('error');
    const success = urlParams.get('success');
    
    if (error) {
      setError(decodeURIComponent(error));
      setLoading(false);
    } else if (success) {
      // OAuth successful, refresh user data
      window.location.href = '/dashboard';
    }
  }, []);

  return {
    loading,
    error,
    initiateOAuth
  };
}
```

```typescript
// components/OAuthButtons.tsx
import React from 'react';
import { useOAuth } from '../hooks/useOAuth';

export function OAuthButtons() {
  const { loading, error, initiateOAuth } = useOAuth();

  return (
    <div className="space-y-4">
      {error && (
        <div className="text-red-600 text-sm p-2 bg-red-50 rounded">
          {error}
        </div>
      )}
      
      <div className="space-y-3">
        <button
          onClick={() => initiateOAuth('google')}
          disabled={loading}
          className="w-full flex items-center justify-center px-4 py-2 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50"
        >
          <svg className="w-5 h-5 mr-2" viewBox="0 0 24 24">
            {/* Google icon SVG */}
          </svg>
          {loading ? 'Redirecting...' : 'Continue with Google'}
        </button>
        
        <button
          onClick={() => initiateOAuth('github')}
          disabled={loading}
          className="w-full flex items-center justify-center px-4 py-2 border border-gray-300 rounded-md shadow-sm bg-gray-900 text-sm font-medium text-white hover:bg-gray-800 disabled:opacity-50"
        >
          <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 24 24">
            {/* GitHub icon SVG */}
          </svg>
          {loading ? 'Redirecting...' : 'Continue with GitHub'}
        </button>
      </div>
    </div>
  );
}
```

### Next.js Pages Router

```typescript
// pages/api/auth/[...oauth].ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { getGoogleOAuthURL, handleGoogleCallback, getGitHubOAuthURL, handleGitHubCallback } from 'authrix/oauth';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { oauth } = req.query;
  const [provider, action] = oauth as string[];

  if (action === 'callback') {
    const { code } = req.query;
    
    if (!code) {
      return res.status(400).json({ error: 'No code provided' });
    }
    
    try {
      let oauthUser;
      
      if (provider === 'google') {
        oauthUser = await handleGoogleCallback(code as string);
      } else if (provider === 'github') {
        oauthUser = await handleGitHubCallback(code as string);
      } else {
        return res.status(400).json({ error: 'Unsupported provider' });
      }
      
      // Handle user authentication...
      
      res.redirect('/dashboard');
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  } else {
    // Initiate OAuth
    try {
      const state = crypto.randomUUID();
      let url;
      
      if (provider === 'google') {
        url = getGoogleOAuthURL(state);
      } else if (provider === 'github') {
        url = getGitHubOAuthURL(state);
      } else {
        return res.status(400).json({ error: 'Unsupported provider' });
      }
      
      res.redirect(url);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
}
```

## Security Best Practices

### 1. State Parameter Validation

Always use and validate the `state` parameter to prevent CSRF attacks:

```typescript
// Generate secure random state
const state = crypto.randomUUID();

// Store state (in session, database, or secure cookie)
req.session.oauthState = state;

// Validate on callback
if (callbackState !== storedState) {
  throw new Error('Invalid state parameter');
}
```

### 2. Environment Variable Validation

Ensure OAuth environment variables are set when needed:

```typescript
function validateOAuthConfig(provider: 'google' | 'github') {
  if (provider === 'google') {
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
      throw new Error('Google OAuth environment variables not configured');
    }
  }
  
  if (provider === 'github') {
    if (!process.env.GITHUB_CLIENT_ID || !process.env.GITHUB_CLIENT_SECRET) {
      throw new Error('GitHub OAuth environment variables not configured');
    }
  }
}
```

### 3. User Data Validation

Always validate data received from OAuth providers:

```typescript
function validateOAuthUser(user: any, provider: string) {
  if (!user.email) {
    throw new Error(`${provider} OAuth did not provide email`);
  }
  
  if (!user.id) {
    throw new Error(`${provider} OAuth did not provide user ID`);
  }
  
  // Additional validation as needed
}
```

### 4. Error Handling

Implement comprehensive error handling:

```typescript
try {
  const oauthUser = await handleGoogleCallback(code);
  validateOAuthUser(oauthUser, 'google');
  
  // Process user...
} catch (error) {
  console.error('OAuth error:', error);
  
  // Don't expose internal errors to users
  const userMessage = error.message.includes('OAuth') 
    ? error.message 
    : 'Authentication failed. Please try again.';
    
  res.redirect(`/signin?error=${encodeURIComponent(userMessage)}`);
}
```

### 5. Secure Cookie Configuration

Use secure cookie settings in production:

```typescript
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax' as const,
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  path: '/'
};
```

## Troubleshooting

### Common Issues

#### 1. Environment Variables Not Found

**Error:** `GOOGLE_CLIENT_ID is not defined`

**Solution:** Ensure environment variables are properly set and restart your development server:

```bash
# Check your .env file
cat .env

# Restart development server
npm run dev
```

#### 2. OAuth Redirect URI Mismatch

**Error:** `redirect_uri_mismatch`

**Solution:** Ensure the redirect URI in your OAuth provider settings matches exactly:

```
Development: http://localhost:3000/auth/google/callback
Production:  https://yourdomain.com/auth/google/callback
```

#### 3. Invalid State Parameter

**Error:** `Invalid state parameter`

**Solution:** Ensure state is properly stored and validated:

```typescript
// Store state securely
req.session.oauthState = state;

// Validate on callback
if (state !== req.session.oauthState) {
  throw new Error('Invalid state parameter');
}

// Clear state after use
delete req.session.oauthState;
```

#### 4. Import Errors

**Error:** `Cannot resolve module 'authrix/oauth'`

**Solution:** Update to the latest version of Authrix and use the correct import syntax:

```bash
npm update authrix
```

```typescript
// Correct import
import { getGoogleOAuthURL } from 'authrix/oauth';

// Alternative import
import { getGoogleOAuthURL } from 'authrix/providers/google';
```

### Debug Mode

Enable debug logging for OAuth operations:

```typescript
// Add to your environment variables
DEBUG=authrix:oauth

// Or set in code
process.env.DEBUG = 'authrix:oauth';
```

### Testing OAuth Locally

Use tools like ngrok for local OAuth testing:

```bash
# Install ngrok
npm install -g ngrok

# Expose local server
ngrok http 3000

# Use the https URL in OAuth provider settings
# Example: https://abc123.ngrok.io/auth/google/callback
```

## Advanced Usage

### Custom OAuth Providers

You can extend Authrix to support additional OAuth providers:

```typescript
// providers/custom.ts
export async function getCustomOAuthURL(state: string): Promise<string> {
  const params = new URLSearchParams({
    client_id: process.env.CUSTOM_CLIENT_ID!,
    redirect_uri: `${process.env.BASE_URL}/auth/custom/callback`,
    scope: 'user:email',
    state,
    response_type: 'code'
  });
  
  return `https://custom-provider.com/oauth/authorize?${params}`;
}

export async function handleCustomCallback(code: string) {
  // Exchange code for access token
  const tokenResponse = await fetch('https://custom-provider.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: process.env.CUSTOM_CLIENT_ID,
      client_secret: process.env.CUSTOM_CLIENT_SECRET,
      code,
      grant_type: 'authorization_code'
    })
  });
  
  const { access_token } = await tokenResponse.json();
  
  // Get user info
  const userResponse = await fetch('https://custom-provider.com/api/user', {
    headers: { Authorization: `Bearer ${access_token}` }
  });
  
  return await userResponse.json();
}
```

### OAuth with Custom User Fields

Handle additional user data from OAuth providers:

```typescript
async function createOAuthUser(oauthUser: any, provider: string) {
  const userData = {
    email: oauthUser.email,
    password: crypto.randomUUID(), // Random password for OAuth users
    name: oauthUser.name || oauthUser.login,
    avatar: provider === 'google' ? oauthUser.picture : oauthUser.avatar_url,
    oauthProvider: provider,
    oauthId: oauthUser.id.toString(),
    emailVerified: oauthUser.verified_email || true,
    locale: oauthUser.locale,
    createdAt: new Date()
  };
  
  return await mongoAdapter.createUser(userData);
}
```

This comprehensive guide covers all aspects of OAuth integration with Authrix. For more specific use cases or custom implementations, refer to the main documentation or create an issue on the GitHub repository.
