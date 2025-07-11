# OAuth Usage Guide

This guide explains how to use OAuth providers with Authrix after the recent fixes for environment variable issues.

## Overview

OAuth provider functions are now exported separately to avoid environment variable validation errors when OAuth is not being used. You can import OAuth functionality in several ways:

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

## Environment Variables

OAuth functionality requires specific environment variables. These are only validated when OAuth functions are actually called, not when the library is imported.

### Google OAuth
```env
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_secret
GOOGLE_REDIRECT_URI=http://localhost:3000/auth/google/callback
```

### GitHub OAuth
```env
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_secret
GITHUB_REDIRECT_URI=http://localhost:3000/auth/github/callback
```

## Usage Examples

### Next.js App Router
```typescript
// app/auth/google/route.ts
import { getGoogleOAuthURL } from 'authrix/oauth';

export async function GET() {
  try {
    const state = crypto.randomUUID();
    const url = getGoogleOAuthURL(state);
    
    return Response.redirect(url);
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
}

// app/auth/google/callback/route.ts
import { handleGoogleCallback } from 'authrix/oauth';
import { initAuth, mongoAdapter } from 'authrix';

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter,
});

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const code = searchParams.get('code');
  
  if (!code) {
    return Response.json({ error: 'No code provided' }, { status: 400 });
  }
  
  try {
    const oauthUser = await handleGoogleCallback(code);
    
    // Handle user creation/authentication here
    // Check if user exists in your database, create if not
    // Generate JWT token and set cookie
    
    return Response.redirect('/dashboard');
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
}
```

### Express.js
```typescript
import express from 'express';
import { getGitHubOAuthURL, handleGitHubCallback } from 'authrix/oauth';
import { initAuth, mongoAdapter } from 'authrix';

const app = express();

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter,
});

app.get('/auth/github', (req, res) => {
  try {
    const state = crypto.randomUUID();
    const url = getGitHubOAuthURL(state);
    res.redirect(url);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/auth/github/callback', async (req, res) => {
  const { code } = req.query;
  
  if (!code) {
    return res.status(400).json({ error: 'No code provided' });
  }
  
  try {
    const oauthUser = await handleGitHubCallback(code as string);
    
    // Handle user creation/authentication here
    // Check if user exists in your database, create if not
    // Generate JWT token and set cookie
    
    res.redirect('/dashboard');
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
```

## Error Handling

If you try to use OAuth functions without setting the required environment variables, you'll get a clear error message:

```
Missing Google OAuth environment variables. Please set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and GOOGLE_REDIRECT_URI in your environment file. These are only required when using Google OAuth functionality.
```

This error will only occur when you actually call the OAuth functions, not when importing the library.

## Migration from Previous Versions

If you were previously importing OAuth functions from the main 'authrix' export:

### Before
```typescript
import { getGoogleOAuthURL, handleGoogleCallback } from 'authrix';
```

### After
```typescript
import { getGoogleOAuthURL, handleGoogleCallback } from 'authrix/oauth';
```

This change ensures that OAuth environment variables are only validated when needed, preventing errors during signup/signin when OAuth is not being used.
