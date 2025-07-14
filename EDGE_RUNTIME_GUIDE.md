# Edge Runtime Guide

> Complete guide for using Authrix in Next.js Edge Runtime environments, including middleware, edge functions, and serverless deployments.

## Table of Contents

- [Overview](#overview)
- [Edge Runtime Compatibility](#edge-runtime-compatibility)
- [Middleware Authentication](#middleware-authentication)
- [Edge API Routes](#edge-api-routes)
- [Limitations and Workarounds](#limitations-and-workarounds)
- [Performance Optimization](#performance-optimization)
- [Security Considerations](#security-considerations)
- [Deployment Platforms](#deployment-platforms)
- [Troubleshooting](#troubleshooting)

## Overview

The Edge Runtime is a JavaScript runtime based on Web APIs rather than Node.js APIs. It's designed for high performance and low latency, making it ideal for middleware, edge functions, and serverless deployments.

### Key Benefits

- **Low Latency**: Faster cold starts compared to Node.js runtime
- **Geographic Distribution**: Run closer to users globally
- **Automatic Scaling**: Handle traffic spikes efficiently
- **Reduced Bundle Size**: Smaller runtime footprint

### Authrix Edge Runtime Features

- ✅ **JWT Token Validation**: Basic structure and expiration checks
- ✅ **Cookie Handling**: Read and parse authentication cookies
- ✅ **Middleware Support**: Route protection in Next.js middleware
- ✅ **Edge API Routes**: Authentication in edge functions
- ⚠️ **Limited Database Access**: No direct database connections
- ⚠️ **No JWT Signature Verification**: Use secure validation endpoints instead

## Edge Runtime Compatibility

### Supported Features

```typescript
// ✅ These work in Edge Runtime
import { 
  checkAuthMiddleware,          // Basic auth check without signature verification
  checkAuthMiddlewareSecure,    // Auth check with API validation
  getCurrentUserNextApp,        // User info from cookies
  isAuthenticatedNextApp,       // Authentication status
  createAuthCookieString,       // Manual cookie creation
  createLogoutCookieString      // Manual cookie clearing
} from "authrix/nextjs";
```

### Unsupported Features

```typescript
// ❌ These DON'T work in Edge Runtime
import {
  signupNextApp,     // Requires database access
  signinNextApp,     // Requires database access
  verifyToken        // Requires Node.js crypto APIs
} from "authrix/nextjs";
```

## Middleware Authentication

### Basic Middleware

Use `checkAuthMiddleware` for basic authentication checks:

```typescript
// middleware.ts
import { NextRequest, NextResponse } from "next/server";
import { checkAuthMiddleware } from "authrix/nextjs";

export async function middleware(request: NextRequest) {
  // Check authentication for protected routes
  if (request.nextUrl.pathname.startsWith('/dashboard') ||
      request.nextUrl.pathname.startsWith('/profile') ||
      request.nextUrl.pathname.startsWith('/admin')) {
    
    const auth = await checkAuthMiddleware(request);
    
    if (!auth.isAuthenticated) {
      // Redirect to login page
      const loginUrl = new URL('/signin', request.url);
      loginUrl.searchParams.set('redirect', request.nextUrl.pathname);
      return NextResponse.redirect(loginUrl);
    }
    
    // Optional: Add user info to headers for downstream consumption
    const response = NextResponse.next();
    if (auth.user) {
      response.headers.set('x-user-id', auth.user.id);
      response.headers.set('x-user-email', auth.user.email);
    }
    return response;
  }
  
  // Redirect authenticated users away from auth pages
  if (request.nextUrl.pathname === '/signin' ||
      request.nextUrl.pathname === '/signup') {
    
    const auth = await checkAuthMiddleware(request);
    
    if (auth.isAuthenticated) {
      return NextResponse.redirect(new URL('/dashboard', request.url));
    }
  }
  
  return NextResponse.next();
}

export const config = {
  matcher: [
    '/dashboard/:path*',
    '/profile/:path*', 
    '/admin/:path*',
    '/signin',
    '/signup'
  ]
};
```

### Secure Middleware with API Validation

For enhanced security, use `checkAuthMiddlewareSecure` which validates tokens via API calls:

```typescript
// middleware.ts
import { NextRequest, NextResponse } from "next/server";
import { checkAuthMiddlewareSecure } from "authrix/nextjs";

export async function middleware(request: NextRequest) {
  if (request.nextUrl.pathname.startsWith('/admin')) {
    // Use secure validation for admin routes
    const auth = await checkAuthMiddlewareSecure(request, {
      validationEndpoint: '/api/auth/validate',
      timeout: 5000 // 5 second timeout
    });
    
    if (!auth.isAuthenticated) {
      return NextResponse.redirect(new URL('/signin', request.url));
    }
    
    // Additional role-based checks can be added here
    return NextResponse.next();
  }
  
  // Use basic validation for other protected routes
  if (request.nextUrl.pathname.startsWith('/dashboard')) {
    const auth = await checkAuthMiddleware(request);
    
    if (!auth.isAuthenticated) {
      return NextResponse.redirect(new URL('/signin', request.url));
    }
  }
  
  return NextResponse.next();
}
```

### Advanced Middleware Patterns

#### Role-Based Access Control

```typescript
// middleware.ts
import { NextRequest, NextResponse } from "next/server";
import { checkAuthMiddlewareSecure } from "authrix/nextjs";

const ROLE_ROUTES = {
  '/admin': ['admin'],
  '/moderator': ['admin', 'moderator'],
  '/dashboard': ['admin', 'moderator', 'user']
};

export async function middleware(request: NextRequest) {
  const path = request.nextUrl.pathname;
  const requiredRoles = Object.entries(ROLE_ROUTES)
    .find(([route]) => path.startsWith(route))?.[1];
  
  if (requiredRoles) {
    const auth = await checkAuthMiddlewareSecure(request, {
      validationEndpoint: '/api/auth/validate-role'
    });
    
    if (!auth.isAuthenticated) {
      return NextResponse.redirect(new URL('/signin', request.url));
    }
    
    // Role validation is handled by the API endpoint
    // The secure middleware will return user role information
  }
  
  return NextResponse.next();
}
```

#### Geographic Restrictions

```typescript
// middleware.ts
import { NextRequest, NextResponse } from "next/server";
import { checkAuthMiddleware } from "authrix/nextjs";

export async function middleware(request: NextRequest) {
  // Geo-restrictions for sensitive routes
  if (request.nextUrl.pathname.startsWith('/admin')) {
    const country = request.geo?.country;
    const allowedCountries = ['US', 'CA', 'GB'];
    
    if (country && !allowedCountries.includes(country)) {
      return NextResponse.json(
        { error: 'Access not allowed from this location' },
        { status: 403 }
      );
    }
    
    const auth = await checkAuthMiddleware(request);
    if (!auth.isAuthenticated) {
      return NextResponse.redirect(new URL('/signin', request.url));
    }
  }
  
  return NextResponse.next();
}
```

## Edge API Routes

### Basic Edge Authentication

```typescript
// app/api/user/profile/route.ts
import { NextRequest } from "next/server";
import { getCurrentUserNextApp } from "authrix/nextjs";

export const runtime = 'edge';

export async function GET(request: NextRequest) {
  try {
    const user = await getCurrentUserNextApp();
    
    if (!user) {
      return Response.json(
        { error: 'Authentication required' },
        { status: 401 }
      );
    }
    
    // Return user profile data
    return Response.json({
      user: {
        id: user.id,
        email: user.email,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    return Response.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
```

### Token Validation Endpoint

Create a validation endpoint for secure middleware:

```typescript
// app/api/auth/validate/route.ts
import { NextRequest } from "next/server";
import { verifyToken } from "authrix/tokens";

export const runtime = 'nodejs'; // Use Node.js runtime for crypto operations

export async function POST(request: NextRequest) {
  try {
    const { token } = await request.json();
    
    if (!token) {
      return Response.json({ valid: false }, { status: 400 });
    }
    
    const user = await verifyToken(token);
    
    return Response.json({
      valid: true,
      user: {
        id: user.id,
        email: user.email,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    return Response.json({ valid: false }, { status: 401 });
  }
}
```

### Edge Function with External API

```typescript
// app/api/external-data/route.ts
import { NextRequest } from "next/server";
import { checkAuthMiddleware } from "authrix/nextjs";

export const runtime = 'edge';

export async function GET(request: NextRequest) {
  // Check authentication
  const auth = await checkAuthMiddleware(request);
  
  if (!auth.isAuthenticated) {
    return Response.json(
      { error: 'Authentication required' },
      { status: 401 }
    );
  }
  
  try {
    // Fetch data from external API
    const response = await fetch('https://api.example.com/data', {
      headers: {
        'Authorization': `Bearer ${process.env.EXTERNAL_API_KEY}`,
        'User-Agent': 'Authrix-Edge-Function'
      }
    });
    
    if (!response.ok) {
      throw new Error('External API failed');
    }
    
    const data = await response.json();
    
    return Response.json({
      user: auth.user,
      data
    });
  } catch (error) {
    return Response.json(
      { error: 'Failed to fetch external data' },
      { status: 500 }
    );
  }
}
```

## Limitations and Workarounds

### Database Access Limitation

**Problem:** Edge Runtime cannot make direct database connections.

**Workaround:** Use API routes in Node.js runtime for database operations:

```typescript
// app/api/user/update/route.ts (Node.js runtime)
import { getCurrentUser } from "authrix";
import { mongoAdapter } from "authrix/adapters/mongo";

export async function PUT(request: Request) {
  const user = await getCurrentUser(request);
  
  if (!user) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }
  
  const updates = await request.json();
  
  // Direct database access works in Node.js runtime
  const updatedUser = await mongoAdapter.updateUser(user.id, updates);
  
  return Response.json({ user: updatedUser });
}
```

```typescript
// app/api/user/profile-edge/route.ts (Edge runtime)
import { NextRequest } from "next/server";
import { getCurrentUserNextApp } from "authrix/nextjs";

export const runtime = 'edge';

export async function GET(request: NextRequest) {
  const user = await getCurrentUserNextApp();
  
  if (!user) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }
  
  // Fetch additional data via internal API
  const response = await fetch(new URL('/api/user/details', request.url), {
    headers: {
      'Cookie': request.headers.get('cookie') || ''
    }
  });
  
  const userData = await response.json();
  
  return Response.json(userData);
}
```

### JWT Signature Verification

**Problem:** Edge Runtime lacks Node.js crypto APIs for JWT signature verification.

**Workaround:** Use API validation endpoints:

```typescript
// Secure validation via API call
const auth = await checkAuthMiddlewareSecure(request, {
  validationEndpoint: '/api/auth/validate'
});
```

### Session Storage

**Problem:** No built-in session storage in Edge Runtime.

**Workaround:** Use cookies or external storage:

```typescript
import { NextRequest, NextResponse } from "next/server";

export async function middleware(request: NextRequest) {
  // Store temporary data in cookies
  const response = NextResponse.next();
  
  // Set secure cookie for session data
  response.cookies.set('session_data', JSON.stringify({
    timestamp: Date.now(),
    requestId: crypto.randomUUID()
  }), {
    httpOnly: true,
    secure: true,
    maxAge: 300 // 5 minutes
  });
  
  return response;
}
```

## Performance Optimization

### Minimize Bundle Size

Only import what you need in Edge Runtime:

```typescript
// ✅ Good - Import specific functions
import { checkAuthMiddleware } from "authrix/nextjs";

// ❌ Avoid - Importing entire modules
import * as authrix from "authrix";
```

### Cache Authentication Results

```typescript
// Simple in-memory cache for Edge Runtime
const authCache = new Map();

export async function middleware(request: NextRequest) {
  const token = request.cookies.get('auth_token')?.value;
  
  if (!token) {
    return NextResponse.redirect(new URL('/signin', request.url));
  }
  
  // Check cache first (be careful with sensitive data)
  const cacheKey = `auth_${token.slice(-8)}`;
  const cached = authCache.get(cacheKey);
  
  if (cached && Date.now() - cached.timestamp < 60000) { // 1 minute cache
    if (!cached.isAuthenticated) {
      return NextResponse.redirect(new URL('/signin', request.url));
    }
    return NextResponse.next();
  }
  
  // Validate token
  const auth = await checkAuthMiddleware(request);
  
  // Cache result
  authCache.set(cacheKey, {
    isAuthenticated: auth.isAuthenticated,
    timestamp: Date.now()
  });
  
  if (!auth.isAuthenticated) {
    return NextResponse.redirect(new URL('/signin', request.url));
  }
  
  return NextResponse.next();
}
```

### Optimize API Calls

```typescript
// Batch validation requests when possible
export async function validateMultipleTokens(tokens: string[]) {
  const validationPromises = tokens.map(async (token) => {
    try {
      const response = await fetch('/api/auth/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });
      return await response.json();
    } catch (error) {
      return { valid: false };
    }
  });
  
  return await Promise.all(validationPromises);
}
```

## Security Considerations

### Token Exposure

Since Edge Runtime has limitations with signature verification, be extra careful about token exposure:

```typescript
// Always use secure cookies
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict' as const,
  path: '/'
};
```

### Rate Limiting

Implement rate limiting in Edge Runtime:

```typescript
// Simple rate limiting
const rateLimitCache = new Map();

export async function middleware(request: NextRequest) {
  const ip = request.ip || request.headers.get('x-forwarded-for');
  const key = `rate_limit_${ip}`;
  
  const now = Date.now();
  const windowMs = 60000; // 1 minute
  const maxRequests = 100;
  
  const requests = rateLimitCache.get(key) || [];
  const validRequests = requests.filter((time: number) => now - time < windowMs);
  
  if (validRequests.length >= maxRequests) {
    return NextResponse.json(
      { error: 'Too many requests' },
      { status: 429 }
    );
  }
  
  validRequests.push(now);
  rateLimitCache.set(key, validRequests);
  
  return NextResponse.next();
}
```

### Input Validation

```typescript
function validateRequest(request: NextRequest): boolean {
  // Validate request headers
  const userAgent = request.headers.get('user-agent');
  if (!userAgent || userAgent.length > 1000) {
    return false;
  }
  
  // Validate request size
  const contentLength = request.headers.get('content-length');
  if (contentLength && parseInt(contentLength) > 1024 * 1024) { // 1MB limit
    return false;
  }
  
  return true;
}
```

## Deployment Platforms

### Vercel

Authrix works seamlessly with Vercel's Edge Runtime:

```javascript
// vercel.json
{
  "functions": {
    "app/api/edge/**/*.js": {
      "runtime": "edge"
    }
  }
}
```

### Cloudflare Workers

```typescript
// wrangler.toml
compatibility_flags = ["nodejs_compat"]

# worker.js
import { checkAuthMiddleware } from "authrix/nextjs";

export default {
  async fetch(request, env, ctx) {
    const auth = await checkAuthMiddleware(request);
    
    if (!auth.isAuthenticated) {
      return new Response('Unauthorized', { status: 401 });
    }
    
    return new Response('Hello authenticated user!');
  }
};
```

### AWS Lambda@Edge

```typescript
// lambda-edge.js
const { checkAuthMiddleware } = require('authrix/nextjs');

exports.handler = async (event, context) => {
  const request = event.Records[0].cf.request;
  
  // Convert CloudFront request to standard format
  const standardRequest = {
    cookies: {
      get: (name) => {
        const cookies = parseCookies(request.headers.cookie?.[0]?.value || '');
        return { value: cookies[name] };
      }
    }
  };
  
  const auth = await checkAuthMiddleware(standardRequest);
  
  if (!auth.isAuthenticated) {
    return {
      status: '302',
      statusDescription: 'Found',
      headers: {
        location: [{
          key: 'Location',
          value: '/signin'
        }]
      }
    };
  }
  
  return request;
};
```

## Troubleshooting

### Common Issues

#### 1. "Cannot use Node.js APIs in Edge Runtime"

**Error:** `ReferenceError: crypto is not defined`

**Solution:** Use Web APIs instead of Node.js APIs:

```typescript
// ❌ Node.js API
const hash = crypto.createHash('sha256');

// ✅ Web API
const hash = await crypto.subtle.digest('SHA-256', data);
```

#### 2. Database Connection Errors

**Error:** `Cannot connect to database in Edge Runtime`

**Solution:** Move database operations to Node.js API routes:

```typescript
// ❌ Direct database access in Edge Runtime
const user = await db.findUser(id);

// ✅ API call to Node.js route
const response = await fetch('/api/user/' + id);
const user = await response.json();
```

#### 3. Large Bundle Size

**Error:** Edge function bundle too large

**Solution:** Use dynamic imports and minimize dependencies:

```typescript
// ✅ Dynamic import
const auth = await import('authrix/nextjs').then(m => 
  m.checkAuthMiddleware(request)
);
```

#### 4. Middleware Not Running

**Issue:** Middleware doesn't execute on certain routes

**Solution:** Check the matcher configuration:

```typescript
export const config = {
  matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
    '/api/protected/:path*'
  ]
};
```

### Debug Mode

Enable debug logging for Edge Runtime issues:

```typescript
// In your Edge function
console.log('Edge Runtime Debug:', {
  url: request.url,
  method: request.method,
  headers: Object.fromEntries(request.headers.entries()),
  cookies: request.cookies.getAll()
});
```

### Testing Edge Functions Locally

```bash
# Next.js development server supports Edge Runtime
npm run dev

# Test middleware behavior
curl -H "Cookie: auth_token=invalid" http://localhost:3000/dashboard
```

### Performance Monitoring

```typescript
export async function middleware(request: NextRequest) {
  const start = Date.now();
  
  const auth = await checkAuthMiddleware(request);
  
  const duration = Date.now() - start;
  console.log(`Auth check took ${duration}ms`);
  
  // Add performance headers
  const response = NextResponse.next();
  response.headers.set('X-Auth-Duration', duration.toString());
  
  return response;
}
```

This comprehensive guide covers all aspects of using Authrix in Edge Runtime environments. The key is understanding the limitations and working with them rather than against them, leveraging the performance benefits while maintaining security and functionality.
