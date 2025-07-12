# Edge Runtime Compatibility Guide

## Problem: Next.js Middleware Edge Runtime Errors

When using Authrix middleware functions in Next.js middleware, you may encounter errors like:

```
Error: The edge runtime does not support Node.js 'dns' module.
```

This happens because Next.js middleware runs on **Edge Runtime**, which doesn't support Node.js APIs like:
- `jsonwebtoken` library (crypto modules)
- Database connections (networking modules)
- File system operations
- DNS resolution

## Solution: Edge Runtime Compatible Functions

Authrix v1.0.1+ provides Edge Runtime compatible middleware functions that work without Node.js dependencies.

### Basic Edge Runtime Middleware

Use `checkAuthMiddleware` for basic token validation:

```typescript
// middleware.ts (Edge Runtime Compatible)
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { checkAuthMiddleware } from 'authrix/nextjs';

export async function middleware(request: NextRequest) {
  // This function works in Edge Runtime!
  const auth = await checkAuthMiddleware(request, {
    cookieName: 'auth_token' // optional, defaults to config or 'auth_token'
  });
  
  const { pathname } = request.nextUrl;
  
  // Define protected routes
  const protectedRoutes = ['/dashboard', '/profile'];
  const authRoutes = ['/signin', '/signup'];
  
  if (protectedRoutes.some(route => pathname.startsWith(route))) {
    if (!auth.isAuthenticated) {
      return NextResponse.redirect(new URL('/signin', request.url));
    }
  }
  
  if (authRoutes.some(route => pathname.startsWith(route))) {
    if (auth.isAuthenticated) {
      return NextResponse.redirect(new URL('/dashboard', request.url));
    }
  }
  
  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)']
};
```

### Secure Edge Runtime Middleware (Recommended)

For production applications, use `checkAuthMiddlewareSecure` which validates tokens via API:

```typescript
// middleware.ts (Secure Edge Runtime)
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { checkAuthMiddlewareSecure } from 'authrix/nextjs';

export async function middleware(request: NextRequest) {
  // This validates tokens securely via API call
  const auth = await checkAuthMiddlewareSecure(request, {
    validationEndpoint: '/api/auth/validate', // optional, defaults to this
    timeout: 3000, // optional, defaults to 5000ms
    cookieName: 'auth_token' // optional, defaults to config or 'auth_token'
  });
  
  const { pathname } = request.nextUrl;
  
  if (pathname.startsWith('/dashboard')) {
    if (!auth.isAuthenticated) {
      return NextResponse.redirect(new URL('/signin', request.url));
    }
    
    // Add user info to headers for downstream use
    const response = NextResponse.next();
    if (auth.user) {
      response.headers.set('x-user-id', auth.user.id);
      response.headers.set('x-user-email', auth.user.email);
    }
    return response;
  }
  
  return NextResponse.next();
}
```

### Required API Validation Endpoint

When using `checkAuthMiddlewareSecure`, create a validation API endpoint:

**App Router** (`app/api/auth/validate/route.ts`):
```typescript
import { createTokenValidationHandler } from 'authrix/nextjs';

export const POST = createTokenValidationHandler();
```

**Pages Router** (`pages/api/auth/validate.ts`):
```typescript
import { createTokenValidationHandlerPages } from 'authrix/nextjs';

export default createTokenValidationHandlerPages();
```

## Fixed Issues in v1.0.1+

### AbortSignal.timeout() Compatibility
The previous implementation used `AbortSignal.timeout()` which is not universally supported in all Edge Runtime environments. This has been fixed to use `AbortController` with `setTimeout()` for better compatibility.

### AuthConfig Access in Edge Runtime
Added fallback mechanisms for accessing authentication configuration in Edge Runtime environments where the config might not be fully initialized.

## How It Works

### Basic Validation (`checkAuthMiddleware`)
- ✅ Edge Runtime compatible
- ⚠️ No signature verification (not cryptographically secure)
- ✅ Structure validation (3-part JWT format)
- ✅ Expiration checking
- ✅ Payload extraction
- 🎯 **Use case**: Non-critical routing decisions, basic auth checks

### Secure Validation (`checkAuthMiddlewareSecure`)
- ✅ Edge Runtime compatible
- ✅ Full JWT signature verification (via API)
- ✅ Database user validation
- ✅ Cryptographically secure
- ⚠️ Additional API call (slight latency)
- 🎯 **Use case**: Production applications, security-critical routing

## Migration Guide

### Before (Problematic)
```typescript
// ❌ This will fail in Edge Runtime
import { getCurrentUserFromToken, isTokenValid } from 'authrix';

export async function middleware(request: NextRequest) {
  const token = request.cookies.get('auth_token')?.value;
  const isAuthenticated = await isTokenValid(token); // Node.js crypto error!
}
```

### After (Working)
```typescript
// ✅ Edge Runtime compatible
import { checkAuthMiddleware } from 'authrix/nextjs';

export async function middleware(request: NextRequest) {
  const auth = await checkAuthMiddleware(request);
  const isAuthenticated = auth.isAuthenticated; // Works in Edge Runtime!
}
```

## Security Considerations

### Basic Middleware Security
The basic `checkAuthMiddleware` function:
- **Does NOT verify JWT signatures** - tokens could be forged
- **Does NOT check database** - users could be deleted but tokens still work
- **Only checks structure and expiration**

Use basic middleware for:
- ✅ Redirecting unauthenticated users to login
- ✅ Showing/hiding UI elements
- ✅ Non-critical route protection
- ❌ **DO NOT USE** for sensitive operations or API protection

### Secure Middleware Security
The secure `checkAuthMiddlewareSecure` function:
- **Verifies JWT signatures** via server-side API
- **Checks user existence** in database
- **Cryptographically secure**
- **Safe for all use cases**

## Performance Notes

- **Basic middleware**: ~1ms (no network calls)
- **Secure middleware**: ~10-50ms (includes API validation call)
- **API validation**: Cached in Edge Runtime (automatically optimized by Next.js)

## Troubleshooting

### Error: "dns module not supported"
- ✅ Use `checkAuthMiddleware` or `checkAuthMiddlewareSecure`
- ❌ Don't import `isTokenValid`, `getCurrentUserFromToken` in middleware

### Error: "AbortSignal.timeout is not a function"
- ✅ This is fixed in v1.0.1+ by using `AbortController` instead
- ✅ Update to the latest version of Authrix

### Error: "API validation failed"
- ✅ Ensure `/api/auth/validate` endpoint exists
- ✅ Check Authrix is properly initialized in API routes
- ✅ Verify database connection works in API context

### Error: "Token appears valid but user access denied"
- ✅ This is expected with basic middleware (no signature verification)
- ✅ Use secure middleware for production authentication
- ✅ Validate tokens properly in your API routes

## Best Practices

1. **Use secure middleware in production**
2. **Use basic middleware for development/non-critical routing**
3. **Always validate tokens in API routes** (not just middleware)
4. **Cache validation results** when possible
5. **Set appropriate timeouts** for API validation
6. **Monitor middleware performance** in production

## Example Complete Setup

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { checkAuthMiddlewareSecure } from 'authrix/nextjs';

export async function middleware(request: NextRequest) {
  const auth = await checkAuthMiddlewareSecure(request);
  const { pathname } = request.nextUrl;
  
  // Protected routes
  if (pathname.startsWith('/dashboard') || pathname.startsWith('/profile')) {
    if (!auth.isAuthenticated) {
      return NextResponse.redirect(new URL('/signin', request.url));
    }
  }
  
  // Auth-only routes (redirect if already logged in)
  if (pathname.startsWith('/signin') || pathname.startsWith('/signup')) {
    if (auth.isAuthenticated) {
      return NextResponse.redirect(new URL('/dashboard', request.url));
    }
  }
  
  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)']
};
```

```typescript
// app/api/auth/validate/route.ts
import { createTokenValidationHandler } from 'authrix/nextjs';

export const POST = createTokenValidationHandler();
```
