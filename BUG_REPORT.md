# Bug Report: Next.js Middleware Edge Runtime Compatibility Issue

## Summary
Next.js middleware fails to run when importing Authrix functions that depend on Node.js modules, specifically encountering "The edge runtime does not support Node.js 'dns' module" error.

## Environment
- **Framework**: Next.js (App Router with Turbopack)
- **Runtime**: Edge Runtime (Middleware)
- **Authentication Library**: Authrix v1.0.1
- **Database**: MongoDB Atlas
- **Date**: July 12, 2025

## Error Details

### Error Message
```
⨯ Error: The edge runtime does not support Node.js 'dns' module.
Learn More: https://nextjs.org/docs/messages/node-module-in-edge-runtime
    at Object.get (.next\server\edge\chunks\_379c85ae._.js:62:41)
    at <unknown> (.next\server\edge\chunks\edge-wrapper_b2962744.js:722:27)
    at runModuleExecutionHooks (.next\server\edge\chunks\edge-wrapper_b2962744.js:768:9)
    at instantiateModule (.next\server\edge\chunks\edge-wrapper_b2962744.js:720:9)
    at getOrInstantiateModuleFromParent (.next\server\edge\chunks\edge-wrapper_b2962744.js:653:12)
    at commonJsRequire (.next\server\edge\chunks\edge-wrapper_b2962744.js:158:20)
    at <unknown> (.next\server\edge\chunks\edge-wrapper_b2962744.js:722:27)
```

### Request Impact
- `GET / 404 in 4ms` - Homepage fails to load
- `GET / 404 in 13ms` - Subsequent requests also fail
- `GET /favicon.ico 200 in 296ms` - Static assets work normally

## Root Cause

### Original Problematic Code
```typescript
// middleware.ts (BROKEN VERSION)
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { getCurrentUserFromToken, isTokenValid } from 'authrix'; // ❌ CAUSES ERROR
import '@/lib/auth'; // ❌ IMPORTS NODE.JS DEPENDENCIES

export async function middleware(request: NextRequest) {
  const token = request.cookies.get('auth_token')?.value;
  const isAuthenticated = token ? await isTokenValid(token) : false; // ❌ USES NODE.JS DNS
  // ... rest of middleware logic
}
```

### Technical Analysis
1. **Edge Runtime Limitation**: Next.js middleware runs on Edge Runtime, which doesn't support Node.js APIs
2. **Authrix Dependencies**: `isTokenValid` function internally uses:
   - JWT verification libraries
   - Database connections (MongoDB)
   - DNS resolution for database connections
   - Crypto APIs that depend on Node.js modules
3. **Import Chain**: Importing `@/lib/auth` pulls in the entire Authrix initialization with MongoDB adapter

## Impact Assessment

### Severity: HIGH
- **Functionality**: Complete middleware failure
- **User Experience**: Homepage and protected routes inaccessible
- **Performance**: Requests fail immediately
- **Development**: Blocks local development workflow

### Affected Features
- ✅ **API Routes**: Working (run on Node.js runtime)
- ❌ **Homepage**: 404 errors due to middleware failure
- ❌ **Route Protection**: Cannot access any protected routes
- ❌ **Authentication Redirects**: Middleware-based redirects broken
- ✅ **Static Assets**: Working normally

## Solution Implemented

### Fixed Code
```typescript
// middleware.ts (WORKING VERSION)
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export async function middleware(request: NextRequest) {
  // Get the auth token from cookies
  const token = request.cookies.get('auth_token')?.value;
  
  // Simple token existence check (for Edge Runtime compatibility)
  // In a production app, you might want to validate the JWT structure
  const isAuthenticated = !!(token && token.length > 0); // ✅ EDGE RUNTIME COMPATIBLE
  
  const { pathname } = request.nextUrl;
  
  // Define protected and auth-only routes
  const authRoutes = ['/signin', '/signup'];
  const protectedRoutes = ['/dashboard'];
  
  // Authentication logic remains the same...
}
```

### Key Changes
1. **Removed Authrix imports**: Eliminated dependency on Node.js modules
2. **Simplified token validation**: Basic token existence check instead of full JWT validation
3. **Edge Runtime compatible**: Uses only Web APIs available in Edge Runtime

## Alternative Solutions Considered

### Option 1: Runtime-specific Token Validation
```typescript
// Edge Runtime compatible JWT validation (future enhancement)
function isValidJWTStructure(token: string): boolean {
  const parts = token.split('.');
  return parts.length === 3 && parts.every(part => part.length > 0);
}
```

### Option 2: API Route Validation
```typescript
// Validate token via API call (more network overhead)
const response = await fetch('/api/auth/validate', {
  headers: { Authorization: `Bearer ${token}` }
});
const isAuthenticated = response.ok;
```

### Option 3: Server-side Middleware
```typescript
// Move to API middleware (loses Edge Runtime performance benefits)
// Not implemented due to performance implications
```

## Recommendations

### Immediate Actions ❌ IN PROGRESS
- [x] Remove Node.js dependencies from middleware
- [x] Implement basic token existence check
- [ ] **ISSUE PERSISTS** - Additional investigation needed
- [ ] Identify remaining Node.js dependencies
- [ ] Test middleware functionality
- [ ] Verify route protection works

### Future Enhancements
- [ ] Implement Edge Runtime compatible JWT structure validation
- [ ] Add proper JWT expiration checking without full validation
- [ ] Consider using Web Crypto API for basic token verification
- [ ] Document Edge Runtime limitations for team

### Authrix Library Improvements
- [ ] Create Edge Runtime compatible token validation functions
- [ ] Separate core token utilities from database-dependent functions
- [ ] Provide middleware-specific utilities in separate export

## Testing Status

### Current Status (STILL FAILING)
- ❌ Middleware crashes on startup
- ❌ Homepage returns 404 errors
- ❌ All routes fail due to middleware error
- ❌ Edge Runtime DNS module error persists

### Attempted Fix Results
- ✅ Removed Authrix imports from middleware
- ✅ Simplified token validation logic
- ❌ **Issue still persists** - DNS module error continues
- ❌ Routes still inaccessible

## Additional Investigation Required

### Current Issue Analysis
Despite removing direct Authrix imports from middleware, the DNS module error persists, suggesting:

1. **Hidden Dependencies**: There may be indirect imports still pulling in Node.js modules
2. **Build System Issue**: Turbopack may be bundling unwanted dependencies
3. **Import Side Effects**: Other imports might be causing the DNS module to load
4. **Authrix Global State**: The `@/lib/auth` import may still be affecting the build

### Next Investigation Steps
1. **Check Import Chain**: Analyze what's still importing Node.js modules
2. **Build Analysis**: Examine the generated Edge Runtime chunks
3. **Dependency Audit**: Review all imports in middleware and related files
4. **Isolation Test**: Create minimal middleware without any custom imports

### Potential Root Causes
- Other files in the project importing Authrix globally
- Build system including MongoDB dependencies in Edge Runtime bundle
- Next.js configuration issues with Edge Runtime
- Authrix library bleeding dependencies into global scope

## Related Issues
- [Next.js Edge Runtime Limitations](https://nextjs.org/docs/messages/node-module-in-edge-runtime)
- [Authrix MongoDB Dependencies in Edge Runtime](https://github.com/Grenish/authrix/issues/edge-runtime-compatibility)

## Prevention Strategy
1. **Code Review**: Check for Node.js module imports in middleware
2. **Testing**: Always test middleware in Edge Runtime environment
3. **Documentation**: Maintain list of Edge Runtime compatible utilities
4. **Linting**: Add ESLint rules to prevent Node.js imports in middleware files

---

**Status**: ❌ UNRESOLVED - ISSUE PERSISTS  
**Investigation Date**: July 12, 2025  
**Next Steps**: Further investigation needed to identify remaining Node.js dependencies  
**Impact**: HIGH - Application completely inaccessible due to middleware failure
