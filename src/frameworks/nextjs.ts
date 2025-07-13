// Next.js utilities for Authrix
// These imports are optional and will only work when Next.js is available

import { signupCore } from "../core/signup";
import { signinCore } from "../core/signin";
import { logoutCore } from "../core/logout";
import { getCurrentUserFromToken, isTokenValid } from "../core/session";
import { authConfig } from "../config";

let NextRequest: any, NextResponse: any, NextApiRequest: any, NextApiResponse: any, cookies: any;
let isNextJsAvailable = false;
let nextJsContext: 'app-router' | 'pages-router' | 'middleware' | 'unknown' = 'unknown';
let detectionComplete = false;

// Helper function to safely get cookie name with fallback
function getSafeCookieName(): string {
  try {
    // Try to access authConfig, but provide fallback for Edge Runtime
    return authConfig?.cookieName || 'auth_token';
  } catch (error) {
    // If authConfig is not available (Edge Runtime), use default
    return 'auth_token';
  }
}

// Improved Next.js detection that works in various environments
function detectNextJsEnvironment() {
  if (detectionComplete) {
    return;
  }

  try {
    // Method 1: Try dynamic import approach (works better in bundled environments)
    let nextServerModule: any;
    let nextModule: any;
    let nextHeadersModule: any;

    // Check if we're in a Node.js environment with require
    if (typeof require !== 'undefined') {
      try {
        // Check for Next.js core availability
        require.resolve('next');
        isNextJsAvailable = true;
      } catch (error) {
        // Try alternative detection methods
      }

      if (isNextJsAvailable) {
        try {
          nextServerModule = require("next/server");
          NextRequest = nextServerModule.NextRequest;
          NextResponse = nextServerModule.NextResponse;
        } catch (error) {
          // Next.js server components not available
        }

        try {
          nextModule = require("next");
          NextApiRequest = nextModule.NextApiRequest;
          NextApiResponse = nextModule.NextApiResponse;
        } catch (error) {
          // Next.js pages router not available
        }

        try {
          nextHeadersModule = require("next/headers");
          cookies = nextHeadersModule.cookies;
        } catch (error) {
          // Next.js headers not available
          cookies = null;
        }
      }
    }

    // Method 2: Check for global Next.js objects (in browser/Edge Runtime)
    if (!isNextJsAvailable) {
      // Check if we're in a Next.js environment by looking for globals
      if (typeof globalThis !== 'undefined') {
        // Look for Next.js specific globals
        const hasNextGlobals = 
          (globalThis as any).__NEXT_DATA__ ||
          (globalThis as any).__next ||
          (globalThis as any).next;
        
        if (hasNextGlobals) {
          isNextJsAvailable = true;
        }
      }

      // Check for process.env.NEXT_RUNTIME (available in Next.js environments)
      if (typeof process !== 'undefined' && process.env?.NEXT_RUNTIME) {
        isNextJsAvailable = true;
      }

      // Check for Next.js specific environment variables
      if (typeof process !== 'undefined' && process.env?.NEXT_PUBLIC_VERCEL_URL) {
        isNextJsAvailable = true;
      }
    }

    // Method 3: Try to detect based on available APIs
    if (!isNextJsAvailable) {
      try {
        // If we can create these constructors, we might be in Next.js
        if (typeof Request !== 'undefined' && typeof Response !== 'undefined') {
          // This is a weaker signal but might indicate a Next.js environment
          // We'll mark as potentially available but won't set the flag definitively
        }
      } catch (error) {
        // Not in a Web API environment
      }
    }

    // Determine context based on available APIs
    if (isNextJsAvailable) {
      // Determine the context
      if (cookies && typeof cookies === 'function') {
        nextJsContext = 'app-router';
      } else if (NextApiRequest && NextApiResponse) {
        nextJsContext = 'pages-router';
      } else if (NextRequest && NextResponse) {
        nextJsContext = 'middleware';
      } else {
        // Try to detect context by environment
        if (typeof process !== 'undefined') {
          if (process.env.NEXT_RUNTIME === 'edge') {
            nextJsContext = 'middleware';
          } else if (process.env.NEXT_RUNTIME === 'nodejs') {
            nextJsContext = 'app-router'; // Likely App Router
          }
        }
      }
    }

    detectionComplete = true;
  } catch (error) {
    // Fallback: assume not available
    isNextJsAvailable = false;
    nextJsContext = 'unknown';
    detectionComplete = true;
  }
}

// Lazy detection function that runs when actually needed
function ensureDetection() {
  if (!detectionComplete) {
    detectNextJsEnvironment();
  }
}

// Run initial detection
detectNextJsEnvironment();

// Helper function to check if Next.js is available and provide better error messages
function ensureNextJs(feature: string) {
  // Ensure detection has run
  ensureDetection();
  
  if (!isNextJsAvailable) {
    throw new Error(
      `${feature} requires Next.js to be installed and properly configured.\n` +
      `Please check:\n` +
      `1. Next.js is installed: npm install next\n` +
      `2. You're running this code in a Next.js environment\n` +
      `3. Your bundler is configured to handle Next.js modules\n` +
      `\nIf you're using Authrix outside of Next.js, consider using the universal functions from 'authrix/universal'.`
    );
  }
  
  // Provide context-specific guidance
  if (feature.includes('NextApp') && nextJsContext !== 'app-router' && !cookies) {
    throw new Error(
      `${feature} requires Next.js App Router with 'next/headers' support. ` +
      `Current context: ${nextJsContext}. ` +
      `This function should be called from a Server Component, Server Action, or Route Handler in the App Router. ` +
      `If you're using Pages Router, use the 'NextPages' equivalent function instead. ` +
      `If you're not in a Next.js context, use the universal functions from 'authrix/universal'.`
    );
  }
}

/**
 * Get information about the detected Next.js environment
 * Useful for debugging Next.js detection issues
 */
export function getNextJsEnvironmentInfo() {
  // Ensure detection has run
  ensureDetection();
  
  return {
    isNextJsAvailable,
    context: nextJsContext,
    hasAppRouterSupport: !!cookies,
    hasPagesRouterSupport: !!(NextApiRequest && NextApiResponse),
    hasMiddlewareSupport: !!(NextRequest && NextResponse),
    detectionComplete,
    runtimeInfo: {
      hasRequire: typeof require !== 'undefined',
      hasGlobalThis: typeof globalThis !== 'undefined',
      hasProcess: typeof process !== 'undefined',
      nextRuntime: typeof process !== 'undefined' ? process.env?.NEXT_RUNTIME : undefined,
      hasNextData: typeof globalThis !== 'undefined' ? !!(globalThis as any).__NEXT_DATA__ : false
    }
  };
}

// Next.js App Router utilities

/**
 * Sign up a user in Next.js App Router
 */
export async function signupNextApp(email: string, password: string) {
  ensureNextJs("signupNextApp");
  
  const result = await signupCore(email, password);
  
  // Set cookie using Next.js cookies() function
  try {
    const cookieStore = cookies();
    cookieStore.set(authConfig.cookieName, result.token, result.cookieOptions);
  } catch (error) {
    // If cookies() fails, it might be because we're not in the right context
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Failed to set authentication cookie. This function must be called from a Server Component, ` +
      `Server Action, or Route Handler in Next.js App Router. If you're in an API route or Pages Router, ` +
      `use signupNextPages instead. Original error: ${errorMessage}`
    );
  }
  
  return result.user;
}

/**
 * Sign in a user in Next.js App Router
 */
export async function signinNextApp(email: string, password: string) {
  ensureNextJs("signinNextApp");
  
  const result = await signinCore(email, password);
  
  // Set cookie using Next.js cookies() function
  try {
    const cookieStore = cookies();
    cookieStore.set(authConfig.cookieName, result.token, result.cookieOptions);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Failed to set authentication cookie. This function must be called from a Server Component, ` +
      `Server Action, or Route Handler in Next.js App Router. If you're in an API route or Pages Router, ` +
      `use signinNextPages instead. Original error: ${errorMessage}`
    );
  }
  
  return result.user;
}

/**
 * Log out a user in Next.js App Router
 */
export function logoutNextApp() {
  ensureNextJs("logoutNextApp");
  
  const result = logoutCore();
  
  // Clear cookie using Next.js cookies() function
  try {
    const cookieStore = cookies();
    cookieStore.set(authConfig.cookieName, "", result.cookieOptions);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Failed to clear authentication cookie. This function must be called from a Server Component, ` +
      `Server Action, or Route Handler in Next.js App Router. If you're in an API route or Pages Router, ` +
      `use logoutNextPages instead. Original error: ${errorMessage}`
    );
  }
  
  return { message: result.message };
}

/**
 * Get current user in Next.js App Router
 */
export async function getCurrentUserNextApp() {
  ensureNextJs("getCurrentUserNextApp");
  
  try {
    const cookieStore = cookies();
    const token = cookieStore.get(authConfig.cookieName)?.value || null;
    return getCurrentUserFromToken(token);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Failed to read authentication cookie. This function must be called from a Server Component, ` +
      `Server Action, or Route Handler in Next.js App Router. If you're in an API route or Pages Router, ` +
      `use getCurrentUserNextPages instead. Original error: ${errorMessage}`
    );
  }
}

/**
 * Check if user is authenticated in Next.js App Router
 */
export async function isAuthenticatedNextApp(): Promise<boolean> {
  ensureNextJs("isAuthenticatedNextApp");
  
  const cookieStore = cookies();
  const token = cookieStore.get(authConfig.cookieName)?.value || null;
  return isTokenValid(token);
}

// Next.js Pages Router (API Routes) utilities

/**
 * Sign up a user in Next.js Pages Router API
 */
export async function signupNextPages(email: string, password: string, res: any) {
  const result = await signupCore(email, password);
  
  // Set cookie using Next.js API response
  res.setHeader(
    "Set-Cookie",
    `${authConfig.cookieName}=${result.token}; HttpOnly; Path=/; Max-Age=${result.cookieOptions.maxAge}; SameSite=Lax${
      result.cookieOptions.secure ? "; Secure" : ""
    }`
  );
  
  return result.user;
}

/**
 * Sign in a user in Next.js Pages Router API
 */
export async function signinNextPages(email: string, password: string, res: any) {
  const result = await signinCore(email, password);
  
  // Set cookie using Next.js API response
  res.setHeader(
    "Set-Cookie",
    `${authConfig.cookieName}=${result.token}; HttpOnly; Path=/; Max-Age=${result.cookieOptions.maxAge}; SameSite=Lax${
      result.cookieOptions.secure ? "; Secure" : ""
    }`
  );
  
  return result.user;
}

/**
 * Log out a user in Next.js Pages Router API
 */
export function logoutNextPages(res: any) {
  const result = logoutCore();
  
  // Clear cookie using Next.js API response
  res.setHeader(
    "Set-Cookie",
    `${authConfig.cookieName}=; HttpOnly; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax${
      result.cookieOptions.secure ? "; Secure" : ""
    }`
  );
  
  return { message: result.message };
}

/**
 * Get current user in Next.js Pages Router API
 */
export async function getCurrentUserNextPages(req: any) {
  const token = req.cookies[authConfig.cookieName] || null;
  return getCurrentUserFromToken(token);
}

/**
 * Check if user is authenticated in Next.js Pages Router API
 */
export async function isAuthenticatedNextPages(req: any): Promise<boolean> {
  const token = req.cookies[authConfig.cookieName] || null;
  return isTokenValid(token);
}

// Next.js Middleware utilities

/**
 * Edge Runtime compatible JWT structure validation
 * This is a lightweight check that doesn't require Node.js crypto APIs
 */
function isValidJWTStructure(token: string): boolean {
  if (!token || typeof token !== 'string') {
    return false;
  }
  
  const parts = token.split('.');
  if (parts.length !== 3) {
    return false;
  }
  
  // Check if all parts have content
  return parts.every(part => part.length > 0);
}

/**
 * Basic JWT payload extraction for Edge Runtime
 * WARNING: This does NOT verify the signature - use only for non-critical operations
 */
function extractJWTPayloadUnsafe(token: string): any {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }
    
    const payload = parts[1];
    // Add padding if needed for base64 decoding
    const padded = payload + '='.repeat((4 - payload.length % 4) % 4);
    const decoded = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(decoded);
  } catch (error) {
    return null;
  }
}

/**
 * Edge Runtime compatible basic token expiration check
 * WARNING: This does NOT verify the signature - use only for non-critical operations
 */
function isTokenExpiredUnsafe(token: string): boolean {
  const payload = extractJWTPayloadUnsafe(token);
  if (!payload || !payload.exp) {
    return true; // Consider invalid tokens as expired
  }
  
  const now = Math.floor(Date.now() / 1000);
  return payload.exp < now;
}

/**
 * Check authentication in Next.js middleware (Edge Runtime Compatible)
 * This version only performs basic token structure validation and expiration checks
 * without verifying the JWT signature or making database calls
 */
export async function checkAuthMiddleware(request: any, options: { 
  cookieName?: string;
} = {}) {
  const cookieName = options.cookieName || getSafeCookieName();
  const token = request.cookies.get(cookieName)?.value || null;
  
  // Basic token validation for Edge Runtime
  if (!token) {
    return {
      isAuthenticated: false,
      user: null,
      reason: 'No token provided'
    };
  }
  
  // Check JWT structure
  if (!isValidJWTStructure(token)) {
    return {
      isAuthenticated: false,
      user: null,
      reason: 'Invalid token structure'
    };
  }
  
  // Check expiration (without signature verification)
  if (isTokenExpiredUnsafe(token)) {
    return {
      isAuthenticated: false,
      user: null,
      reason: 'Token expired'
    };
  }
  
  // Extract user info from token (without signature verification)
  const payload = extractJWTPayloadUnsafe(token);
  const user = payload ? {
    id: payload.id,
    email: payload.email,
    createdAt: payload.createdAt ? new Date(payload.createdAt) : undefined
  } : null;
  
  return {
    isAuthenticated: !!user,
    user,
    reason: user ? 'Token appears valid' : 'Invalid token payload'
  };
}

/**
 * Edge Runtime compatible middleware function that validates tokens server-side
 * This version makes an API call to validate the token properly with signature verification
 */
export async function checkAuthMiddlewareSecure(request: any, options: { 
  validationEndpoint?: string;
  timeout?: number;
  cookieName?: string;
} = {}) {
  const cookieName = options.cookieName || getSafeCookieName();
  const token = request.cookies.get(cookieName)?.value || null;
  
  if (!token) {
    return {
      isAuthenticated: false,
      user: null,
      reason: 'No token provided'
    };
  }
  
  // Basic structure check first
  if (!isValidJWTStructure(token)) {
    return {
      isAuthenticated: false,
      user: null,
      reason: 'Invalid token structure'
    };
  }
  
  try {
    // Validate token via API call
    const validationUrl = options.validationEndpoint || '/api/auth/validate';
    const baseUrl = request.nextUrl.origin;
    
    // Create AbortController for timeout - Edge Runtime compatible
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      controller.abort();
    }, options.timeout || 5000);
    
    const response = await fetch(`${baseUrl}${validationUrl}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      signal: controller.signal
    });
    
    // Clear timeout if request completes successfully
    clearTimeout(timeoutId);
    
    if (response.ok) {
      const data = await response.json();
      return {
        isAuthenticated: true,
        user: data.user,
        reason: 'Token validated via API'
      };
    } else {
      return {
        isAuthenticated: false,
        user: null,
        reason: 'Token validation failed'
      };
    }
  } catch (error) {
    // Fallback to basic validation if API call fails
    const payload = extractJWTPayloadUnsafe(token);
    const user = payload ? {
      id: payload.id,
      email: payload.email,
      createdAt: payload.createdAt ? new Date(payload.createdAt) : undefined
    } : null;
    
    return {
      isAuthenticated: !!user,
      user,
      reason: 'Fallback validation (API unavailable)'
    };
  }
}

// Higher-order function for protecting Next.js API routes
export function withAuth<T extends Record<string, any>, U extends Record<string, any>>(
  handler: (req: T & { user: { id: string; email: string; createdAt?: Date } }, res: U) => Promise<void> | void
) {
  return async (req: T, res: U) => {
    try {
      const user = await getCurrentUserNextPages(req);
      
      if (!user) {
        return (res as any).status(401).json({ 
          success: false, 
          error: { message: "Authentication required" }
        });
      }
      
      // Add user to request object
      (req as any).user = user;
      
      return handler(req as T & { user: typeof user }, res);
    } catch (error) {
      console.error("Authentication error:", error);
      return (res as any).status(500).json({ 
        success: false, 
        error: { message: "Authentication failed" }
      });
    }
  };
}

// === FLEXIBLE NEXT.JS FUNCTIONS ===
// These functions provide better compatibility across different Next.js contexts

/**
 * Flexible Next.js signup that works in both App Router and Pages Router
 * Automatically detects the context and uses the appropriate method
 */
export async function signupNextFlexible(email: string, password: string, res?: any) {
  ensureDetection();
  
  if (!isNextJsAvailable) {
    throw new Error(
      "Next.js is not available. Please install Next.js: npm install next\n" +
      "If you're not using Next.js, consider using 'signupUniversal' from 'authrix/universal'."
    );
  }

  const result = await signupCore(email, password);
  
  // Try App Router first (if cookies is available)
  if (cookies && !res) {
    try {
      const cookieStore = cookies();
      cookieStore.set(authConfig.cookieName, result.token, result.cookieOptions);
      return result.user;
    } catch (error) {
      // If App Router fails, continue to Pages Router method
      console.warn("App Router cookie setting failed, falling back to Pages Router method");
    }
  }
  
  // Fall back to Pages Router method if res is provided or App Router failed
  if (res && res.setHeader) {
    res.setHeader(
      "Set-Cookie",
      `${authConfig.cookieName}=${result.token}; HttpOnly; Path=/; Max-Age=${result.cookieOptions.maxAge}; SameSite=Lax${
        result.cookieOptions.secure ? "; Secure" : ""
      }`
    );
    return result.user;
  }
  
  // If neither method works, suggest using universal functions
  throw new Error(
    "Unable to set authentication cookie. This function requires either Next.js App Router context " +
    "or a response object for Pages Router. Consider using 'signupUniversal' from 'authrix/universal' " +
    "for manual cookie handling.\n\n" +
    `Current Next.js context: ${nextJsContext}\n` +
    `Environment info: ${JSON.stringify(getNextJsEnvironmentInfo(), null, 2)}`
  );
}

/**
 * Flexible Next.js signin that works in both App Router and Pages Router
 */
export async function signinNextFlexible(email: string, password: string, res?: any) {
  ensureDetection();
  
  if (!isNextJsAvailable) {
    throw new Error(
      "Next.js is not available. Please install Next.js: npm install next\n" +
      "If you're not using Next.js, consider using 'signinUniversal' from 'authrix/universal'."
    );
  }

  const result = await signinCore(email, password);
  
  // Try App Router first (if cookies is available)
  if (cookies && !res) {
    try {
      const cookieStore = cookies();
      cookieStore.set(authConfig.cookieName, result.token, result.cookieOptions);
      return result.user;
    } catch (error) {
      // If App Router fails, continue to Pages Router method
      console.warn("App Router cookie setting failed, falling back to Pages Router method");
    }
  }
  
  // Fall back to Pages Router method if res is provided or App Router failed
  if (res && res.setHeader) {
    res.setHeader(
      "Set-Cookie",
      `${authConfig.cookieName}=${result.token}; HttpOnly; Path=/; Max-Age=${result.cookieOptions.maxAge}; SameSite=Lax${
        result.cookieOptions.secure ? "; Secure" : ""
      }`
    );
    return result.user;
  }
  
  throw new Error(
    "Unable to set authentication cookie. This function requires either Next.js App Router context " +
    "or a response object for Pages Router. Consider using 'signinUniversal' from 'authrix/universal' " +
    "for manual cookie handling.\n\n" +
    `Current Next.js context: ${nextJsContext}\n` +
    `Environment info: ${JSON.stringify(getNextJsEnvironmentInfo(), null, 2)}`
  );
}

/**
 * Flexible Next.js get current user that works in both App Router and Pages Router
 */
export async function getCurrentUserNextFlexible(req?: any) {
  ensureDetection();
  
  if (!isNextJsAvailable) {
    throw new Error(
      "Next.js is not available. Please install Next.js: npm install next\n" +
      "If you're not using Next.js, consider using 'validateAuth' from 'authrix/universal'."
    );
  }

  // Try App Router first (if cookies is available)
  if (cookies && !req) {
    try {
      const cookieStore = cookies();
      const token = cookieStore.get(authConfig.cookieName)?.value || null;
      return getCurrentUserFromToken(token);
    } catch (error) {
      // If App Router fails, continue to manual method
      console.warn("App Router cookie reading failed, falling back to Pages Router method");
    }
  }
  
  // Fall back to Pages Router method if req is provided or App Router failed
  if (req && req.cookies) {
    const token = req.cookies[authConfig.cookieName] || null;
    return getCurrentUserFromToken(token);
  }
  
  throw new Error(
    "Unable to read authentication cookie. This function requires either Next.js App Router context " +
    "or a request object for Pages Router. Consider using 'validateAuth' from 'authrix/universal' " +
    "with manual token extraction.\n\n" +
    `Current Next.js context: ${nextJsContext}\n` +
    `Environment info: ${JSON.stringify(getNextJsEnvironmentInfo(), null, 2)}`
  );
}

/**
 * Create an authenticated NextResponse with user info
 */
export function createAuthenticatedResponse(
  response: any,
  user: { id: string; email: string; createdAt?: Date }
) {
  // Add user info to response headers for downstream consumption
  response.headers.set("x-user-id", user.id);
  response.headers.set("x-user-email", user.email);
  return response;
}

/**
 * Helper function to create API validation endpoint for secure middleware
 * Use this in your API route to validate tokens server-side
 * 
 * Example usage in pages/api/auth/validate.ts or app/api/auth/validate/route.ts:
 * 
 * ```typescript
 * import { createTokenValidationHandler } from 'authrix/nextjs';
 * 
 * export const POST = createTokenValidationHandler();
 * ```
 */
export function createTokenValidationHandler() {
  return async function handler(request: Request) {
    try {
      const authHeader = request.headers.get('Authorization');
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return Response.json(
          { success: false, error: 'Authorization header required' },
          { status: 401 }
        );
      }
      
      const token = authHeader.slice(7);
      const user = await getCurrentUserFromToken(token);
      
      if (!user) {
        return Response.json(
          { success: false, error: 'Invalid token' },
          { status: 401 }
        );
      }
      
      return Response.json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          createdAt: user.createdAt
        }
      });
    } catch (error) {
      return Response.json(
        { success: false, error: 'Token validation failed' },
        { status: 500 }
      );
    }
  };
}

/**
 * Pages Router version of token validation handler
 * 
 * Example usage in pages/api/auth/validate.ts:
 * 
 * ```typescript
 * import { createTokenValidationHandlerPages } from 'authrix/nextjs';
 * 
 * export default createTokenValidationHandlerPages();
 * ```
 */
export function createTokenValidationHandlerPages() {
  return async function handler(req: any, res: any) {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }
    
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          success: false,
          error: 'Authorization header required'
        });
      }
      
      const token = authHeader.slice(7);
      const user = await getCurrentUserFromToken(token);
      
      if (!user) {
        return res.status(401).json({
          success: false,
          error: 'Invalid token'
        });
      }
      
      return res.json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          createdAt: user.createdAt
        }
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        error: 'Token validation failed'
      });
    }
  };
}

/**
 * Manually re-run Next.js environment detection
 * Useful when the environment might have changed or for debugging detection issues
 */
export function redetectNextJsEnvironment() {
  detectionComplete = false;
  isNextJsAvailable = false;
  nextJsContext = 'unknown';
  NextRequest = NextResponse = NextApiRequest = NextApiResponse = cookies = undefined;
  
  detectNextJsEnvironment();
  
  return getNextJsEnvironmentInfo();
}

/**
 * Force Next.js availability (use with caution)
 * This can be used to override detection in environments where automatic detection fails
 */
export function forceNextJsAvailability(
  available: boolean, 
  context?: 'app-router' | 'pages-router' | 'middleware' | 'unknown'
) {
  isNextJsAvailable = available;
  if (context) {
    nextJsContext = context;
  }
  detectionComplete = true;
  
  console.warn(
    `Next.js availability manually set to: ${available}${context ? `, context: ${context}` : ''}\n` +
    'This should only be used for debugging or in environments where automatic detection fails.'
  );
}
