// Next.js utilities for Authrix
// These imports are optional and will only work when Next.js is available

import { signupCore } from "../core/signup";
import { signinCore } from "../core/signin";
import { logoutCore } from "../core/logout";
import { getCurrentUserFromToken, isTokenValid } from "../core/session";
import { authConfig } from "../config";

let NextRequest: any, NextResponse: any, NextApiRequest: any, NextApiResponse: any, cookies: any;

/**
 * Safely import Next.js headers module
 * This avoids eval() while still providing dynamic imports
 */
function getNextHeaders(): any {
  try {
    // Use dynamic require to avoid bundler warnings
    const requireFunc = typeof require !== 'undefined' ? require : null;
    if (!requireFunc) {
      throw new Error('require is not available');
    }
    return requireFunc('next/headers');
  } catch (error) {
    throw new Error(
      `Next.js App Router functions require 'next/headers' to be available. ` +
      `Make sure you're using Next.js 13+ with App Router and this function is called within a Server Component or API Route. ` +
      `Original error: ${error instanceof Error ? error.message : 'Unknown error'}`
    );
  }
}
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
  try {
    const result = await signupCore(email, password);
    
    // Try to import and use cookies() dynamically
    try {
      // Use require for better compatibility
      const nextHeaders = require("next/headers");
      const cookieStore = nextHeaders.cookies();
      cookieStore.set(authConfig.cookieName, result.token, result.cookieOptions);
      return result.user;
    } catch (importError) {
      // If next/headers fails to import, throw a helpful error
      throw new Error(
        `Next.js App Router functions require 'next/headers' to be available. ` +
        `This function must be called from a Server Component, Server Action, or Route Handler in Next.js App Router. ` +
        `If you're in an API route or Pages Router, use signupNextPages instead. ` +
        `If you want to handle cookies manually, use signupCore and handle the cookie setting yourself.`
      );
    }
  } catch (error) {
    // Re-throw with context if it's not already our custom error
    if (error instanceof Error && error.message.includes('next/headers')) {
      throw error;
    }
    throw new Error(`Signup failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Sign in a user in Next.js App Router
 */
export async function signinNextApp(email: string, password: string) {
  try {
    const result = await signinCore(email, password);
    
    // Try to import and use cookies() dynamically
    try {
      // Use require for better compatibility
      const nextHeaders = require("next/headers");
      const cookieStore = nextHeaders.cookies();
      cookieStore.set(authConfig.cookieName, result.token, result.cookieOptions);
      return result.user;
    } catch (importError) {
      // If next/headers fails to import, throw a helpful error
      throw new Error(
        `Next.js App Router functions require 'next/headers' to be available. ` +
        `This function must be called from a Server Component, Server Action, or Route Handler in Next.js App Router. ` +
        `If you're in an API route or Pages Router, use signinNextPages instead. ` +
        `If you want to handle cookies manually, use signinCore and handle the cookie setting yourself.`
      );
    }
  } catch (error) {
    // Re-throw with context if it's not already our custom error
    if (error instanceof Error && error.message.includes('next/headers')) {
      throw error;
    }
    throw new Error(`Signin failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Log out a user in Next.js App Router
 */
export function logoutNextApp() {
  try {
    const result = logoutCore();
    
    // Try to import and use cookies() dynamically
    try {
      // Use safe dynamic import instead of eval
      const nextHeaders = getNextHeaders();
      const cookieStore = nextHeaders.cookies();
      cookieStore.set(authConfig.cookieName, "", result.cookieOptions);
      return { message: result.message };
    } catch (importError) {
      // If next/headers fails to import, throw a helpful error
      throw new Error(
        `Next.js App Router functions require 'next/headers' to be available. ` +
        `This function must be called from a Server Component, Server Action, or Route Handler in Next.js App Router. ` +
        `If you're in an API route or Pages Router, use logoutNextPages instead. ` +
        `If you want to handle cookies manually, use logoutCore and handle the cookie clearing yourself.`
      );
    }
  } catch (error) {
    // Re-throw with context if it's not already our custom error
    if (error instanceof Error && error.message.includes('next/headers')) {
      throw error;
    }
    throw new Error(`Logout failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Get current user in Next.js App Router
 */
export async function getCurrentUserNextApp() {
  try {
    // Try to import and use cookies() dynamically
    try {
      // Use safe dynamic import instead of eval
      const nextHeaders = getNextHeaders();
      const cookieStore = nextHeaders.cookies();
      const token = cookieStore.get(authConfig.cookieName)?.value || null;
      return getCurrentUserFromToken(token);
    } catch (importError) {
      // If next/headers fails to import, throw a helpful error
      throw new Error(
        `Next.js App Router functions require 'next/headers' to be available. ` +
        `This function must be called from a Server Component, Server Action, or Route Handler in Next.js App Router. ` +
        `If you're in an API route or Pages Router, use getCurrentUserNextPages instead. ` +
        `If you want to handle token extraction manually, use getCurrentUserFromToken with manual token extraction.`
      );
    }
  } catch (error) {
    // Re-throw with context if it's not already our custom error
    if (error instanceof Error && error.message.includes('next/headers')) {
      throw error;
    }
    throw new Error(`Get current user failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Check if user is authenticated in Next.js App Router
 */
export async function isAuthenticatedNextApp(): Promise<boolean> {
  try {
    // Try to import and use cookies() dynamically
    try {
      // Use safe dynamic import instead of eval
      const nextHeaders = getNextHeaders();
      const cookieStore = nextHeaders.cookies();
      const token = cookieStore.get(authConfig.cookieName)?.value || null;
      return isTokenValid(token);
    } catch (importError) {
      // If next/headers fails to import, return false
      console.warn('Next.js headers not available, assuming not authenticated');
      return false;
    }
  } catch (error) {
    console.error('Authentication check failed:', error);
    return false;
  }
}

// Next.js Pages Router (API Routes) utilities

/**
 * Sign up a user in Next.js Pages Router API
 */
export async function signupNextPages(email: string, password: string, res: any) {
  try {
    const result = await signupCore(email, password);
    
    if (!res || typeof res.setHeader !== 'function') {
      throw new Error(
        'signupNextPages requires a valid Next.js API response object. ' +
        'Make sure you are calling this function from within a Next.js API route handler. ' +
        'If you want to handle cookies manually, use signupCore instead.'
      );
    }
    
    // Set cookie using Next.js API response
    res.setHeader(
      "Set-Cookie",
      `${authConfig.cookieName}=${result.token}; HttpOnly; Path=/; Max-Age=${result.cookieOptions.maxAge}; SameSite=Lax${
        result.cookieOptions.secure ? "; Secure" : ""
      }`
    );
    
    return result.user;
  } catch (error) {
    throw new Error(`Signup failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Sign in a user in Next.js Pages Router API
 */
export async function signinNextPages(email: string, password: string, res: any) {
  try {
    const result = await signinCore(email, password);
    
    if (!res || typeof res.setHeader !== 'function') {
      throw new Error(
        'signinNextPages requires a valid Next.js API response object. ' +
        'Make sure you are calling this function from within a Next.js API route handler. ' +
        'If you want to handle cookies manually, use signinCore instead.'
      );
    }
    
    // Set cookie using Next.js API response
    res.setHeader(
      "Set-Cookie",
      `${authConfig.cookieName}=${result.token}; HttpOnly; Path=/; Max-Age=${result.cookieOptions.maxAge}; SameSite=Lax${
        result.cookieOptions.secure ? "; Secure" : ""
      }`
    );
    
    return result.user;
  } catch (error) {
    throw new Error(`Signin failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Log out a user in Next.js Pages Router API
 */
export function logoutNextPages(res: any) {
  try {
    const result = logoutCore();
    
    if (!res || typeof res.setHeader !== 'function') {
      throw new Error(
        'logoutNextPages requires a valid Next.js API response object. ' +
        'Make sure you are calling this function from within a Next.js API route handler. ' +
        'If you want to handle cookies manually, use logoutCore instead.'
      );
    }
    
    // Clear cookie using Next.js API response
    res.setHeader(
      "Set-Cookie",
      `${authConfig.cookieName}=; HttpOnly; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax${
        result.cookieOptions.secure ? "; Secure" : ""
      }`
    );
    
    return { message: result.message };
  } catch (error) {
    throw new Error(`Logout failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Get current user in Next.js Pages Router API
 */
export async function getCurrentUserNextPages(req: any) {
  try {
    if (!req || !req.cookies) {
      throw new Error(
        'getCurrentUserNextPages requires a valid Next.js API request object with cookies. ' +
        'Make sure you are calling this function from within a Next.js API route handler. ' +
        'If you want to handle token extraction manually, use getCurrentUserFromToken instead.'
      );
    }
    
    const token = req.cookies[authConfig.cookieName] || null;
    return getCurrentUserFromToken(token);
  } catch (error) {
    throw new Error(`Get current user failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Check if user is authenticated in Next.js Pages Router API
 */
export async function isAuthenticatedNextPages(req: any): Promise<boolean> {
  try {
    if (!req || !req.cookies) {
      console.warn('isAuthenticatedNextPages: Invalid request object, assuming not authenticated');
      return false;
    }
    
    const token = req.cookies[authConfig.cookieName] || null;
    return isTokenValid(token);
  } catch (error) {
    console.error('Authentication check failed:', error);
    return false;
  }
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
  try {
    const result = await signupCore(email, password);
    
    // If res is provided, use Pages Router method
    if (res && typeof res.setHeader === 'function') {
      res.setHeader(
        "Set-Cookie",
        `${authConfig.cookieName}=${result.token}; HttpOnly; Path=/; Max-Age=${result.cookieOptions.maxAge}; SameSite=Lax${
          result.cookieOptions.secure ? "; Secure" : ""
        }`
      );
      return result.user;
    }
    
    // Try App Router method (next/headers)
    try {
      // Use safe dynamic import instead of eval
      const nextHeaders = getNextHeaders();
      const cookieStore = nextHeaders.cookies();
      cookieStore.set(authConfig.cookieName, result.token, result.cookieOptions);
      return result.user;
    } catch (importError) {
      // If both methods fail, provide guidance
      throw new Error(
        'Unable to set authentication cookie. This function requires either:\n' +
        '1. A Next.js API response object (Pages Router): signupNextFlexible(email, password, res)\n' +
        '2. Next.js App Router context (Server Component/Action/Route Handler)\n\n' +
        'Alternative: Use signupCore() and handle cookie setting manually:\n' +
        'const result = await signupCore(email, password);\n' +
        '// Then set result.token as a cookie manually'
      );
    }
  } catch (error) {
    throw new Error(`Signup failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Flexible Next.js signin that works in both App Router and Pages Router
 */
export async function signinNextFlexible(email: string, password: string, res?: any) {
  try {
    const result = await signinCore(email, password);
    
    // If res is provided, use Pages Router method
    if (res && typeof res.setHeader === 'function') {
      res.setHeader(
        "Set-Cookie",
        `${authConfig.cookieName}=${result.token}; HttpOnly; Path=/; Max-Age=${result.cookieOptions.maxAge}; SameSite=Lax${
          result.cookieOptions.secure ? "; Secure" : ""
        }`
      );
      return result.user;
    }
    
    // Try App Router method (next/headers)
    try {
      // Use safe dynamic import instead of eval
      const nextHeaders = getNextHeaders();
      const cookieStore = nextHeaders.cookies();
      cookieStore.set(authConfig.cookieName, result.token, result.cookieOptions);
      return result.user;
    } catch (importError) {
      // If both methods fail, provide guidance
      throw new Error(
        'Unable to set authentication cookie. This function requires either:\n' +
        '1. A Next.js API response object (Pages Router): signinNextFlexible(email, password, res)\n' +
        '2. Next.js App Router context (Server Component/Action/Route Handler)\n\n' +
        'Alternative: Use signinCore() and handle cookie setting manually:\n' +
        'const result = await signinCore(email, password);\n' +
        '// Then set result.token as a cookie manually'
      );
    }
  } catch (error) {
    throw new Error(`Signin failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Flexible Next.js get current user that works in both App Router and Pages Router
 */
export async function getCurrentUserNextFlexible(req?: any) {
  try {
    // If req is provided, use Pages Router method
    if (req && req.cookies) {
      const token = req.cookies[authConfig.cookieName] || null;
      return getCurrentUserFromToken(token);
    }
    
    // Try App Router method (next/headers)
    try {
      // Use safe dynamic import instead of eval
      const nextHeaders = getNextHeaders();
      const cookieStore = nextHeaders.cookies();
      const token = cookieStore.get(authConfig.cookieName)?.value || null;
      return getCurrentUserFromToken(token);
    } catch (importError) {
      // If both methods fail, provide guidance
      throw new Error(
        'Unable to read authentication cookie. This function requires either:\n' +
        '1. A Next.js API request object (Pages Router): getCurrentUserNextFlexible(req)\n' +
        '2. Next.js App Router context (Server Component/Action/Route Handler)\n\n' +
        'Alternative: Extract the token manually and use getCurrentUserFromToken(token)'
      );
    }
  } catch (error) {
    throw new Error(`Get current user failed: ${error instanceof Error ? error.message : String(error)}`);
  }
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

// === SIMPLIFIED PRODUCTION-READY FUNCTIONS ===
// These functions provide direct access to the core functionality
// without complex environment detection for better production reliability

/**
 * Simple Next.js signup for App Router - uses dynamic import
 * Call this from Server Components, Server Actions, or Route Handlers
 */
export async function signupNext(email: string, password: string) {
  const result = await signupCore(email, password);
  
  try {
    // Use require for better compatibility
    const nextHeaders = require("next/headers");
    const cookieStore = nextHeaders.cookies();
    cookieStore.set(authConfig.cookieName, result.token, result.cookieOptions);
    return result.user;
  } catch (error) {
    throw new Error(
      `Failed to set authentication cookie. Make sure you're calling this from a Next.js App Router context ` +
      `(Server Component, Server Action, or Route Handler). ` +
      `For Pages Router, use signupNextPages(email, password, res) instead. ` +
      `For manual cookie handling, use signupCore(email, password) and handle the cookie yourself.`
    );
  }
}

/**
 * Simple Next.js signin for App Router - uses dynamic import
 * Call this from Server Components, Server Actions, or Route Handlers
 */
export async function signinNext(email: string, password: string) {
  const result = await signinCore(email, password);
  
  try {
    // Use require for better compatibility
    const nextHeaders = require("next/headers");
    const cookieStore = nextHeaders.cookies();
    cookieStore.set(authConfig.cookieName, result.token, result.cookieOptions);
    return result.user;
  } catch (error) {
    throw new Error(
      `Failed to set authentication cookie. Make sure you're calling this from a Next.js App Router context ` +
      `(Server Component, Server Action, or Route Handler). ` +
      `For Pages Router, use signinNextPages(email, password, res) instead. ` +
      `For manual cookie handling, use signinCore(email, password) and handle the cookie yourself.`
    );
  }
}

/**
 * Simple Next.js logout for App Router - uses dynamic import
 * Call this from Server Components, Server Actions, or Route Handlers
 */
export function logoutNext() {
  const result = logoutCore();
  
  try {
    // Dynamic import to avoid build-time errors
    const { cookies } = require("next/headers");
    const cookieStore = cookies();
    cookieStore.set(authConfig.cookieName, "", result.cookieOptions);
    return { message: result.message };
  } catch (error) {
    throw new Error(
      `Failed to clear authentication cookie. Make sure you're calling this from a Next.js App Router context ` +
      `(Server Component, Server Action, or Route Handler). ` +
      `For Pages Router, use logoutNextPages(res) instead. ` +
      `For manual cookie handling, use logoutCore() and handle the cookie yourself.`
    );
  }
}

/**
 * Simple Next.js get current user for App Router - uses dynamic import
 * Call this from Server Components, Server Actions, or Route Handlers
 */
export async function getCurrentUserNext() {
  try {
    // Dynamic import to avoid build-time errors
    const { cookies } = require("next/headers");
    const cookieStore = cookies();
    const token = cookieStore.get(authConfig.cookieName)?.value || null;
    return getCurrentUserFromToken(token);
  } catch (error) {
    throw new Error(
      `Failed to read authentication cookie. Make sure you're calling this from a Next.js App Router context ` +
      `(Server Component, Server Action, or Route Handler). ` +
      `For Pages Router, use getCurrentUserNextPages(req) instead. ` +
      `For manual token handling, extract the token yourself and use getCurrentUserFromToken(token).`
    );
  }
}

/**
 * Production-ready authentication check that always works
 * Returns false instead of throwing errors for better UX
 */
export async function isAuthenticatedNext(): Promise<boolean> {
  try {
    // Try Next.js App Router first
    const { cookies } = require("next/headers");
    const cookieStore = cookies();
    const token = cookieStore.get(authConfig.cookieName)?.value || null;
    return isTokenValid(token);
  } catch (error) {
    // Silently return false if Next.js headers aren't available
    return false;
  }
}

// === MANUAL COOKIE HELPERS ===
// For when you want full control over cookie handling

/**
 * Helper to create cookie string for manual setting
 * Use this when you want to handle cookie setting manually
 */
export function createAuthCookieString(token: string, options?: { 
  secure?: boolean; 
  maxAge?: number; 
  sameSite?: string; 
  path?: string; 
}) {
  const cookieOptions = {
    secure: options?.secure ?? (process.env.NODE_ENV === "production"),
    maxAge: options?.maxAge ?? (1000 * 60 * 60 * 24 * 7), // 7 days
    sameSite: options?.sameSite ?? "lax",
    path: options?.path ?? "/",
  };
  
  return `${authConfig.cookieName}=${token}; HttpOnly; Path=${cookieOptions.path}; Max-Age=${cookieOptions.maxAge}; SameSite=${cookieOptions.sameSite}${
    cookieOptions.secure ? "; Secure" : ""
  }`;
}

/**
 * Helper to create logout cookie string for manual clearing
 */
export function createLogoutCookieString(options?: { 
  secure?: boolean; 
  sameSite?: string; 
  path?: string; 
}) {
  const cookieOptions = {
    secure: options?.secure ?? (process.env.NODE_ENV === "production"),
    sameSite: options?.sameSite ?? "lax",
    path: options?.path ?? "/",
  };
  
  return `${authConfig.cookieName}=; HttpOnly; Path=${cookieOptions.path}; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=${cookieOptions.sameSite}${
    cookieOptions.secure ? "; Secure" : ""
  }`;
}
