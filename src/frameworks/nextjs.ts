// Next.js utilities for Authrix
// These imports are optional and will only work when Next.js is available

let NextRequest: any, NextResponse: any, NextApiRequest: any, NextApiResponse: any, cookies: any;

try {
  // Dynamic imports to handle cases where Next.js is not installed
  const nextServer = require("next/server");
  NextRequest = nextServer.NextRequest;
  NextResponse = nextServer.NextResponse;
} catch (error) {
  // Next.js server components not available
}

try {
  const next = require("next");
  NextApiRequest = next.NextApiRequest;
  NextApiResponse = next.NextApiResponse;
} catch (error) {
  // Next.js not available
}

try {
  const nextHeaders = require("next/headers");
  cookies = nextHeaders.cookies;
} catch (error) {
  // Next.js headers not available
}

import { signupCore } from "../core/signup";
import { signinCore } from "../core/signin";
import { logoutCore } from "../core/logout";
import { getCurrentUserFromToken, isTokenValid } from "../core/session";
import { authConfig } from "../config";

// Helper function to check if Next.js is available
function ensureNextJs(feature: string) {
  if (!cookies) {
    throw new Error(`${feature} requires Next.js to be installed. Please install Next.js: npm install next`);
  }
}

// Next.js App Router utilities

/**
 * Sign up a user in Next.js App Router
 */
export async function signupNextApp(email: string, password: string) {
  ensureNextJs("signupNextApp");
  
  const result = await signupCore(email, password);
  
  // Set cookie using Next.js cookies() function
  const cookieStore = cookies();
  cookieStore.set(authConfig.cookieName, result.token, result.cookieOptions);
  
  return result.user;
}

/**
 * Sign in a user in Next.js App Router
 */
export async function signinNextApp(email: string, password: string) {
  ensureNextJs("signinNextApp");
  
  const result = await signinCore(email, password);
  
  // Set cookie using Next.js cookies() function
  const cookieStore = cookies();
  cookieStore.set(authConfig.cookieName, result.token, result.cookieOptions);
  
  return result.user;
}

/**
 * Log out a user in Next.js App Router
 */
export function logoutNextApp() {
  ensureNextJs("logoutNextApp");
  
  const result = logoutCore();
  
  // Clear cookie using Next.js cookies() function
  const cookieStore = cookies();
  cookieStore.set(authConfig.cookieName, "", result.cookieOptions);
  
  return { message: result.message };
}

/**
 * Get current user in Next.js App Router
 */
export async function getCurrentUserNextApp() {
  ensureNextJs("getCurrentUserNextApp");
  
  const cookieStore = cookies();
  const token = cookieStore.get(authConfig.cookieName)?.value || null;
  return getCurrentUserFromToken(token);
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
 * Check authentication in Next.js middleware
 */
export async function checkAuthMiddleware(request: any) {
  const token = request.cookies.get(authConfig.cookieName)?.value || null;
  const isValid = await isTokenValid(token);
  
  return {
    isAuthenticated: isValid,
    user: isValid ? await getCurrentUserFromToken(token) : null
  };
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
