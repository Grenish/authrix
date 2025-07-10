// Next.js types are optional dependencies - they will be available when used in Next.js projects
// @ts-ignore
import type { NextRequest, NextResponse } from "next/server";
// @ts-ignore
import type { NextApiRequest, NextApiResponse } from "next";
// @ts-ignore
import { cookies } from "next/headers";

import { signupCore } from "../core/signup";
import { signinCore } from "../core/signin";
import { logoutCore } from "../core/logout";
import { getCurrentUserFromToken, isTokenValid } from "../core/session";
import { authConfig } from "../config";

// Next.js App Router utilities

/**
 * Sign up a user in Next.js App Router
 */
export async function signupNextApp(email: string, password: string) {
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
  const cookieStore = cookies();
  const token = cookieStore.get(authConfig.cookieName)?.value || null;
  return getCurrentUserFromToken(token);
}

/**
 * Check if user is authenticated in Next.js App Router
 */
export async function isAuthenticatedNextApp(): Promise<boolean> {
  const cookieStore = cookies();
  const token = cookieStore.get(authConfig.cookieName)?.value || null;
  return isTokenValid(token);
}

// Next.js Pages Router (API Routes) utilities

/**
 * Sign up a user in Next.js Pages Router API
 */
export async function signupNextPages(email: string, password: string, res: NextApiResponse) {
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
export async function signinNextPages(email: string, password: string, res: NextApiResponse) {
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
export function logoutNextPages(res: NextApiResponse) {
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
export async function getCurrentUserNextPages(req: NextApiRequest) {
  const token = req.cookies[authConfig.cookieName] || null;
  return getCurrentUserFromToken(token);
}

/**
 * Check if user is authenticated in Next.js Pages Router API
 */
export async function isAuthenticatedNextPages(req: NextApiRequest): Promise<boolean> {
  const token = req.cookies[authConfig.cookieName] || null;
  return isTokenValid(token);
}

// Next.js Middleware utilities

/**
 * Check authentication in Next.js middleware
 */
export async function checkAuthMiddleware(request: NextRequest) {
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
  response: NextResponse,
  user: { id: string; email: string; createdAt?: Date }
) {
  // Add user info to response headers for downstream consumption
  response.headers.set("x-user-id", user.id);
  response.headers.set("x-user-email", user.email);
  return response;
}

// Higher-order function for protecting Next.js API routes
export function withAuth<T extends NextApiRequest, U extends NextApiResponse>(
  handler: (req: T & { user: { id: string; email: string; createdAt?: Date } }, res: U) => Promise<void> | void
) {
  return async (req: T, res: U) => {
    try {
      const user = await getCurrentUserNextPages(req);
      
      if (!user) {
        return res.status(401).json({ 
          success: false, 
          error: { message: "Authentication required" }
        });
      }
      
      // Add user to request object
      (req as any).user = user;
      
      return handler(req as T & { user: typeof user }, res);
    } catch (error) {
      console.error("Authentication error:", error);
      return res.status(500).json({ 
        success: false, 
        error: { message: "Authentication failed" }
      });
    }
  };
}
