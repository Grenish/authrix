// Framework-agnostic utilities for any JavaScript/TypeScript framework

import { signupCore } from "../core/signup";
import { signinCore } from "../core/signin";
import { logoutCore } from "../core/logout";
import { getCurrentUserFromToken, isTokenValid } from "../core/session";
import { authConfig } from "../config";

export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  maxAge?: number;
  sameSite?: "strict" | "lax" | "none";
  path?: string;
  expires?: Date;
}

export interface AuthResult {
  user: { id: string; email: string };
  token: string;
  cookieOptions: CookieOptions;
}

export interface AuthErrorResult {
  success: false;
  error: { message: string };
}

export type AuthResponse = AuthResult | AuthErrorResult;

export interface UniversalLogoutResult {
  success: boolean;
  message: string;
  cookiesToClear: Array<{
    name: string;
    options: {
      httpOnly: boolean;
      secure: boolean;
      sameSite: "lax" | "strict" | "none";
      path: string;
      expires: Date;
      domain?: string;
    };
  }>;
  redirectUrl?: string;
}

/**
 * Framework-agnostic signup function
 * Returns user data, token, and cookie options for manual handling
 */
export async function signupUniversal(email: string, password: string): Promise<AuthResponse> {
  try {
    return await signupCore(email, password);
  } catch (error) {
    return errorResponse(error, 'Signup failed');
  }
}

/**
 * Framework-agnostic signin function
 * Returns user data, token, and cookie options for manual handling
 */
export async function signinUniversal(email: string, password: string): Promise<AuthResponse> {
  try {
    return await signinCore(email, password);
  } catch (error) {
    return errorResponse(error, 'Signin failed');
  }
}

/**
 * Framework-agnostic logout function
 * Returns cookie information for manual clearing
 */
export function logoutUniversal(): UniversalLogoutResult {
  return logoutCore();
}

/**
 * Helper function to get cookie clearing strings from logout result
 * Useful for frameworks that need cookie strings
 */
export function getCookieClearingStrings(logoutResult: UniversalLogoutResult): string[] {
  return logoutResult.cookiesToClear.map(cookie => 
    createCookieString(cookie.name, '', {
      ...cookie.options,
      maxAge: 0 // Ensure cookie is cleared
    })
  );
}

/**
 * Helper function to get the main auth cookie clearing info
 * Returns the primary auth cookie that needs to be cleared
 */
export function getMainAuthCookie(logoutResult: UniversalLogoutResult): { name: string; clearingString: string } | null {
  const authCookie = logoutResult.cookiesToClear.find(cookie => 
    cookie.name === authConfig.cookieName
  );
  
  if (!authCookie) return null;
  
  return {
    name: authCookie.name,
    clearingString: createCookieString(authCookie.name, '', {
      ...authCookie.options,
      maxAge: 0
    })
  };
}

/**
 * Get current user from token (framework-agnostic)
 */
export async function getCurrentUserUniversal(token: string | null) {
  return getCurrentUserFromToken(token);
}

/**
 * Check if token is valid (framework-agnostic)
 */
export async function isTokenValidUniversal(token: string | null): Promise<boolean> {
  return isTokenValid(token);
}

/**
 * Utility to create a standard cookie string
 */
export function createCookieString(name: string, value: string, options: CookieOptions): string {
  let cookieString = `${encodeURIComponent(name)}=${encodeURIComponent(value)}`;
  if (options.maxAge !== undefined) cookieString += `; Max-Age=${options.maxAge}`;
  if (options.expires) cookieString += `; Expires=${options.expires.toUTCString()}`;
  cookieString += `; Path=${options.path || '/'}`;
  if (options.secure) cookieString += `; Secure`;
  if (options.httpOnly) cookieString += `; HttpOnly`;
  if (options.sameSite) cookieString += `; SameSite=${options.sameSite}`;
  return cookieString;
}

/**
 * Utility to parse cookies from a cookie header string
 */
export function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(';').forEach(raw => {
    const part = raw.trim();
    if (!part) return;
    const eqIndex = part.indexOf('=');
    if (eqIndex === -1) return;
    const name = decodeURIComponent(part.slice(0, eqIndex).trim());
    const value = decodeURIComponent(part.slice(eqIndex + 1).trim());
    if (name) cookies[name] = value;
  });
  return cookies;
}

/**
 * Get auth token from parsed cookies
 */
export function getAuthTokenFromCookies(cookies: Record<string, string>): string | null {
  return cookies[authConfig.cookieName] || null;
}

/**
 * Validate authentication for any framework
 * Returns both validation result and user data
 */
export async function validateAuth(token: string | null) {
  if (!token) return { isValid: false, user: null, error: 'No token provided' };
  try {
    const user = await getCurrentUserFromToken(token);
    if (!user) return { isValid: false, user: null, error: 'Invalid or expired token' };
    return { isValid: true, user, error: null };
  } catch (error) {
    return { isValid: false, user: null, error: error instanceof Error ? error.message : 'Authentication failed' };
  }
}

/**
 * Create authentication headers for API requests
 */
export function createAuthHeaders(token: string): Record<string, string> {
  return {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  };
}

/**
 * Utility for framework-specific implementations to handle errors consistently
 */
export function createAuthError(message: string, status: number = 401) {
  return { success: false, error: { message }, status };
}

/**
 * Utility for framework-specific implementations to handle success responses consistently
 */
export function createAuthSuccess<T>(data: T, status: number = 200) {
  return { success: true, data, status };
}

// Internal reusable error formatter
function errorResponse(error: unknown, fallback: string): AuthErrorResult {
  return {
    success: false,
    error: { message: error instanceof Error ? error.message : fallback }
  };
}

// Collection export for convenience (tree-shakable)
export const universalAuth = {
  signup: signupUniversal,
  signin: signinUniversal,
  logout: logoutUniversal,
  currentUser: getCurrentUserUniversal,
  validate: validateAuth,
  isTokenValid: isTokenValidUniversal
};
