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

export interface LogoutResult {
  cookieName: string;
  cookieOptions: CookieOptions;
  message: string;
}

/**
 * Framework-agnostic signup function
 * Returns user data, token, and cookie options for manual handling
 */
export async function signupUniversal(email: string, password: string): Promise<AuthResponse> {
  try {
    return await signupCore(email, password);
  } catch (error) {
    return {
      success: false,
      error: { message: error instanceof Error ? error.message : 'Unknown error' }
    };
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
    return {
      success: false,
      error: { message: error instanceof Error ? error.message : 'Unknown error' }
    };
  }
}

/**
 * Framework-agnostic logout function
 * Returns cookie information for manual clearing
 */
export function logoutUniversal(): LogoutResult {
  return logoutCore();
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
  let cookieString = `${name}=${value}`;
  
  if (options.maxAge) cookieString += `; Max-Age=${options.maxAge}`;
  if (options.expires) cookieString += `; Expires=${options.expires.toUTCString()}`;
  if (options.path) cookieString += `; Path=${options.path}`;
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
  
  cookieHeader.split(';').forEach(cookie => {
    const [name, ...rest] = cookie.split('=');
    const value = rest.join('=');
    if (name && value) {
      cookies[name.trim()] = value.trim();
    }
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
  try {
    if (!token) {
      return { isValid: false, user: null, error: "No token provided" };
    }

    const user = await getCurrentUserFromToken(token);
    
    if (!user) {
      return { isValid: false, user: null, error: "Invalid or expired token" };
    }

    return { isValid: true, user, error: null };
  } catch (error) {
    return { 
      isValid: false, 
      user: null, 
      error: error instanceof Error ? error.message : "Authentication failed" 
    };
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
  return {
    success: false,
    error: { message },
    status
  };
}

/**
 * Utility for framework-specific implementations to handle success responses consistently
 */
export function createAuthSuccess<T>(data: T, status: number = 200) {
  return {
    success: true,
    data,
    status
  };
}
