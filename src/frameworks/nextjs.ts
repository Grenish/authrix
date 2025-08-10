// Next.js utilities for Authrix - Optimized and bug-fixed version

import { signupCore } from "../core/signup";
import { signinCore } from "../core/signin";
import { logoutCore } from "../core/logout";
import { getCurrentUserFromToken, isTokenValid } from "../core/session";
import { authConfig } from "../config";

// Types
interface NextJsModules {
  NextRequest?: any;
  NextResponse?: any;
  NextApiRequest?: any;
  NextApiResponse?: any;
  cookies?: any;
  headers?: any;
}

interface EnvironmentInfo {
  isNextJsAvailable: boolean;
  context: 'app-router' | 'pages-router' | 'middleware' | 'unknown';
  hasAppRouterSupport: boolean;
  hasPagesRouterSupport: boolean;
  hasMiddlewareSupport: boolean;
}

// Module cache for better performance
class ModuleLoader {
  private static cache: NextJsModules = {};
  private static detectionComplete = false;
  private static environmentInfo: EnvironmentInfo = {
    isNextJsAvailable: false,
    context: 'unknown',
    hasAppRouterSupport: false,
    hasPagesRouterSupport: false,
    hasMiddlewareSupport: false
  };

  static async loadModules(): Promise<NextJsModules> {
    if (this.detectionComplete) {
      return this.cache;
    }

    try {
      // Check if we're in a Node.js environment
      if (typeof require !== 'undefined') {
        // Try loading Next.js modules
        try {
          const nextServer = require('next/server');
          this.cache.NextRequest = nextServer.NextRequest;
          this.cache.NextResponse = nextServer.NextResponse;
          this.environmentInfo.hasMiddlewareSupport = true;
        } catch {}

        try {
          const nextHeaders = require('next/headers');
          this.cache.cookies = nextHeaders.cookies;
          this.cache.headers = nextHeaders.headers;
          this.environmentInfo.hasAppRouterSupport = true;
        } catch {}

        // Check environment
        if (this.cache.cookies) {
          this.environmentInfo.context = 'app-router';
        } else if (this.cache.NextRequest && this.cache.NextResponse) {
          this.environmentInfo.context = 'middleware';
        } else {
          this.environmentInfo.context = 'pages-router';
          this.environmentInfo.hasPagesRouterSupport = true;
        }

        this.environmentInfo.isNextJsAvailable = true;
      }
    } catch (error) {
      console.debug('Next.js module loading failed:', error);
    }

    this.detectionComplete = true;
    return this.cache;
  }

  static getEnvironmentInfo(): EnvironmentInfo {
    return { ...this.environmentInfo };
  }

  static reset(): void {
    this.cache = {};
    this.detectionComplete = false;
    this.environmentInfo = {
      isNextJsAvailable: false,
      context: 'unknown',
      hasAppRouterSupport: false,
      hasPagesRouterSupport: false,
      hasMiddlewareSupport: false
    };
  }
}

// Cookie utilities
class CookieUtils {
  static getCookieName(): string {
    try {
      return authConfig?.cookieName || 'auth_token';
    } catch {
      return 'auth_token';
    }
  }

  static createCookieString(
    name: string,
    value: string,
    options: {
      maxAge?: number;
      expires?: Date;
      path?: string;
      secure?: boolean;
      sameSite?: 'strict' | 'lax' | 'none';
      httpOnly?: boolean;
    } = {}
  ): string {
    const parts = [`${name}=${value}`];

    if (options.httpOnly !== false) parts.push('HttpOnly');
    if (options.path) parts.push(`Path=${options.path}`);
    if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`);
    if (options.expires) parts.push(`Expires=${options.expires.toUTCString()}`);
    if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
    if (options.secure) parts.push('Secure');

    return parts.join('; ');
  }

  static createLogoutCookie(name: string): string {
    return this.createCookieString(name, '', {
      expires: new Date(0),
      path: '/',
      httpOnly: true
    });
  }
}

// JWT utilities for Edge Runtime
class JWTUtils {
  static isValidStructure(token: string): boolean {
    if (!token || typeof token !== 'string') return false;
    const parts = token.split('.');
    return parts.length === 3 && parts.every(part => part.length > 0);
  }

  static extractPayload(token: string): any {
    try {
      if (!this.isValidStructure(token)) return null;
      
      const payload = token.split('.')[1];
      const padded = payload + '='.repeat((4 - payload.length % 4) % 4);
      const decoded = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
      return JSON.parse(decoded);
    } catch {
      return null;
    }
  }

  static isExpired(token: string): boolean {
    const payload = this.extractPayload(token);
    if (!payload?.exp) return true;
    return Math.floor(Date.now() / 1000) >= payload.exp;
  }
}

// Error messages
const ErrorMessages = {
  APP_ROUTER_REQUIRED: (method: string) => 
    `${method} requires Next.js App Router context. ` +
    `Call this from a Server Component, Server Action, or Route Handler. ` +
    `For Pages Router, use the 'NextPages' variant instead.`,
  
  PAGES_ROUTER_REQUIRED: (method: string) =>
    `${method} requires a valid Next.js API response object. ` +
    `Call this from a Next.js API route handler with (req, res) parameters.`,
  
  COOKIE_SET_FAILED: (method: string) =>
    `${method} failed to set authentication cookie. ` +
    `Use the Core variant for manual cookie handling.`,
  
  NOT_AVAILABLE: 'Next.js is not available in this environment.'
};

// === App Router Functions ===

export async function signupNextApp(email: string, password: string) {
  const result = await signupCore(email, password);
  
  try {
    const modules = await ModuleLoader.loadModules();
    if (!modules.cookies) {
      throw new Error(ErrorMessages.APP_ROUTER_REQUIRED('signupNextApp'));
    }
    
    const cookieStore = modules.cookies();
    cookieStore.set(CookieUtils.getCookieName(), result.token, result.cookieOptions);
    return result.user;
  } catch (error) {
    if (error instanceof Error && error.message.includes('Next.js')) {
      throw error;
    }
    throw new Error(ErrorMessages.COOKIE_SET_FAILED('signupNextApp'));
  }
}

export async function signinNextApp(email: string, password: string) {
  const result = await signinCore(email, password);
  
  try {
    const modules = await ModuleLoader.loadModules();
    if (!modules.cookies) {
      throw new Error(ErrorMessages.APP_ROUTER_REQUIRED('signinNextApp'));
    }
    
    const cookieStore = modules.cookies();
    cookieStore.set(CookieUtils.getCookieName(), result.token, result.cookieOptions);
    return result.user;
  } catch (error) {
    if (error instanceof Error && error.message.includes('Next.js')) {
      throw error;
    }
    throw new Error(ErrorMessages.COOKIE_SET_FAILED('signinNextApp'));
  }
}

export async function logoutNextApp() {
  const result = logoutCore();
  
  try {
    const modules = await ModuleLoader.loadModules();
    if (!modules.cookies) {
      throw new Error(ErrorMessages.APP_ROUTER_REQUIRED('logoutNextApp'));
    }
    
    const cookieStore = modules.cookies();
    cookieStore.set(CookieUtils.getCookieName(), "", result.cookieOptions);
    return { message: result.message };
  } catch (error) {
    if (error instanceof Error && error.message.includes('Next.js')) {
      throw error;
    }
    throw new Error(ErrorMessages.COOKIE_SET_FAILED('logoutNextApp'));
  }
}

export async function getCurrentUserNextApp() {
  try {
    const modules = await ModuleLoader.loadModules();
    if (!modules.cookies) {
      throw new Error(ErrorMessages.APP_ROUTER_REQUIRED('getCurrentUserNextApp'));
    }
    
    const cookieStore = modules.cookies();
    const token = cookieStore.get(CookieUtils.getCookieName())?.value || null;
    return getCurrentUserFromToken(token);
  } catch (error) {
    if (error instanceof Error && error.message.includes('Next.js')) {
      throw error;
    }
    return null;
  }
}

export async function isAuthenticatedNextApp(): Promise<boolean> {
  try {
    const modules = await ModuleLoader.loadModules();
    if (!modules.cookies) return false;
    
    const cookieStore = modules.cookies();
    const token = cookieStore.get(CookieUtils.getCookieName())?.value || null;
    return isTokenValid(token);
  } catch {
    return false;
  }
}

// === Pages Router Functions ===

export async function signupNextPages(
  email: string, 
  password: string, 
  res: any
) {
  if (!res?.setHeader) {
    throw new Error(ErrorMessages.PAGES_ROUTER_REQUIRED('signupNextPages'));
  }
  
  const result = await signupCore(email, password);
  const cookie = CookieUtils.createCookieString(
    CookieUtils.getCookieName(),
    result.token,
    result.cookieOptions
  );
  
  res.setHeader('Set-Cookie', cookie);
  return result.user;
}

export async function signinNextPages(
  email: string,
  password: string,
  res: any
) {
  if (!res?.setHeader) {
    throw new Error(ErrorMessages.PAGES_ROUTER_REQUIRED('signinNextPages'));
  }
  
  const result = await signinCore(email, password);
  const cookie = CookieUtils.createCookieString(
    CookieUtils.getCookieName(),
    result.token,
    result.cookieOptions
  );
  
  res.setHeader('Set-Cookie', cookie);
  return result.user;
}

export function logoutNextPages(res: any) {
  if (!res?.setHeader) {
    throw new Error(ErrorMessages.PAGES_ROUTER_REQUIRED('logoutNextPages'));
  }
  
  const result = logoutCore();
  const cookie = CookieUtils.createLogoutCookie(CookieUtils.getCookieName());
  
  res.setHeader('Set-Cookie', cookie);
  return { message: result.message };
}

export async function getCurrentUserNextPages(req: any) {
  if (!req?.cookies) {
    throw new Error('getCurrentUserNextPages requires a request object with cookies');
  }
  
  const token = req.cookies[CookieUtils.getCookieName()] || null;
  return getCurrentUserFromToken(token);
}

export async function isAuthenticatedNextPages(req: any): Promise<boolean> {
  if (!req?.cookies) return false;
  
  const token = req.cookies[CookieUtils.getCookieName()] || null;
  return isTokenValid(token);
}

// === Middleware Functions ===

export async function checkAuthMiddleware(
  request: any,
  options: { cookieName?: string } = {}
) {
  const cookieName = options.cookieName || CookieUtils.getCookieName();
  const token = request.cookies?.get(cookieName)?.value || null;
  
  if (!token) {
    return {
      isAuthenticated: false,
      user: null,
      reason: 'No token provided'
    };
  }
  
  if (!JWTUtils.isValidStructure(token)) {
    return {
      isAuthenticated: false,
      user: null,
      reason: 'Invalid token structure'
    };
  }
  
  if (JWTUtils.isExpired(token)) {
    return {
      isAuthenticated: false,
      user: null,
      reason: 'Token expired'
    };
  }
  
  const payload = JWTUtils.extractPayload(token);
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

export async function checkAuthMiddlewareSecure(
  request: any,
  options: {
    validationEndpoint?: string;
    timeout?: number;
    cookieName?: string;
  } = {}
) {
  const result = await checkAuthMiddleware(request, options);
  
  if (!result.isAuthenticated) {
    return result;
  }
  
  try {
    const cookieName = options.cookieName || CookieUtils.getCookieName();
    const token = request.cookies?.get(cookieName)?.value;
    
    if (!token) return result;
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), options.timeout || 5000);
    
    const validationUrl = options.validationEndpoint || '/api/auth/validate';
    const baseUrl = request.nextUrl?.origin || request.url?.split('/').slice(0, 3).join('/');
    
    const response = await fetch(`${baseUrl}${validationUrl}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    if (response.ok) {
      const data = await response.json();
      return {
        isAuthenticated: true,
        user: data.user,
        reason: 'Token validated via API'
      };
    }
    
    return result; // Fallback to basic validation
  } catch {
    return result; // Fallback to basic validation
  }
}

// === Higher-Order Functions ===

export function withAuth<T extends Record<string, any>, U extends Record<string, any>>(
  handler: (req: T & { user: any }, res: U) => Promise<void> | void
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

// === Flexible Functions ===

export async function signupNext(
  email: string,
  password: string,
  res?: any
) {
  const result = await signupCore(email, password);
  
  // Try Pages Router if res provided
  if (res?.setHeader) {
    const cookie = CookieUtils.createCookieString(
      CookieUtils.getCookieName(),
      result.token,
      result.cookieOptions
    );
    res.setHeader('Set-Cookie', cookie);
    return result.user;
  }
  
  // Try App Router
  try {
    const modules = await ModuleLoader.loadModules();
    if (modules.cookies) {
      const cookieStore = modules.cookies();
      cookieStore.set(CookieUtils.getCookieName(), result.token, result.cookieOptions);
      return result.user;
    }
  } catch {}
  
  // Fallback error
  throw new Error(
    'Unable to set authentication cookie. ' +
    'Pass a response object for Pages Router or call from App Router context.'
  );
}

export async function signinNext(
  email: string,
  password: string,
  res?: any
) {
  const result = await signinCore(email, password);
  
  // Try Pages Router if res provided
  if (res?.setHeader) {
    const cookie = CookieUtils.createCookieString(
      CookieUtils.getCookieName(),
      result.token,
      result.cookieOptions
    );
    res.setHeader('Set-Cookie', cookie);
    return result.user;
  }
  
  // Try App Router
  try {
    const modules = await ModuleLoader.loadModules();
    if (modules.cookies) {
      const cookieStore = modules.cookies();
      cookieStore.set(CookieUtils.getCookieName(), result.token, result.cookieOptions);
      return result.user;
    }
  } catch {}
  
  // Fallback error
  throw new Error(
    'Unable to set authentication cookie. ' +
    'Pass a response object for Pages Router or call from App Router context.'
  );
}

export async function getCurrentUser(req?: any) {
  // Try Pages Router if req provided
  if (req?.cookies) {
    const token = req.cookies[CookieUtils.getCookieName()] || null;
    return getCurrentUserFromToken(token);
  }
  
  // Try App Router
  try {
    const modules = await ModuleLoader.loadModules();
    if (modules.cookies) {
      const cookieStore = modules.cookies();
      const token = cookieStore.get(CookieUtils.getCookieName())?.value || null;
      return getCurrentUserFromToken(token);
    }
  } catch {}
  
  return null;
}

export async function isAuthenticated(req?: any): Promise<boolean> {
  // Try Pages Router if req provided
  if (req?.cookies) {
    const token = req.cookies[CookieUtils.getCookieName()] || null;
    return isTokenValid(token);
  }
  
  // Try App Router
  try {
    const modules = await ModuleLoader.loadModules();
    if (modules.cookies) {
      const cookieStore = modules.cookies();
      const token = cookieStore.get(CookieUtils.getCookieName())?.value || null;
      return isTokenValid(token);
    }
  } catch {}
  
  return false;
}

// === Validation Handlers ===

export function createTokenValidationHandler() {
  return async function handler(request: Request) {
    try {
      const authHeader = request.headers.get('Authorization');
      if (!authHeader?.startsWith('Bearer ')) {
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
      
      return Response.json({ success: true, user });
    } catch (error) {
      return Response.json(
        { success: false, error: 'Token validation failed' },
        { status: 500 }
      );
    }
  };
}

export function createTokenValidationHandlerPages() {
  return async function handler(req: any, res: any) {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }
    
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith('Bearer ')) {
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
      
      return res.json({ success: true, user });
    } catch (error) {
      return res.status(500).json({
        success: false,
        error: 'Token validation failed'
      });
    }
  };
}

// === Environment Info ===

export function getNextJsEnvironmentInfo(): EnvironmentInfo & {
  detectionComplete: boolean;
  runtimeInfo: Record<string, any>;
} {
  const info = ModuleLoader.getEnvironmentInfo();
  return {
    ...info,
    detectionComplete: true,
    runtimeInfo: {
      hasRequire: typeof require !== 'undefined',
      hasProcess: typeof process !== 'undefined',
      nextRuntime: typeof process !== 'undefined' ? process.env?.NEXT_RUNTIME : undefined
    }
  };
}

export function resetEnvironmentDetection(): void {
  ModuleLoader.reset();
}

// === Cookie Helpers ===

export function createAuthCookieString(
  token: string,
  options?: Partial<Parameters<typeof CookieUtils.createCookieString>[2]>
): string {
  return CookieUtils.createCookieString(
    CookieUtils.getCookieName(),
    token,
    {
      httpOnly: true,
      path: '/',
      maxAge: 604800, // 7 days
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      ...options
    }
  );
}

export function createLogoutCookieString(): string {
  return CookieUtils.createLogoutCookie(CookieUtils.getCookieName());
}