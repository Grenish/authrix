// Next.js utilities for Authrix - unified API for App Router, Pages Router & Middleware
// The goal of this refactor is to offer consistent behaviors while preserving
// existing exported function names for backwards compatibility.

import { signupCore } from "../core/signup";
import { signinCore } from "../core/signin";
import { logoutCore } from "../core/logout";
import { getCurrentUserFromToken, isTokenValid } from "../core/session";
import { authConfig } from "../config";

// Types
interface NextJsModules {
  NextRequest?: any;
  NextResponse?: any;
  cookies?: any;
  headers?: any;
}

interface EnvironmentInfo {
  isNextJsAvailable: boolean;
  context: 'app-router' | 'pages-router' | 'middleware' | 'unknown';
  hasAppRouterSupport: boolean;
  hasPagesRouterSupport: boolean;
  hasMiddlewareSupport: boolean;
  detectionComplete: boolean;
  runtimeInfo: {
    hasRequire: boolean;
    hasProcess: boolean;
    hasGlobalThis: boolean;
    hasNextData: boolean;
    nextRuntime?: string;
  };
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
    hasMiddlewareSupport: false,
    detectionComplete: false,
    runtimeInfo: {
      hasRequire: false,
      hasProcess: false,
      hasGlobalThis: false,
      hasNextData: false,
    }
  };

  static async loadModules(): Promise<NextJsModules> {
    if (this.detectionComplete) return this.cache;

    this.environmentInfo.runtimeInfo = {
      // Use classic detection so Jest / Node environments that still expose require get flagged
      hasRequire: typeof require !== 'undefined',
      hasProcess: typeof process !== 'undefined',
      hasGlobalThis: typeof globalThis !== 'undefined',
      hasNextData: typeof (globalThis as any).__NEXT_DATA__ !== 'undefined',
      nextRuntime: typeof process !== 'undefined' ? process.env?.NEXT_RUNTIME : undefined,
    } as any;

    // Use dynamic import so Edge runtime (which disallows require) does not crash
    const tryImport = async (path: string) => {
      try { return await import(path); } catch { return null; }
    };

    const nextServer = await tryImport('next/server');
    if (nextServer) {
      this.cache.NextRequest = (nextServer as any).NextRequest;
      this.cache.NextResponse = (nextServer as any).NextResponse;
      this.environmentInfo.hasMiddlewareSupport = true;
      this.environmentInfo.isNextJsAvailable = true;
    }

    const nextHeaders = await tryImport('next/headers');
    if (nextHeaders) {
      this.cache.cookies = (nextHeaders as any).cookies;
      this.cache.headers = (nextHeaders as any).headers;
      this.environmentInfo.hasAppRouterSupport = true;
      this.environmentInfo.isNextJsAvailable = true;
    }

    // Determine context heuristically
    if (this.cache.cookies) {
      // Presence of cookies() indicates App Router / Route Handler / Server Component context
      this.environmentInfo.context = 'app-router';
    } else if (this.cache.NextRequest && this.cache.NextResponse) {
      this.environmentInfo.context = 'middleware';
    } else {
      // If neither dynamic modules loaded we may still be in Pages router (Jest / API route)
      this.environmentInfo.context = 'pages-router';
      this.environmentInfo.hasPagesRouterSupport = true;
    }

    this.detectionComplete = true;
    this.environmentInfo.detectionComplete = true;
    return this.cache;
  }

  static getEnvironmentInfo(): EnvironmentInfo { return { ...this.environmentInfo }; }
  static reset(): EnvironmentInfo {
    this.cache = {};
    this.detectionComplete = false;
    // Force immediate re-detection so callers get fresh runtime info (mirrors previous behavior)
    // Fire and forget; synchronous callers will still see updated runtimeInfo defaults, then async load updates.
    void this.loadModules();
    return this.getEnvironmentInfo();
  }
}

// --- Unified Context Helpers -------------------------------------------------

type AnyReq = any; // intentionally loose: supports NextRequest, API req, standard Request
type AnyRes = any; // supports NextResponse, API res

interface CookieSetOptions {
  name: string; value: string; options?: any;
}

function buildCookieString(name: string, value: string, options: any = {}) {
  return CookieUtils.createCookieString(name, value, options);
}

function setCookieInPages(res: AnyRes, cookie: string) {
  if (!res?.setHeader) return false;
  const existing = res.getHeader?.('Set-Cookie');
  if (existing) {
    const arr = Array.isArray(existing) ? existing : [existing];
    res.setHeader('Set-Cookie', [...arr, cookie]);
  } else {
    res.setHeader('Set-Cookie', cookie);
  }
  return true;
}

async function setCookieInApp(tokenInfo: CookieSetOptions): Promise<boolean> {
  try {
    const modules = await ModuleLoader.loadModules();
    if (!modules.cookies) return false;
    const store = modules.cookies();
    store.set(tokenInfo.name, tokenInfo.value, tokenInfo.options);
    return true;
  } catch { return false; }
}

async function applyAuthCookie(token: string, cookieOptions: any, ctx?: { res?: AnyRes }): Promise<boolean> {
  const name = CookieUtils.getCookieName();
  const successPages = ctx?.res ? setCookieInPages(ctx.res, buildCookieString(name, token, cookieOptions)) : false;
  if (successPages) return true;
  const successApp = await setCookieInApp({ name, value: token, options: cookieOptions });
  return successApp;
}

async function clearAuthCookie(ctx?: { res?: AnyRes }): Promise<boolean> {
  const name = CookieUtils.getCookieName();
  const clearString = CookieUtils.createLogoutCookie(name);
  const successPages = ctx?.res ? setCookieInPages(ctx.res, clearString) : false;
  if (successPages) return true;
  try {
    const modules = await ModuleLoader.loadModules();
    if (modules.cookies) {
      const store = modules.cookies();
      store.set(name, "", { path: '/', expires: new Date(0) });
      return true;
    }
  } catch {}
  return false;
}

// Extract token from any supported context
async function extractToken(ctx?: { req?: AnyReq; request?: Request }): Promise<string | null> {
  // 1. Pages router (req.cookies)
  if (ctx?.req?.cookies && typeof ctx.req.cookies === 'object') {
    return ctx.req.cookies[CookieUtils.getCookieName()] || null;
  }

  // 2. App router (cookies())
  try {
    const modules = await ModuleLoader.loadModules();
    if (modules.cookies) {
      const store = modules.cookies();
      const value = store.get(CookieUtils.getCookieName())?.value;
      if (value) return value;
    }
  } catch {}

  // 3. Standard Request (Route Handler / Middleware cloning) cookie header
  const reqLike = ctx?.request || ctx?.req;
  const header = reqLike?.headers ? (reqLike.headers.get ? reqLike.headers.get('cookie') : reqLike.headers['cookie']) : undefined;
  if (typeof header === 'string') {
    const cookies = parseCookies(header);
    if (cookies[CookieUtils.getCookieName()]) return cookies[CookieUtils.getCookieName()];
  }

  // 4. Middleware NextRequest (has cookies.get())
  if (reqLike?.cookies?.get) {
    try { return reqLike.cookies.get(CookieUtils.getCookieName())?.value || null; } catch {}
  }

  return null;
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
  const ok = await applyAuthCookie(result.token, result.cookieOptions);
  if (!ok) throw new Error(ErrorMessages.COOKIE_SET_FAILED('signupNextApp'));
  return result.user;
}

export async function signinNextApp(email: string, password: string) {
  const result = await signinCore(email, password);
  const ok = await applyAuthCookie(result.token, result.cookieOptions);
  if (!ok) throw new Error(ErrorMessages.COOKIE_SET_FAILED('signinNextApp'));
  return result.user;
}

export async function logoutNextApp() {
  const result = logoutCore();
  const ok = await clearAuthCookie();
  if (!ok) throw new Error(ErrorMessages.COOKIE_SET_FAILED('logoutNextApp'));
  return { message: result.message };
}

export async function getCurrentUserNextApp() {
  try { return getCurrentUserFromToken(await extractToken()); } catch { return null; }
}

export async function isAuthenticatedNextApp(): Promise<boolean> {
  try { return isTokenValid(await extractToken()); } catch { return false; }
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

// === Flexible Functions (Auto-detect environment) ===

export async function signupNext(email: string, password: string, res?: any) {
  const result = await signupCore(email, password);
  const ok = await applyAuthCookie(result.token, result.cookieOptions, { res });
  if (!ok) throw new Error('Unable to set authentication cookie. Pass a response object for Pages Router or call from App Router context.');
  return result.user;
}

export async function signinNext(email: string, password: string, res?: any) {
  const result = await signinCore(email, password);
  const ok = await applyAuthCookie(result.token, result.cookieOptions, { res });
  if (!ok) throw new Error('Unable to set authentication cookie. Pass a response object for Pages Router or call from App Router context.');
  return result.user;
}

export async function logoutNext(res?: any) {
  const result = logoutCore();
  const ok = await clearAuthCookie({ res });
  if (!ok) throw new Error('Unable to clear authentication cookie. Pass a response object for Pages Router or call from App Router context.');
  return { message: result.message };
}

export async function getCurrentUserNext(req?: any) {
  const token = await extractToken({ req });
  return getCurrentUserFromToken(token);
}

export async function isAuthenticatedNext(req?: any): Promise<boolean> {
  return isTokenValid(await extractToken({ req }));
}

// === Flexible Functions with explicit naming ===

export async function signupNextFlexible(
  email: string,
  password: string,
  res?: any
) {
  return signupNext(email, password, res);
}

export async function signinNextFlexible(
  email: string,
  password: string,
  res?: any
) {
  return signinNext(email, password, res);
}

export async function getCurrentUserNextFlexible(req?: any) {
  return getCurrentUserNext(req);
}

// === API Route Handlers ===

export function createSignupHandler() {
  return async function handler(request: Request) {
    if (request.method !== 'POST') {
      return Response.json(
        { error: 'Method not allowed' },
        { status: 405 }
      );
    }

    try {
      const { email, password } = await request.json();

      if (!email || !password) {
        return Response.json(
          { error: 'Email and password are required' },
          { status: 400 }
        );
      }

      const result = await signupCore(email, password);
      
      const response = Response.json({
        success: true,
        user: result.user,
        message: 'Account created successfully'
      });

      // Set cookie
      const cookie = CookieUtils.createCookieString(
        CookieUtils.getCookieName(),
        result.token,
        result.cookieOptions
      );
      response.headers.set('Set-Cookie', cookie);

      return response;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Signup failed';
      const status = message.includes('already registered') ? 409 : 400;
      
      return Response.json(
        { error: message },
        { status }
      );
    }
  };
}

export function createSigninHandler() {
  return async function handler(request: Request) {
    if (request.method !== 'POST') {
      return Response.json(
        { error: 'Method not allowed' },
        { status: 405 }
      );
    }

    try {
      const { email, password } = await request.json();

      if (!email || !password) {
        return Response.json(
          { error: 'Email and password are required' },
          { status: 400 }
        );
      }

      const result = await signinCore(email, password);
      
      const response = Response.json({
        success: true,
        user: result.user,
        message: 'Signed in successfully'
      });

      // Set cookie
      const cookie = CookieUtils.createCookieString(
        CookieUtils.getCookieName(),
        result.token,
        result.cookieOptions
      );
      response.headers.set('Set-Cookie', cookie);

      return response;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Signin failed';
      
      return Response.json(
        { error: message },
        { status: 401 }
      );
    }
  };
}

export function createLogoutHandler() {
  return async function handler(request: Request) {
    if (request.method !== 'POST') {
      return Response.json(
        { error: 'Method not allowed' },
        { status: 405 }
      );
    }

    try {
      const result = logoutCore();
      
      const response = Response.json({
        success: true,
        message: result.message
      });

      // Clear cookie
      const cookie = CookieUtils.createLogoutCookie(CookieUtils.getCookieName());
      response.headers.set('Set-Cookie', cookie);

      return response;
    } catch (error) {
      return Response.json(
        { error: 'Logout failed' },
        { status: 500 }
      );
    }
  };
}

export function createCurrentUserHandler() {
  return async function handler(request: Request) {
    if (request.method !== 'GET') {
      return Response.json(
        { error: 'Method not allowed' },
        { status: 405 }
      );
    }

    try {
      const cookieHeader = request.headers.get('cookie');
      const cookies = parseCookies(cookieHeader || '');
      const token = cookies[CookieUtils.getCookieName()];
      
      const user = await getCurrentUserFromToken(token);
      
      if (!user) {
        return Response.json(
          { error: 'Not authenticated' },
          { status: 401 }
        );
      }

      return Response.json({
        success: true,
        user
      });
    } catch (error) {
      return Response.json(
        { error: 'Failed to get current user' },
        { status: 500 }
      );
    }
  };
}

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

// === Pages Router Handlers ===

export function createSignupHandlerPages() {
  return async function handler(req: any, res: any) {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
      }

      const result = await signupCore(email, password);
      
      // Set cookie
      const cookie = CookieUtils.createCookieString(
        CookieUtils.getCookieName(),
        result.token,
        result.cookieOptions
      );
      res.setHeader('Set-Cookie', cookie);

      return res.json({
        success: true,
        user: result.user,
        message: 'Account created successfully'
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Signup failed';
      const status = message.includes('already registered') ? 409 : 400;
      
      return res.status(status).json({ error: message });
    }
  };
}

export function createSigninHandlerPages() {
  return async function handler(req: any, res: any) {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
      }

      const result = await signinCore(email, password);
      
      // Set cookie
      const cookie = CookieUtils.createCookieString(
        CookieUtils.getCookieName(),
        result.token,
        result.cookieOptions
      );
      res.setHeader('Set-Cookie', cookie);

      return res.json({
        success: true,
        user: result.user,
        message: 'Signed in successfully'
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Signin failed';
      return res.status(401).json({ error: message });
    }
  };
}

export function createLogoutHandlerPages() {
  return async function handler(req: any, res: any) {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
      const result = logoutCore();
      
      // Clear cookie
      const cookie = CookieUtils.createLogoutCookie(CookieUtils.getCookieName());
      res.setHeader('Set-Cookie', cookie);

      return res.json({
        success: true,
        message: result.message
      });
    } catch (error) {
      return res.status(500).json({ error: 'Logout failed' });
    }
  };
}

export function createCurrentUserHandlerPages() {
  return async function handler(req: any, res: any) {
    if (req.method !== 'GET') {
      return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
      const token = req.cookies[CookieUtils.getCookieName()];
      const user = await getCurrentUserFromToken(token);
      
      if (!user) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      return res.json({
        success: true,
        user
      });
    } catch (error) {
      return res.status(500).json({ error: 'Failed to get current user' });
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

// === Helper Functions ===

function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  
  if (!cookieHeader) return cookies;
  
  cookieHeader.split(';').forEach(cookie => {
    const [name, ...rest] = cookie.trim().split('=');
    if (name && rest.length > 0) {
      cookies[name] = rest.join('=');
    }
  });
  
  return cookies;
}

// === Environment Info ===

export function getNextJsEnvironmentInfo(): EnvironmentInfo {
  // Ensure modules are loaded before returning info
  ModuleLoader.loadModules();
  return ModuleLoader.getEnvironmentInfo();
}

export function redetectNextJsEnvironment(): EnvironmentInfo {
  return ModuleLoader.reset();
}

export function resetEnvironmentDetection(): void {
  ModuleLoader.reset();
}

export function forceNextJsAvailability(available: boolean = true): void {
  // For testing purposes - force Next.js availability
  const info = ModuleLoader.getEnvironmentInfo();
  info.isNextJsAvailable = available;
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

// === Response Creation Helpers ===

export function createAuthenticatedResponse(
  data: any,
  token?: string,
  options?: {
    status?: number;
    headers?: Record<string, string>;
    cookieOptions?: any;
  }
) {
  const response = Response.json(data, {
    status: options?.status || 200,
    headers: options?.headers
  });

  if (token) {
    const cookie = CookieUtils.createCookieString(
      CookieUtils.getCookieName(),
      token,
      {
        httpOnly: true,
        path: '/',
        maxAge: 604800, // 7 days
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        ...options?.cookieOptions
      }
    );
    response.headers.set('Set-Cookie', cookie);
  }

  return response;
}