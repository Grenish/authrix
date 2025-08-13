// Next.js utilities for Authrix - unified API for App Router, Pages Router & Middleware
// The goal of this refactor is to offer consistent behaviors while preserving
// existing exported function names for backwards compatibility.

import { signupCore } from "../core/signup";
import { signinCore } from "../core/signin";
import { logoutCore } from "../core/logout";
import { getCurrentUserFromToken, isTokenValid } from "../core/session";
import { authConfig } from "../config";
import { verifyToken } from "../tokens/verifyToken"; // P0: signature validation
import { ConflictError, UnauthorizedError, ForbiddenError } from "../utils/errors"; // P0: status mapping

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

  private static overridePatch: Partial<EnvironmentInfo> | null = null;

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
    if (this.overridePatch) {
      this.environmentInfo = { ...this.environmentInfo, ...this.overridePatch };
    }
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
  static setOverride(patch: Partial<EnvironmentInfo>) {
    this.overridePatch = { ...(this.overridePatch || {}), ...patch };
    this.environmentInfo = { ...this.environmentInfo, ...patch };
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
  const adjusted = { ...cookieOptions };
  if (typeof adjusted.maxAge === 'number') {
    // convert ms -> s if necessary
    const maybe = (CookieUtils as any).normalizeMaxAge?.(adjusted.maxAge) ?? adjusted.maxAge;
    adjusted.maxAge = maybe;
  }
  const successPages = ctx?.res ? setCookieInPages(ctx.res, buildCookieString(name, token, adjusted)) : false;
  if (successPages) return true;
  const successApp = await setCookieInApp({ name, value: token, options: adjusted });
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

  // Convert ms -> s if value appears to be milliseconds (heuristic > 1,000,000)
  private static normalizeMaxAge(raw?: number): number | undefined {
    if (typeof raw !== 'number') return raw;
    return raw > 1_000_000 ? Math.floor(raw / 1000) : raw;
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
    const normalized = this.normalizeOptions(options);
    if (typeof normalized.maxAge === 'number') {
      normalized.maxAge = this.normalizeMaxAge(normalized.maxAge);
    }
    const parts = [`${name}=${value}`];

    if (normalized.httpOnly) parts.push('HttpOnly');
    if (normalized.path) parts.push(`Path=${normalized.path}`);
    if (normalized.maxAge !== undefined) parts.push(`Max-Age=${normalized.maxAge}`);
    if (normalized.expires) parts.push(`Expires=${normalized.expires.toUTCString()}`);
    if (normalized.sameSite) parts.push(`SameSite=${normalized.sameSite}`);
    if (normalized.secure) parts.push('Secure');

    return parts.join('; ');
  }

  static createLogoutCookie(name: string): string {
    return this.createCookieString(name, '', {
      expires: new Date(0),
      path: '/',
      httpOnly: true
    });
  }

  /**
   * Normalize cookie options enforcing secure defaults:
   *  - httpOnly defaults to true
   *  - sameSite defaults to 'lax'
   *  - secure defaults to true in production
   *  - if sameSite === 'none', force secure true (browser requirement)
   *  - path defaults to '/'
   */
  private static normalizeOptions(opts: any = {}) {
    const isProd = process.env.NODE_ENV === 'production';
    const normalized: any = { ...opts };
    if (normalized.httpOnly !== false) normalized.httpOnly = true;
    if (!normalized.path) normalized.path = '/';
    if (!normalized.sameSite) normalized.sameSite = 'lax';
    if (normalized.sameSite === 'none') normalized.secure = true; // Required by modern browsers
    if (typeof normalized.secure === 'undefined') normalized.secure = isProd;
    return normalized;
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
      const b64 = padded.replace(/-/g, '+').replace(/_/g, '/');
      let decoded: string;
      if (typeof atob === 'function') {
        decoded = atob(b64);
      } else {
        decoded = Buffer.from(b64, 'base64').toString('utf8');
      }
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


// === Pages Router Functions ===


// === Middleware Functions ===

export async function checkAuthMiddleware(
  request: any,
  options: { cookieName?: string } = {}
) {
  const cookieName = options.cookieName || CookieUtils.getCookieName();
  const token = request.cookies?.get(cookieName)?.value || null;
  if (!token) {
    return { isAuthenticated: false, user: null, reason: 'No token provided' };
  }
  if (!JWTUtils.isValidStructure(token)) {
    return { isAuthenticated: false, user: null, reason: 'Invalid token structure' };
  }
  try {
    verifyToken(token); // validates signature & exp
  } catch {
    return { isAuthenticated: false, user: null, reason: 'Invalid or expired token' };
  }
  const payload = JWTUtils.extractPayload(token);
  const user = payload ? { id: payload.id, email: payload.email, createdAt: payload.createdAt ? new Date(payload.createdAt) : undefined } : null;
  return { isAuthenticated: !!user, user, reason: user ? 'Token valid' : 'Invalid token payload' };
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
  const token = req && (req as any).cookies ? (req as any).cookies[CookieUtils.getCookieName()] : null;
  const user = await getCurrentUserFromToken(token);
      
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


// === Flexible Functions with explicit naming ===

// (Original flexible exports moved to deprecation wrappers later in file)

// === API Route Handlers ===

export function createSignupHandler() {
  return async function handler(request: Request) {
    if (request.method !== 'POST') {
      return Response.json({ error: 'Method not allowed' }, { status: 405 });
    }
    try {
      const { email, password } = await request.json();
      if (!email || !password) {
        return Response.json({ error: 'Email and password are required' }, { status: 400 });
      }
      const result = await signupCore(email, password);
      const response = Response.json({ success: true, user: result.user, message: 'Account created successfully' });
      const cookie = CookieUtils.createCookieString(CookieUtils.getCookieName(), result.token, { ...result.cookieOptions });
      response.headers.set('Set-Cookie', cookie);
      return response;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Signup failed';
      const status = error instanceof ConflictError ? 409 : 400;
      return Response.json({ error: message }, { status });
    }
  };
}

export function createSigninHandler() {
  return async function handler(request: Request) {
    if (request.method !== 'POST') {
      return Response.json({ error: 'Method not allowed' }, { status: 405 });
    }
    try {
      const { email, password } = await request.json();
      if (!email || !password) {
        return Response.json({ error: 'Email and password are required' }, { status: 400 });
      }
      const result = await signinCore(email, password);
      const response = Response.json({ success: true, user: result.user, message: 'Signed in successfully' });
      const cookie = CookieUtils.createCookieString(CookieUtils.getCookieName(), result.token, { ...result.cookieOptions });
      response.headers.set('Set-Cookie', cookie);
      return response;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Signin failed';
      const status = error instanceof UnauthorizedError ? 401 : error instanceof ForbiddenError ? 403 : 400;
      return Response.json({ error: message }, { status });
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
      const cookie = CookieUtils.createCookieString(CookieUtils.getCookieName(), result.token, { ...result.cookieOptions });
      res.setHeader('Set-Cookie', cookie);
      return res.json({ success: true, user: result.user, message: 'Account created successfully' });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Signup failed';
      const status = error instanceof ConflictError ? 409 : 400;
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
      const cookie = CookieUtils.createCookieString(CookieUtils.getCookieName(), result.token, { ...result.cookieOptions });
      res.setHeader('Set-Cookie', cookie);
      return res.json({ success: true, user: result.user, message: 'Signed in successfully' });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Signin failed';
      const status = error instanceof UnauthorizedError ? 401 : error instanceof ForbiddenError ? 403 : 400;
      return res.status(status).json({ error: message });
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
  // For testing purposes - force Next.js availability (properly mutates internal state)
  ModuleLoader.setOverride({ isNextJsAvailable: available });
}

export async function getNextJsEnvironmentInfoAsync(): Promise<EnvironmentInfo> {
  await ModuleLoader.loadModules();
  return ModuleLoader.getEnvironmentInfo();
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

// --- Deprecation Wrappers (P1) ---
const _depEmitted = new Set<string>();
function warnDep(oldName: string, newUsage: string) {
  if (process.env.NODE_ENV === 'production') return;
  const key = `${oldName}->${newUsage}`;
  if (_depEmitted.has(key)) return;
  _depEmitted.add(key);
  console.warn(`[AUTHRIX][DEPRECATION] ${oldName} is deprecated. Use ${newUsage} instead.`);
}

// Wrap flexible variants with deprecation warning (will later point to unified API)
// Legacy variant exports removed in favor of unified namespace API.