// Internal cookie utilities (framework-agnostic abstraction)
// P1: Single applyAuthCookie + clearAuthCookie used by Next.js wrappers & unified namespace

import { authConfig } from '../config';

export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  maxAge?: number; // ms or seconds; normalized to seconds in header
  sameSite?: 'lax' | 'strict' | 'none';
  path?: string;
  expires?: Date;
}

export interface NormalizeCookieOptionsInput extends CookieOptions {
  framework: 'header' | 'express';
}

/**
 * Normalize cookie options for different frameworks / output targets.
 * - Converts maxAge from ms to seconds for header usage.
 * - Ensures httpOnly default true unless explicitly false.
 * - Applies secure flag per config / NODE_ENV.
 */
export function normalizeCookieOptions(input: NormalizeCookieOptionsInput): CookieOptions {
  const { framework, maxAge, httpOnly, secure, sameSite, path, expires } = input;
  const base: CookieOptions = {
    httpOnly: httpOnly !== false,
    sameSite: sameSite || 'lax',
    path: path || '/',
    secure: authConfig.forceSecureCookies || secure || process.env.NODE_ENV === 'production'
  };
  if (typeof maxAge === 'number') {
    base.maxAge = framework === 'header' ? normalizeMaxAge(maxAge) : maxAge; // express accepts ms; header needs seconds
  }
  if (expires) base.expires = expires;
  return base;
}

export interface ApplyCookieContext { res?: any; }

function getCookieName(): string { return authConfig.cookieName || 'auth_token'; }
// Public alias for centralized retrieval (used across framework layers)
export const getAuthCookieName = getCookieName;

function normalizeMaxAge(value?: number): number | undefined {
  if (typeof value !== 'number') return value;
  return value > 1_000_000 ? Math.floor(value / 1000) : value; // heuristic ms -> s
}

export function createAuthCookieString(token: string, options: CookieOptions = {}): string {
  const parts: string[] = [];
  parts.push(`${getCookieName()}=${token}`);
  const opts: CookieOptions = { httpOnly: true, sameSite: 'lax', path: '/', secure: authConfig.forceSecureCookies || process.env.NODE_ENV === 'production', ...options };
  if (opts.httpOnly) parts.push('HttpOnly');
  if (opts.path) parts.push(`Path=${opts.path}`);
  if (typeof opts.maxAge === 'number') parts.push(`Max-Age=${normalizeMaxAge(opts.maxAge)}`);
  if (opts.expires) parts.push(`Expires=${opts.expires.toUTCString()}`);
  if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`);
  if (opts.secure) parts.push('Secure');
  return parts.join('; ');
}

export function createLogoutCookieString(): string {
  return createAuthCookieString('', { expires: new Date(0) });
}

async function setNextCookies(name: string, value: string, options: CookieOptions): Promise<boolean> {
  try {
    // @ts-ignore optional peer dependency loaded dynamically
    const headersMod: any = await import('next/headers').catch(() => null);
    if (headersMod?.cookies) {
      headersMod.cookies().set(name, value, options as any);
      return true;
    }
  } catch { }
  return false;
}

export async function applyAuthCookie(token: string, options: CookieOptions, ctx?: ApplyCookieContext): Promise<boolean> {
  const name = getCookieName();
  if (ctx?.res?.setHeader) {
    const cookieStr = createAuthCookieString(token, options);
    const existing = ctx.res.getHeader?.('Set-Cookie');
    if (existing) {
      const arr = Array.isArray(existing) ? existing : [existing];
      ctx.res.setHeader('Set-Cookie', [...arr, cookieStr]);
    } else {
      ctx.res.setHeader('Set-Cookie', cookieStr);
    }
    return true;
  }
  if (await setNextCookies(name, token, options)) return true;
  return false;
}

export async function clearAuthCookie(ctx?: ApplyCookieContext): Promise<boolean> {
  const name = getCookieName();
  const cookieStr = createLogoutCookieString();
  if (ctx?.res?.setHeader) {
    const existing = ctx.res.getHeader?.('Set-Cookie');
    if (existing) {
      const arr = Array.isArray(existing) ? existing : [existing];
      ctx.res.setHeader('Set-Cookie', [...arr, cookieStr]);
    } else {
      ctx.res.setHeader('Set-Cookie', cookieStr);
    }
    return true;
  }
  try {
    // @ts-ignore optional peer dependency loaded dynamically
    const headersMod: any = await import('next/headers').catch(() => null);
    if (headersMod?.cookies) {
      headersMod.cookies().set(name, '', { path: '/', expires: new Date(0) });
      return true;
    }
  } catch {}
  return false;
}

export const internalCookies = {
  getCookieName,
  applyAuthCookie,
  clearAuthCookie,
  createAuthCookieString,
  createLogoutCookieString,
  normalizeCookieOptions,
  getAuthCookieName
};
