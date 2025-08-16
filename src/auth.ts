// Unified Authrix namespace API (Phase: API Surface Consolidation P0)
// Provides grouped, discoverable entrypoints while preserving existing flat exports.
// Intent: Non-breaking addition. Legacy exports remain until deprecation cycle.

import { signupCore, type SignupOptions, type SignupResult } from './core/signup';
import { signinCore, type SigninOptions, type SigninResult } from './core/signin';
import { logoutCore, type LogoutOptions, type LogoutResult } from './core/logout';
import { getCurrentUserFromToken, isTokenValid } from './core/session';
import { internalCookies } from './internal/cookies';
import { warnDep } from './internal/deprecations';
import { requireAuth } from './core/requireAuth';
import { authConfig } from './config';

// Lazy dynamic import wrapper for Next.js specific utilities to avoid pulling them
// into non-Next environments / enable tree-shaking.
async function loadNext(): Promise<any | null> {
  try { return await import('./frameworks/nextjs'); } catch { return null; }
}

// Shared helpers
interface ActionContext { res?: any; req?: any; }

export interface AuthActionResult<TUser> { user: TUser; token?: string; meta?: Record<string, any>; }

async function performSignup(email: string, password: string, options: SignupOptions = {}, ctx?: ActionContext): Promise<AuthActionResult<SignupResult['user']>> {
  const coreResult = await signupCore(email, password, options);
  // Future: attempt cookie set via next flexible util when available.
  void ctx; // placeholder to suppress unused warning for now
  return { user: coreResult.user, token: coreResult.token, meta: { source: 'core' } };
}

async function performSignin(email: string, password: string, options: SigninOptions = {}, ctx?: ActionContext): Promise<AuthActionResult<SigninResult['user']>> {
  const coreResult = await signinCore(email, password, options);
  void ctx;
  return { user: coreResult.user, token: coreResult.token, meta: { source: 'core' } };
}

async function performLogout(options: LogoutOptions = {}, ctx?: ActionContext): Promise<LogoutResult> {
  void ctx;
  return logoutCore(options);
}

async function resolveToken(ctx?: ActionContext): Promise<string | null> {
  const cookieName = internalCookies.getAuthCookieName();
  const cookieVal = ctx?.req?.cookies?.[cookieName];
  return cookieVal || null;
}

async function getUser(ctx?: ActionContext) {
  const token = await resolveToken(ctx);
  return getCurrentUserFromToken(token);
}

async function isAuthed(ctx?: ActionContext) {
  const token = await resolveToken(ctx);
  return isTokenValid(token);
}

// Middleware variants
function middlewareGuard() { return requireAuth; }
function middlewareOptional(handler: any) {
  return async (req: any, res: any) => {
    try {
      const user = await getUser({ req });
      (req as any).user = user || null;
      return handler(req, res);
    } catch {
      (req as any).user = null;
      return handler(req, res);
    }
  };
}
function middlewareWithUser(handler: any) { return middlewareOptional(handler); }
const middleware = { require: requireAuth, guard: middlewareGuard(), optional: middlewareOptional, withUser: middlewareWithUser };

async function resolveHandler(name: string) {
  const mod = await loadNext();
  if (!mod) throw new Error(`Next.js handlers not available (attempted: ${name}).`);
  const map: Record<string, any> = {
    signup: mod.createSignupHandler,
    signin: mod.createSigninHandler,
    logout: mod.createLogoutHandler,
    currentUser: mod.createCurrentUserHandler,
    validateToken: mod.createTokenValidationHandler
  };
  const fnFactory = map[name];
  if (!fnFactory) throw new Error(`Unknown handler ${name}`);
  return fnFactory();
}
type NextRouteHandler = (request: Request) => Promise<Response>;

/**
 * Next.js App Router compatible handlers.
 * Usage in app route: `export const POST = auth.handlers.signup;`
 * Each handler is a request-bound wrapper that always returns a Response.
 */
const handlers: {
  signup: NextRouteHandler;
  signin: NextRouteHandler;
  logout: NextRouteHandler;
  currentUser: NextRouteHandler;
  validateToken: NextRouteHandler;
} = {
  signup: async (request: Request) => {
    try {
      const h = await resolveHandler('signup');
      return h(request);
    } catch (err: any) {
      const message = err?.message || 'Signup handler unavailable';
      return Response.json({ success: false, error: { message } }, { status: 500 });
    }
  },
  signin: async (request: Request) => {
    try {
      const h = await resolveHandler('signin');
      return h(request);
    } catch (err: any) {
      const message = err?.message || 'Signin handler unavailable';
      return Response.json({ success: false, error: { message } }, { status: 500 });
    }
  },
  logout: async (request: Request) => {
    try {
      const h = await resolveHandler('logout');
      return h(request);
    } catch (err: any) {
      const message = err?.message || 'Logout handler unavailable';
      return Response.json({ success: false, error: { message } }, { status: 500 });
    }
  },
  currentUser: async (request: Request) => {
    try {
      const h = await resolveHandler('currentUser');
      return h(request);
    } catch (err: any) {
      const message = err?.message || 'Current user handler unavailable';
      return Response.json({ success: false, error: { message } }, { status: 500 });
    }
  },
  validateToken: async (request: Request) => {
    try {
      const h = await resolveHandler('validateToken');
      return h(request);
    } catch (err: any) {
      const message = err?.message || 'Token validation handler unavailable';
      return Response.json({ success: false, error: { message } }, { status: 500 });
    }
  }
};

const cookies = {
  create: (token: string, opts?: any) => internalCookies.createAuthCookieString(token, opts),
  clear: () => internalCookies.createLogoutCookieString()
};

const env = {
  detect: () => ({ isNextJs: !!(globalThis as any).EdgeRuntime || !!(globalThis as any).__NEXT_DATA__ }),
  async next() {
    const mod = await loadNext();
    if (!mod) return null;
    return {
      info: mod.getNextJsEnvironmentInfo?.(),
      infoAsync: mod.getNextJsEnvironmentInfoAsync?.(),
      reset: mod.resetEnvironmentDetection,
      redetect: mod.redetectNextJsEnvironment,
      injectTest: mod.forceNextJsAvailability
    };
  }
};

export const auth = {
  actions: { signup: performSignup, signin: performSignin, logout: performLogout },
  session: { getUser, isAuthenticated: isAuthed },
  middleware,
  handlers,
  cookies,
  env
} as const;

export type AuthNamespace = typeof auth;
