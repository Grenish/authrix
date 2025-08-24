import {
  signupCore,
  type SignupOptions,
  type SignupResult,
} from "./core/signup";
import {
  signinCore,
  type SigninOptions,
  type SigninResult,
} from "./core/signin";
import {
  logoutCore,
  type LogoutOptions,
  type LogoutResult,
} from "./core/logout";
import { getCurrentUserFromToken, isTokenValid } from "./core/session";
import { internalCookies } from "./internal/cookies";
import { requireAuth } from "./core/requireAuth";

// Lazy-loaded module cache
let nextModule: any = null;
let isNextLoading = false;
let nextLoadError: Error | null = null;

async function loadNext(): Promise<any | null> {
  if (nextModule) return nextModule;
  if (nextLoadError) return null;
  if (isNextLoading) {
    // Wait for ongoing load to complete
    await new Promise((resolve) => setTimeout(resolve, 10));
    return loadNext();
  }

  isNextLoading = true;
  try {
    nextModule = await import("./frameworks/nextjs");
    return nextModule;
  } catch (error) {
    nextLoadError = error as Error;
    return null;
  } finally {
    isNextLoading = false;
  }
}

// Types
interface ActionContext {
  res?: any;
  req?: any;
}

export interface AuthActionResult<TUser> {
  user: TUser;
  token?: string;
  meta?: Record<string, any>;
}

type NextRouteHandler = (request: Request) => Promise<Response>;

// Constants
const HANDLER_MAP = {
  signup: "createSignupHandler",
  signin: "createSigninHandler",
  logout: "createLogoutHandler",
  currentUser: "createCurrentUserHandler",
  validateToken: "createTokenValidationHandler",
} as const;

const ERROR_MESSAGES = {
  NOT_INITIALIZED:
    "Auth not initialized. Call initAuth({ jwtSecret, db }) before using handlers.",
  HANDLER_UNAVAILABLE: (name: string) => `${name} handler unavailable`,
  UNKNOWN_HANDLER: (name: string) => `Unknown handler ${name}`,
  NEXT_NOT_AVAILABLE: (name: string) =>
    `Next.js handlers not available (attempted: ${name}).`,
} as const;

// Helper functions
async function performAuth<T extends { user: any; token?: string }>(
  coreFn: () => Promise<T>,
  ctx?: ActionContext
): Promise<AuthActionResult<T["user"]>> {
  const result = await coreFn();
  // Future: attempt cookie set via next flexible util when available.
  void ctx; // placeholder to suppress unused warning
  return {
    user: result.user,
    token: result.token,
    meta: { source: "core" },
  };
}

async function resolveToken(ctx?: ActionContext): Promise<string | null> {
  if (!ctx?.req?.cookies) return null;
  const cookieName = internalCookies.getAuthCookieName();
  return ctx.req.cookies[cookieName] || null;
}

async function resolveHandler(name: keyof typeof HANDLER_MAP) {
  const mod = await loadNext();
  if (!mod) {
    throw new Error(ERROR_MESSAGES.NEXT_NOT_AVAILABLE(name));
  }

  const factoryName = HANDLER_MAP[name];
  const fnFactory = mod[factoryName];

  if (!fnFactory) {
    throw new Error(ERROR_MESSAGES.UNKNOWN_HANDLER(name));
  }

  return fnFactory();
}

function createErrorResponse(message: string, status = 500): Response {
  return Response.json({ success: false, error: { message } }, { status });
}

function createRouteHandler(
  handlerName: keyof typeof HANDLER_MAP,
  requiresInit = false
): NextRouteHandler {
  // Return an async function so dynamic imports still work inside without forcing outer factory async
  return async (request: Request) => {
    try {
      if (requiresInit) {
        const { isAuthrixInitialized } = await import("./config/index");
        if (!isAuthrixInitialized?.()) {
          return createErrorResponse(ERROR_MESSAGES.NOT_INITIALIZED);
        }
      }

      const handler = await resolveHandler(handlerName);
      return handler(request);
    } catch (err: any) {
      const message =
        err?.message || ERROR_MESSAGES.HANDLER_UNAVAILABLE(handlerName);
      return createErrorResponse(message);
    }
  };
}

// Middleware functions
function createMiddleware(attachUser: boolean) {
  return (handler: any) => async (req: any, res: any) => {
    try {
      const user = await getUser({ req });
      (req as any).user = user || null;
    } catch {
      if (attachUser) {
        (req as any).user = null;
      }
    }
    return handler(req, res);
  };
}

// Actions
const actions = {
  signup: (
    email: string,
    password: string,
    options: SignupOptions = {},
    ctx?: ActionContext
  ) => performAuth(() => signupCore(email, password, options), ctx),

  signin: (
    email: string,
    password: string,
    options: SigninOptions = {},
    ctx?: ActionContext
  ) => performAuth(() => signinCore(email, password, options), ctx),

  logout: (
    options: LogoutOptions = {},
    ctx?: ActionContext
  ): Promise<LogoutResult> => {
    void ctx;
    return logoutCore(options);
  },
} as const;

// Session
async function getUser(ctx?: ActionContext) {
  const token = await resolveToken(ctx);
  return getCurrentUserFromToken(token);
}

async function isAuthenticated(ctx?: ActionContext) {
  const token = await resolveToken(ctx);
  return isTokenValid(token);
}

const session = {
  getUser,
  isAuthenticated,
} as const;

// Middleware
const middleware = {
  require: requireAuth,
  guard: () => requireAuth,
  optional: createMiddleware(true),
  withUser: createMiddleware(true),
} as const;

// Handlers - lazy initialized
const handlers: Record<keyof typeof HANDLER_MAP, NextRouteHandler> = {
  get signup() {
    const handler = createRouteHandler("signup");
    Object.defineProperty(this, "signup", { value: handler });
    return handler;
  },
  get signin() {
    const handler = createRouteHandler("signin", true);
    Object.defineProperty(this, "signin", { value: handler });
    return handler;
  },
  get logout() {
    const handler = createRouteHandler("logout");
    Object.defineProperty(this, "logout", { value: handler });
    return handler;
  },
  get currentUser() {
    const handler = createRouteHandler("currentUser");
    Object.defineProperty(this, "currentUser", { value: handler });
    return handler;
  },
  get validateToken() {
    const handler = createRouteHandler("validateToken");
    Object.defineProperty(this, "validateToken", { value: handler });
    return handler;
  },
} as any;

// Cookies
const cookies = {
  create: (token: string, opts?: any) =>
    internalCookies.createAuthCookieString(token, opts),
  clear: () => internalCookies.createLogoutCookieString(),
} as const;

// Environment
const env = {
  detect: () => ({
    isNextJs:
      !!(globalThis as any).EdgeRuntime || !!(globalThis as any).__NEXT_DATA__,
  }),
  async next() {
    const mod = await loadNext();
    if (!mod) return null;

    return {
      info: mod.getNextJsEnvironmentInfo?.(),
      infoAsync: mod.getNextJsEnvironmentInfoAsync?.(),
      reset: mod.resetEnvironmentDetection,
      redetect: mod.redetectNextJsEnvironment,
      injectTest: mod.forceNextJsAvailability,
    };
  },
} as const;

// Main export
export const auth = {
  actions,
  session,
  middleware,
  handlers,
  cookies,
  env,
} as const;

export type AuthNamespace = typeof auth;
