import type { IncomingHttpHeaders } from "http";
import { validateAuth } from "../frameworks/universal";
import { authConfig } from "../config";

// Types
interface AuthResult {
  isValid: boolean;
  user: AuthUser | null;
  error: string | null;
  token?: string;
  expiresAt?: Date;
}

interface AuthUser {
  id: string;
  email: string;
  createdAt?: Date;
  emailVerified?: boolean;
  metadata?: Record<string, any>;
}

interface BaseRequest {
  headers?: IncomingHttpHeaders | Record<string, string | string[] | undefined>;
  cookies?: Record<string, string>;
  query?: Record<string, any>;
  body?: any;
  method?: string;
  url?: string;
  path?: string;
}

interface BaseResponse {
  status?: (code: number) => any;
  json?: (data: any) => any;
  send?: (data: any) => any;
  setHeader?: (name: string, value: string | string[]) => any;
  writeHead?: (statusCode: number, headers?: Record<string, string>) => any;
  end?: (data?: any) => any;
}

type NextFunction = (error?: any) => void | Promise<void>;

interface AuthMiddlewareOptions {
  required?: boolean;
  tokenExtractor?: TokenExtractor;
  errorHandler?: ErrorHandler;
  successHandler?: SuccessHandler;
  cookieName?: string;
  enableCache?: boolean;
  cacheTimeout?: number;
  allowedPaths?: string[] | RegExp[];
  excludedPaths?: string[] | RegExp[];
  roles?: string[];
  permissions?: string[];
  onUnauthorized?: (req: any, res: any) => void | Promise<void>;
  onForbidden?: (req: any, res: any) => void | Promise<void>;
}

type TokenExtractor = (req: any) => string | null | Promise<string | null>;
type ErrorHandler = (
  error: any,
  req: any,
  res: any,
  next?: any
) => void | Promise<void>;
type SuccessHandler = (
  authResult: AuthResult,
  req: any,
  res: any,
  next?: any
) => void | Promise<void>;

// Token extraction strategies
class TokenExtractors {
  static fromCookie(cookieName: string): TokenExtractor {
    return (req: BaseRequest) => {
      if (req.cookies?.[cookieName]) {
        return req.cookies[cookieName];
      }

      if (req.headers?.cookie) {
        const cookies = this.parseCookies(req.headers.cookie as string);
        return cookies[cookieName] || null;
      }

      return null;
    };
  }

  static fromHeader(
    headerName = "authorization",
    prefix = "Bearer "
  ): TokenExtractor {
    return (req: BaseRequest) => {
      const header = req.headers?.[headerName.toLowerCase()];
      if (!header) return null;

      const value = Array.isArray(header) ? header[0] : header;
      if (typeof value !== "string") return null;

      if (prefix && value.startsWith(prefix)) {
        return value.slice(prefix.length);
      }

      return value;
    };
  }

  static fromQuery(paramName = "token"): TokenExtractor {
    return (req: BaseRequest) => {
      return req.query?.[paramName] || null;
    };
  }

  static fromBody(fieldName = "token"): TokenExtractor {
    return (req: BaseRequest) => {
      return req.body?.[fieldName] || null;
    };
  }

  static chain(...extractors: TokenExtractor[]): TokenExtractor {
    return async (req: BaseRequest) => {
      for (const extractor of extractors) {
        const token = await extractor(req);
        if (token) return token;
      }
      return null;
    };
  }

  private static parseCookies(cookieString: string): Record<string, string> {
    const cookies: Record<string, string> = {};

    cookieString.split(/;\s*/).forEach((pair) => {
      const [key, ...values] = pair.split("=");
      if (key) {
        cookies[key] = values.join("=");
      }
    });

    return cookies;
  }
}

// Response handlers for different frameworks
class ResponseHandlers {
  static express(res: any, status: number, data: any): void {
    if (res.status && res.json) {
      res.status(status).json(data);
    } else if (res.writeHead && res.end) {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(data));
    }
  }

  static fastify(res: any, status: number, data: any): void {
    if (res.code && res.send) {
      res.code(status).send(data);
    } else {
      this.express(res, status, data);
    }
  }

  static koa(ctx: any, status: number, data: any): void {
    if (ctx.response) {
      ctx.response.status = status;
      ctx.response.body = data;
    } else if (ctx.status !== undefined && ctx.body !== undefined) {
      ctx.status = status;
      ctx.body = data;
    }
  }

  static auto(res: any, status: number, data: any): void {
    // Try different response methods
    if (res.status && res.json) {
      // Express-like
      this.express(res, status, data);
    } else if (res.code && res.send) {
      // Fastify-like
      this.fastify(res, status, data);
    } else if (
      res.response ||
      (res.status !== undefined && res.body !== undefined)
    ) {
      // Koa-like
      this.koa(res, status, data);
    } else if (res.writeHead && res.end) {
      // Node.js http
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(data));
    } else {
      throw new Error("Unsupported response object");
    }
  }
}

// Cache for auth results
class AuthCache {
  private cache = new Map<string, { result: AuthResult; timestamp: number }>();
  private timeout: number;

  constructor(timeout = 60000) {
    // Default 1 minute
    this.timeout = timeout;
  }

  get(token: string): AuthResult | null {
    const cached = this.cache.get(token);
    if (!cached) return null;

    if (Date.now() - cached.timestamp > this.timeout) {
      this.cache.delete(token);
      return null;
    }

    return cached.result;
  }

  set(token: string, result: AuthResult): void {
    this.cache.set(token, {
      result,
      timestamp: Date.now(),
    });

    // Cleanup old entries periodically
    if (this.cache.size > 1000) {
      this.cleanup();
    }
  }

  cleanup(): void {
    const now = Date.now();
    for (const [token, entry] of this.cache.entries()) {
      if (now - entry.timestamp > this.timeout) {
        this.cache.delete(token);
      }
    }
  }

  clear(): void {
    this.cache.clear();
  }
}

// Path matcher utility
class PathMatcher {
  static matches(path: string, patterns: (string | RegExp)[]): boolean {
    return patterns.some((pattern) => {
      if (typeof pattern === "string") {
        // Simple string matching with wildcard support
        const regex = new RegExp(
          "^" + pattern.replace(/\*/g, ".*").replace(/\?/g, ".") + "$"
        );
        return regex.test(path);
      }
      return pattern.test(path);
    });
  }
}

// Main middleware factory
export function createAuthMiddleware(options: AuthMiddlewareOptions = {}) {
  const {
    required = true,
    tokenExtractor = TokenExtractors.chain(
      TokenExtractors.fromCookie(options.cookieName || authConfig.cookieName),
      TokenExtractors.fromHeader("authorization", "Bearer ")
    ),
    errorHandler = defaultErrorHandler,
    successHandler,
    enableCache = true,
    cacheTimeout = 60000,
    allowedPaths = [],
    excludedPaths = [],
    roles = [],
    permissions = [],
    onUnauthorized,
    onForbidden,
  } = options;

  const cache = enableCache ? new AuthCache(cacheTimeout) : null;

  return async function authMiddleware(req: any, res: any, next?: any) {
    try {
      // Get request path
      const path = req.path || req.url || req.originalUrl || "";

      // Check if path is excluded
      if (
        excludedPaths.length > 0 &&
        PathMatcher.matches(path, excludedPaths)
      ) {
        return next?.();
      }

      // Check if path is not in allowed paths (if specified)
      if (allowedPaths.length > 0 && !PathMatcher.matches(path, allowedPaths)) {
        return next?.();
      }

      // Extract token
      const token = await tokenExtractor(req);

      // Get auth result (from cache if available)
      let authResult: AuthResult;

      if (cache && token) {
        const cached = cache.get(token);
        if (cached) {
          authResult = cached;
        } else {
          authResult = await validateAuth(token);
          cache.set(token, authResult);
        }
      } else {
        authResult = await validateAuth(token);
      }

      // Enhance request object
      enhanceRequest(req, authResult, token);

      // Check if authentication is required
      if (required && !authResult.isValid) {
        if (onUnauthorized) {
          return await onUnauthorized(req, res);
        }
        return errorHandler(
          new Error(authResult.error || "Authentication required"),
          req,
          res,
          next
        );
      }

      // Check roles if specified
      if (authResult.isValid && roles.length > 0) {
        const userRoles = authResult.user?.metadata?.roles || [];
        const hasRole = roles.some((role) => userRoles.includes(role));

        if (!hasRole) {
          if (onForbidden) {
            return await onForbidden(req, res);
          }
          return errorHandler(
            new Error("Insufficient permissions"),
            req,
            res,
            next
          );
        }
      }

      // Check permissions if specified
      if (authResult.isValid && permissions.length > 0) {
        const userPermissions = authResult.user?.metadata?.permissions || [];
        const hasPermission = permissions.every((perm) =>
          userPermissions.includes(perm)
        );

        if (!hasPermission) {
          if (onForbidden) {
            return await onForbidden(req, res);
          }
          return errorHandler(
            new Error("Insufficient permissions"),
            req,
            res,
            next
          );
        }
      }

      // Call success handler if provided
      if (successHandler) {
        return await successHandler(authResult, req, res, next);
      }

      // Continue to next middleware
      next?.();
    } catch (error) {
      return errorHandler(error, req, res, next);
    }
  };
}

// Enhance request with auth information
function enhanceRequest(
  req: any,
  authResult: AuthResult,
  token: string | null
): void {
  req.auth = authResult;
  req.user = authResult.user;
  req.isAuthenticated = authResult.isValid;
  req.token = token;

  // Add helper methods
  req.hasRole = (role: string) => {
    return req.user?.metadata?.roles?.includes(role) || false;
  };

  req.hasPermission = (permission: string) => {
    return req.user?.metadata?.permissions?.includes(permission) || false;
  };

  req.hasAnyRole = (roles: string[]) => {
    return roles.some((role) => req.hasRole(role));
  };

  req.hasAllPermissions = (permissions: string[]) => {
    return permissions.every((perm) => req.hasPermission(perm));
  };
}

// Default error handler
function defaultErrorHandler(error: any, req: any, res: any, next?: any): void {
  const status = error.status || 401;
  const message = error.message || "Authentication required";

  try {
    ResponseHandlers.auto(res, status, {
      success: false,
      error: { message },
    });
  } catch {
    // If auto-detection fails, try passing to next
    if (next) {
      next(error);
    } else {
      throw error;
    }
  }
}

// Framework-specific middleware factories
export const Middleware = {
  // Express middleware
  express(options?: AuthMiddlewareOptions) {
    return createAuthMiddleware(options);
  },

  // Fastify middleware
  fastify(options?: AuthMiddlewareOptions) {
    const middleware = createAuthMiddleware(options);
    return async (req: any, reply: any) => {
      await middleware(req, reply, () => {});
    };
  },

  // Koa middleware
  koa(options?: AuthMiddlewareOptions) {
    const middleware = createAuthMiddleware(options);
    return async (ctx: any, next: any) => {
      await middleware(ctx.request, ctx, next);
    };
  },

  // Hapi middleware
  hapi(options?: AuthMiddlewareOptions) {
    const middleware = createAuthMiddleware(options);
    return {
      method: async (request: any, h: any) => {
        return new Promise((resolve, reject) => {
          middleware(
            request,
            {
              status: (code: number) => ({
                json: (data: any) => h.response(data).code(code),
              }),
            },
            (error?: any) => {
              if (error) reject(error);
              else resolve(h.continue);
            }
          );
        });
      },
    };
  },
};

// Utility functions
export { TokenExtractors, ResponseHandlers, PathMatcher, AuthCache };

// Backward compatibility exports
export const authMiddleware = Middleware.express({ required: true });
export const optionalAuthMiddleware = Middleware.express({ required: false });

// Type exports for better TypeScript support
export type {
  AuthResult,
  AuthUser,
  AuthMiddlewareOptions,
  TokenExtractor,
  ErrorHandler,
  SuccessHandler,
  BaseRequest,
  BaseResponse,
  NextFunction,
};
