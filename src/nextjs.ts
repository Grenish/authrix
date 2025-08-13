// Next.js specific entry point - All functions
export {
  // Recommended production-ready functions (use these for most cases)
  // (Action exports removed; use auth.actions.*)
  // Middleware functions
  checkAuthMiddleware,
  checkAuthMiddlewareSecure,
  withAuth,
  // Cookie helpers
  createAuthCookieString,
  createLogoutCookieString,
  // Advanced middleware
  createAuthenticatedResponse,
  createTokenValidationHandler,
  createTokenValidationHandlerPages,
  // API Route Handlers - App Router
  createSignupHandler,
  createSigninHandler,
  createLogoutHandler,
  createCurrentUserHandler,
  // API Route Handlers - Pages Router
  createSignupHandlerPages,
  createSigninHandlerPages,
  createLogoutHandlerPages,
  createCurrentUserHandlerPages,
  // Environment detection and debugging
  getNextJsEnvironmentInfo,
  redetectNextJsEnvironment,
  resetEnvironmentDetection,
  forceNextJsAvailability
} from "./frameworks/nextjs";

// Re-export config functions to ensure proper sharing
export { initAuth, authConfig, isAuthrixInitialized, getAuthrixStatus } from "./config/index";
export type { AuthDbAdapter, AuthUser } from "./types/db";
