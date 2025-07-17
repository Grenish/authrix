// Next.js specific entry point - All functions
export {
  // Recommended production-ready functions (use these for most cases)
  signupNext,
  signinNext,
  logoutNext,
  getCurrentUserNext,
  isAuthenticatedNext,
  // Flexible functions that work in both App Router and Pages Router
  signupNextFlexible,
  signinNextFlexible,
  getCurrentUserNextFlexible,
  // App Router specific
  signupNextApp,
  signinNextApp,
  logoutNextApp,
  getCurrentUserNextApp,
  isAuthenticatedNextApp,
  // Pages Router specific
  signupNextPages,
  signinNextPages,
  logoutNextPages,
  getCurrentUserNextPages,
  isAuthenticatedNextPages,
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
  // Environment detection and debugging
  getNextJsEnvironmentInfo,
  redetectNextJsEnvironment,
  forceNextJsAvailability
} from "./frameworks/nextjs";

// Re-export config functions to ensure proper sharing
export { initAuth, authConfig, isAuthrixInitialized, getAuthrixStatus } from "./config/index";
export type { AuthDbAdapter, AuthUser } from "./types/db";
