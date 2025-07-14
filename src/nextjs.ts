// Next.js specific entry point
export {
  // App Router
  signupNextApp,
  signinNextApp,
  logoutNextApp,
  getCurrentUserNextApp,
  isAuthenticatedNextApp,
  // Pages Router
  signupNextPages,
  signinNextPages,
  logoutNextPages,
  getCurrentUserNextPages,
  isAuthenticatedNextPages,
  // Flexible (works in both contexts)
  signupNextFlexible,
  signinNextFlexible,
  getCurrentUserNextFlexible,
  // Simplified production-ready functions (RECOMMENDED)
  signupNext,
  signinNext,
  logoutNext,
  getCurrentUserNext,
  isAuthenticatedNext,
  // Manual cookie helpers
  createAuthCookieString,
  createLogoutCookieString,
  // Middleware
  checkAuthMiddleware,
  checkAuthMiddlewareSecure,
  createAuthenticatedResponse,
  withAuth,
  createTokenValidationHandler,
  createTokenValidationHandlerPages,
  // Debugging
  getNextJsEnvironmentInfo
} from "./frameworks/nextjs";

// Re-export config functions to ensure proper sharing
export { initAuth, authConfig, isAuthrixInitialized, getAuthrixStatus } from "./config/index";
export type { AuthDbAdapter, AuthUser } from "./types/db";
