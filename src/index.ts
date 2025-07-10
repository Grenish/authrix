// --- Core Authentication Functions ---
export { signup, signupCore } from "./core/signup";
export { signin, signinCore } from "./core/signin";
export { logout, logoutCore } from "./core/logout";
export { getCurrentUser, getCurrentUserFromToken, isAuthenticated, isTokenValid } from "./core/session";

// --- Middleware ---
export { requireAuth } from "./core/requireAuth";
export { authMiddleware } from "./middleware/authMiddleware";
export { createAuthMiddleware, optionalAuthMiddleware } from "./middleware/flexibleAuth";

// --- Configuration ---
export { initAuth, authConfig } from "./config/index";

// --- Database Adapters ---
export { mongoAdapter } from "./adapters/mongo";
export { supabaseAdapter } from "./adapters/supabase";
export { firebaseAdapter } from "./adapters/firebase";
// export { prismaAdapter } from "./adapters/prisma"; // Uncomment when prisma adapter is ready

// --- OAuth Providers ---
export { getGoogleOAuthURL, handleGoogleCallback } from "./providers/google";
export { getGitHubOAuthURL, handleGitHubCallback } from "./providers/github";

// --- Framework-Specific Utilities ---
// Universal (framework-agnostic)
export { 
  signupUniversal, 
  signinUniversal, 
  logoutUniversal,
  getCurrentUserUniversal,
  isTokenValidUniversal,
  validateAuth,
  createCookieString,
  parseCookies,
  getAuthTokenFromCookies,
  createAuthHeaders,
  createAuthError,
  createAuthSuccess
} from "./frameworks/universal";

// Next.js utilities
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
  // Middleware
  checkAuthMiddleware,
  createAuthenticatedResponse,
  withAuth
} from "./frameworks/nextjs";

// React utilities  
export {
  signupReact,
  signinReact,
  logoutReact,
  getCurrentUserReact,
  isAuthenticatedReact,
  getAuthToken,
  hasAuthToken,
  createUseAuthToken,
  withAuthReact
} from "./frameworks/react";

// --- Error Handling ---
export { errorHandler } from "./utils/response";
export {
  AuthrixError,
  BadRequestError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  ConflictError,
  InternalServerError,
} from "./utils/errors";

// --- Response Helpers ---
export { sendSuccess, sendError } from "./utils/response";

// --- Types ---
export type { AuthDbAdapter, AuthUser } from "./types/db";
export type { AuthenticatedRequest } from "./middleware/authMiddleware";
export type { TokenPayload } from "./tokens/verifyToken";
export type { AuthResult, LogoutResult, CookieOptions } from "./frameworks/universal";
