// Universal/Framework-agnostic entry point
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

export type { AuthResult, CookieOptions, UniversalLogoutResult } from "./frameworks/universal";
export type { LogoutResult } from "./core/logout";

// Re-export config functions to ensure proper sharing
export { initAuth, authConfig, isAuthrixInitialized, getAuthrixStatus } from "./config/index";
export type { AuthDbAdapter, AuthUser } from "./types/db";
