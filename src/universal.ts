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

// frameworks/universal exports AuthResponse (not AuthResult). Provide alias for backward compatibility.
import type { AuthResponse } from "./frameworks/universal";
export type { AuthResponse, CookieOptions, UniversalLogoutResult } from "./frameworks/universal";
// Backward-compatible alias: previous code may have imported AuthResult
export type AuthResult = AuthResponse;
export type { LogoutResult } from "./core/logout";

// Re-export config functions to ensure proper sharing
export { initAuth, authConfig, isAuthrixInitialized, getAuthrixStatus } from "./config/index";
export type { AuthDbAdapter, AuthUser } from "./types/db";
// 2FA utilities (re-export for universal consumers)
export {
  generateTwoFactorCode,
  verifyTwoFactorCode,
  initiateEmailVerification,
  initiateSMSVerification,
  getUserTwoFactorCodes
} from './core/twoFactor';
