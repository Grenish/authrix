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

export type { AuthResult, LogoutResult, CookieOptions } from "./frameworks/universal";
