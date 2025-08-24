// Tree-shake friendly core barrel entrypoint (authrix/core)
import { signupCore } from './core/signup';
import { signinCore } from './core/signin';
import { logoutCore } from './core/logout';
import { getCurrentUserFromToken, isTokenValid } from './core/session';
import { requireAuth } from './core/requireAuth';
import { initAuth, authConfig, isAuthrixInitialized, getAuthrixStatus } from './config/index';
import { hashPassword, verifyPassword, verifyAndCheckRehash, validatePassword, generateSecurePassword, needsRehash } from './utils/hash';

export {
  initAuth, authConfig, isAuthrixInitialized, getAuthrixStatus,
  signupCore as signup,
  signinCore as signin,
  logoutCore as logout,
  getCurrentUserFromToken,
  isTokenValid,
  requireAuth,
  hashPassword,
  verifyPassword,
  verifyAndCheckRehash,
  validatePassword,
  generateSecurePassword,
  needsRehash
};

export type { AuthDbAdapter, AuthUser } from './types/db';
export type { TokenPayload } from './tokens/verifyToken';

// Pure module; no side effects.
