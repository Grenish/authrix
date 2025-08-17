// === AUTHRIX CORE - MINIMAL BUNDLE ===
// Essential authentication functions only
// For framework-specific features, import from dedicated modules:
//   Universal: import { signupUniversal } from 'authrix/universal'
//   Next.js: import { signupNextApp } from 'authrix/nextjs'
//   React: import { signupReact } from 'authrix/react'
//   OAuth: import { getGoogleOAuthURL } from 'authrix/oauth'
//   Adapters: import { mongoAdapter } from 'authrix/adapters/mongo'
//   Utils: import { AuthrixError } from 'authrix/utils'

// Legacy flat action/session exports removed – use auth namespace instead.
// Advanced / two-factor utilities intentionally withheld pending new advanced entrypoint.

// --- Configuration ---
export { initAuth, authConfig, isAuthrixInitialized, getAuthrixStatus } from "./config/index";

// --- Essential Middleware ---
export { requireAuth } from "./core/requireAuth";
export { authMiddleware } from "./middleware/authMiddleware";

// --- Essential Security Utilities ---
export { 
	hashPassword, 
	verifyPassword, 
	verifyAndCheckRehash, 
	validatePassword,
	generateSecurePassword,
	needsRehash
} from './utils/hash';

// Logger (new public utility; safe early import to avoid circular init)
export { logger, createLogger, reconfigureLogger } from './utils/logger';

// --- Core Types ---
export type { AuthDbAdapter, AuthUser } from "./types/db";
export type { AuthenticatedRequest } from "./middleware/authMiddleware";
export type { TokenPayload } from "./tokens/verifyToken";
export { auth, type AuthNamespace, type AuthActionResult } from './auth';
