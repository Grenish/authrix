// Minimal public surface; see subpath exports for frameworks and utilities.

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
