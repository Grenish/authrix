// --- Core Authentication Functions ---
export { signup } from "./core/signup";
export { signin } from "./core/signin";
export { logout } from "./core/logout";
export { getCurrentUser, isAuthenticated } from "./core/session";

// --- Middleware ---
export { requireAuth } from "./core/requireAuth";
export { authMiddleware } from "./middleware/authMiddleware";

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
