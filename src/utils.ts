// Error handling utilities - separate module for optional import
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

// Response helpers
export { sendSuccess, sendError } from "./utils/response";

// Hash / password utilities (security helpers)
export {
  hashPassword,
  verifyPassword,
  verifyAndCheckRehash,
  validatePassword,
  generateSecurePassword,
  needsRehash
} from './utils/hash';
