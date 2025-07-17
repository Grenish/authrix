// === FORGOT PASSWORD ENTRY POINT ===
// Password recovery functions
// Import only when forgot password features are needed

// --- Forgot Password Functions ---
export { 
  initiateForgotPassword, 
  resetPasswordWithCode,
  generateTemporaryPassword,
  sendTemporaryPassword
} from "./core/forgotPassword";
export type { 
  ForgotPasswordOptions, 
  ResetPasswordOptions, 
  ForgotPasswordResult, 
  ResetPasswordResult 
} from "./core/forgotPassword";

// --- Framework Integration Helpers for Forgot Password ---
export { forgotPasswordHelpers } from "./frameworks/helpers";

// Re-export config functions to ensure proper sharing
export { initAuth, authConfig, isAuthrixInitialized, getAuthrixStatus } from "./config/index";
export type { AuthDbAdapter, AuthUser } from "./types/db";
