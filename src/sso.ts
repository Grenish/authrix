// === SSO ENTRY POINT ===
// Single Sign-On and OAuth functions
// Import only when SSO features are needed

// --- SSO & OAuth Functions ---
export { 
  handleGoogleSSO, 
  handleGitHubSSO, 
  handleCustomSSO,
  processSSOAuthentication,
  generateSSOState,
  verifySSOState
} from "./core/sso";
export type { SSOUser, SSOOptions, SSOResult } from "./core/sso";

// --- Framework Integration Helpers for SSO ---
export { ssoHelpers } from "./frameworks/helpers";

// Re-export config functions to ensure proper sharing
export { initAuth, authConfig, isAuthrixInitialized, getAuthrixStatus } from "./config/index";
export type { AuthDbAdapter, AuthUser } from "./types/db";
