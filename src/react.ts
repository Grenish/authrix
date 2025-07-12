// React specific entry point
export {
  signupReact,
  signinReact,
  logoutReact,
  getCurrentUserReact,
  isAuthenticatedReact,
  getAuthToken,
  hasAuthToken,
  createUseAuthToken,
  withAuthReact
} from "./frameworks/react";

// Re-export config functions to ensure proper sharing
export { initAuth, authConfig } from "./config/index";
export type { AuthDbAdapter, AuthUser } from "./types/db";
