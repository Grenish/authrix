// Next.js specific entry point
export {
  // App Router
  signupNextApp,
  signinNextApp,
  logoutNextApp,
  getCurrentUserNextApp,
  isAuthenticatedNextApp,
  // Pages Router
  signupNextPages,
  signinNextPages,
  logoutNextPages,
  getCurrentUserNextPages,
  isAuthenticatedNextPages,
  // Middleware
  checkAuthMiddleware,
  createAuthenticatedResponse,
  withAuth
} from "./frameworks/nextjs";
