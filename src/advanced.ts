// Advanced entrypoint exposing low-level core primitives.
import { signupCore } from './core/signup';
import { signinCore } from './core/signin';
import { logoutCore } from './core/logout';
import { getCurrentUserFromToken, isTokenValid } from './core/session';
import { generateTwoFactorCode, verifyTwoFactorCode, initiateEmailVerification, initiateSMSVerification, sendVerificationEmail, sendVerificationSMS, getUserTwoFactorCodes, cleanupExpiredCodes } from './core/twoFactor';
import { EmailServiceRegistry } from './core/emailRegistry';
import { hashPassword, verifyPassword, verifyAndCheckRehash, validatePassword, generateSecurePassword, needsRehash } from './utils/hash';

export const core = {
  signup: signupCore,
  signin: signinCore,
  logout: logoutCore,
  getCurrentUserFromToken,
  isTokenValid
};

export const twoFactor = {
  generateTwoFactorCode,
  verifyTwoFactorCode,
  initiateEmailVerification,
  initiateSMSVerification,
  sendVerificationEmail,
  sendVerificationSMS,
  getUserTwoFactorCodes,
  cleanupExpiredCodes,
  EmailServiceRegistry
};

export const hash = {
  hashPassword,
  verifyPassword,
  verifyAndCheckRehash,
  validatePassword,
  generateSecurePassword,
  needsRehash
};

// Direct re-exports for granular named imports
export { signupCore, signinCore, logoutCore };
export { getCurrentUserFromToken, isTokenValid };
export { generateTwoFactorCode, verifyTwoFactorCode, initiateEmailVerification, initiateSMSVerification, sendVerificationEmail, sendVerificationSMS, getUserTwoFactorCodes, cleanupExpiredCodes };
export { EmailServiceRegistry } from './core/emailRegistry';
export { hashPassword, verifyPassword, verifyAndCheckRehash, validatePassword, generateSecurePassword, needsRehash };
