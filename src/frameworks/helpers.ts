/**
 * SSO and Forgot Password Integration Helpers
 * 
 * This module provides helper functions that can be used with any framework.
 * For framework-specific implementations, see the examples below.
 */

import { 
  handleGoogleSSO, 
  handleGitHubSSO, 
  generateSSOState, 
  verifySSOState,
  SSOOptions 
} from "../core/sso";
import { 
  initiateForgotPassword, 
  resetPasswordWithCode,
  ForgotPasswordOptions,
  ResetPasswordOptions 
} from "../core/forgotPassword";
import { getGoogleOAuthURL } from "../providers/google";
import { getGitHubOAuthURL } from "../providers/github";

/**
 * Universal SSO helpers that work with any framework
 */
export const ssoHelpers = {
  /**
   * Get Google OAuth URL with state
   */
  getGoogleAuthUrl(redirectUrl: string = '/dashboard'): string {
    const state = generateSSOState({ redirect: redirectUrl });
    return getGoogleOAuthURL({ state });
  },

  /**
   * Get GitHub OAuth URL with state
   */
  getGitHubAuthUrl(redirectUrl: string = '/dashboard'): string {
    const state = generateSSOState({ redirect: redirectUrl });
    return getGitHubOAuthURL({ state });
  },

  /**
   * Handle OAuth callback (works with any provider)
   */
  async handleCallback(
    provider: 'google' | 'github',
    code: string,
    state: string,
    options: SSOOptions = {}
  ) {
    // Verify state
    const stateData = verifySSOState(state);
    
    // Handle SSO based on provider
    const result = provider === 'google' 
      ? await handleGoogleSSO(code, options)
      : await handleGitHubSSO(code, options);
    
    return {
      ...result,
      redirectUrl: stateData.redirect || '/dashboard'
    };
  },

  /**
   * Generate secure state for OAuth
   */
  generateState(data?: any): string {
    return generateSSOState(data);
  },

  /**
   * Verify OAuth state
   */
  verifyState(state: string, maxAge?: number): any {
    return verifySSOState(state, maxAge);
  }
};

/**
 * Universal forgot password helpers
 */
export const forgotPasswordHelpers = {
  /**
   * Initiate password reset
   */
  async initiate(email: string, options: ForgotPasswordOptions = {}) {
    return await initiateForgotPassword(email, options);
  },

  /**
   * Reset password with verification code
   */
  async reset(email: string, code: string, newPassword: string, options: ResetPasswordOptions = {}) {
    return await resetPasswordWithCode(email, code, newPassword, options);
  }
};
