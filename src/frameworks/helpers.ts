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
import { getAppleOAuthURL } from "../providers/apple";
import { getDiscordOAuthURL } from "../providers/discord";
import { getFacebookOAuthURL } from "../providers/facebook";
import { getLinkedInOAuthURL } from "../providers/linkedin";
import { getXOAuthURL } from "../providers/x";

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
   * Get Apple OAuth URL with state
   */
  getAppleAuthUrl(redirectUrl: string = '/dashboard'): string {
    const state = generateSSOState({ redirect: redirectUrl });
    return getAppleOAuthURL({ state });
  },

  /**
   * Get Discord OAuth URL with state
   */
  getDiscordAuthUrl(redirectUrl: string = '/dashboard'): string {
    const state = generateSSOState({ redirect: redirectUrl });
    return getDiscordOAuthURL({ state });
  },

  /**
   * Get Facebook OAuth URL with state
   */
  getFacebookAuthUrl(redirectUrl: string = '/dashboard'): string {
    const state = generateSSOState({ redirect: redirectUrl });
    return getFacebookOAuthURL({ state });
  },

  /**
   * Get LinkedIn OAuth URL with state
   */
  getLinkedInAuthUrl(redirectUrl: string = '/dashboard'): string {
    const state = generateSSOState({ redirect: redirectUrl });
    return getLinkedInOAuthURL({ state });
  },

  /**
   * Get X/Twitter OAuth URL with state
   */
  async getXAuthUrl(redirectUrl: string = '/dashboard'): Promise<string> {
    const state = generateSSOState({ redirect: redirectUrl });
    const result = await getXOAuthURL({ state });
    return result.url;
  },

  /**
   * Handle OAuth callback (works with any provider)
   */
  async handleCallback(
    provider: 'google' | 'github' | 'apple' | 'discord' | 'facebook' | 'linkedin' | 'x',
    code: string,
    state: string,
    options: SSOOptions = {}
  ) {
    // Verify state
    const stateData = verifySSOState(state);
    
    // Handle SSO based on provider
    let result;
    switch (provider) {
      case 'google':
        result = await handleGoogleSSO(code, options);
        break;
      case 'github':
        result = await handleGitHubSSO(code, options);
        break;
      case 'apple':
        result = await (await import('../core/sso')).handleAppleSSO(code, options);
        break;
      case 'discord':
        result = await (await import('../core/sso')).handleDiscordSSO(code, options);
        break;
      case 'facebook':
        result = await (await import('../core/sso')).handleFacebookSSO(code, options);
        break;
      case 'linkedin':
        result = await (await import('../core/sso')).handleLinkedInSSO(code, options);
        break;
      case 'x':
        // For X we require state during callback for PKCE verification
        result = await (await import('../core/sso')).handleXSSO(code, state, options);
        break;
      default:
        throw new Error(`Unsupported provider: ${provider}`);
    }
    
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
