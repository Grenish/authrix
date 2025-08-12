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

// -------------------- Types --------------------
export type SupportedProvider =
  | 'google'
  | 'github'
  | 'apple'
  | 'discord'
  | 'facebook'
  | 'linkedin'
  | 'x';

interface ProviderUrlBuilderSync {
  (opts: { state: string }): string;
}

interface ProviderUrlBuilderAsync {
  (opts: { state: string }): Promise<{ url: string } | { url: string; state?: string }>;
}

type ProviderUrlBuilder = ProviderUrlBuilderSync | ProviderUrlBuilderAsync;

// Mapping of provider -> URL builder (kept internal)
const providerUrlBuilders: Record<string, ProviderUrlBuilder> = {
  google: getGoogleOAuthURL,
  github: getGitHubOAuthURL,
  apple: getAppleOAuthURL,
  discord: getDiscordOAuthURL,
  facebook: getFacebookOAuthURL,
  linkedin: getLinkedInOAuthURL,
  x: getXOAuthURL // async returning { url }
};

// Lazy handler dynamic imports (only when needed) for non-eager providers
async function invokeSSOHandler(provider: SupportedProvider, code: string, state: string, options: SSOOptions) {
  switch (provider) {
    case 'google':
      return handleGoogleSSO(code, options);
    case 'github':
      return handleGitHubSSO(code, options);
    case 'apple':
      return (await import('../core/sso')).handleAppleSSO(code, options);
    case 'discord':
      return (await import('../core/sso')).handleDiscordSSO(code, options);
    case 'facebook':
      return (await import('../core/sso')).handleFacebookSSO(code, options);
    case 'linkedin':
      return (await import('../core/sso')).handleLinkedInSSO(code, options);
    case 'x':
      return (await import('../core/sso')).handleXSSO(code, state, options);
    default:
      throw new Error(`Unsupported provider: ${provider}`);
  }
}

// -------------------- URL Helpers (granular) --------------------
export function buildProviderAuthUrl(provider: SupportedProvider, redirectUrl: string = '/dashboard'): Promise<string> | string {
  const state = generateSSOState({ redirect: redirectUrl });
  const builder = providerUrlBuilders[provider];
  if (!builder) throw new Error(`No OAuth URL builder registered for provider: ${provider}`);
  const result = builder({ state } as any);
  if (result && typeof (result as any).then === 'function') {
    // async provider (X)
    return (result as Promise<any>).then(r => ('url' in r ? r.url : r));
  }
  return result as string;
}

export function getGoogleAuthUrl(redirectUrl?: string) { return buildProviderAuthUrl('google', redirectUrl); }
export function getGitHubAuthUrl(redirectUrl?: string) { return buildProviderAuthUrl('github', redirectUrl); }
export function getAppleAuthUrl(redirectUrl?: string) { return buildProviderAuthUrl('apple', redirectUrl); }
export function getDiscordAuthUrl(redirectUrl?: string) { return buildProviderAuthUrl('discord', redirectUrl); }
export function getFacebookAuthUrl(redirectUrl?: string) { return buildProviderAuthUrl('facebook', redirectUrl); }
export function getLinkedInAuthUrl(redirectUrl?: string) { return buildProviderAuthUrl('linkedin', redirectUrl); }
export function getXAuthUrl(redirectUrl?: string) { return buildProviderAuthUrl('x', redirectUrl); }

// Batch helper
export async function getAllAuthUrls(redirectUrl: string = '/dashboard', providers: SupportedProvider[] = ['google','github','apple','discord','facebook','linkedin','x']): Promise<Record<SupportedProvider, string>> {
  const entries = await Promise.all(providers.map(async p => [p, await buildProviderAuthUrl(p, redirectUrl)] as [SupportedProvider, string]));
  return Object.fromEntries(entries) as Record<SupportedProvider, string>;
}

/**
 * Universal SSO helpers that work with any framework
 */
export const ssoHelpers = {
  getGoogleAuthUrl,
  getGitHubAuthUrl,
  getAppleAuthUrl,
  getDiscordAuthUrl,
  getFacebookAuthUrl,
  getLinkedInAuthUrl,
  getXAuthUrl,
  buildProviderAuthUrl,
  getAllAuthUrls,
  async handleCallback(provider: SupportedProvider, code: string, state: string, options: SSOOptions = {}) {
    const stateData = verifySSOState(state);
    const result = await invokeSSOHandler(provider, code, state, options);
    return { ...result, redirectUrl: stateData.redirect || '/dashboard' };
  },
  generateState: (data?: any) => generateSSOState(data),
  verifyState: (state: string, maxAge?: number) => verifySSOState(state, maxAge)
};

/**
 * Universal forgot password helpers
 */
export const forgotPasswordHelpers = {
  initiate: (email: string, options: ForgotPasswordOptions = {}) => initiateForgotPassword(email, options),
  reset: (email: string, code: string, newPassword: string, options: ResetPasswordOptions = {}) =>
    resetPasswordWithCode(email, code, newPassword, options)
};

// Backwards-compatible named exports for tree-shaking (optional use)
export const generateState = (data?: any) => generateSSOState(data);
export const verifyState = (state: string, maxAge?: number) => verifySSOState(state, maxAge);
