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
    return getGoogleOAuthURL(state);
  },

  /**
   * Get GitHub OAuth URL with state
   */
  getGitHubAuthUrl(redirectUrl: string = '/dashboard'): string {
    const state = generateSSOState({ redirect: redirectUrl });
    return getGitHubOAuthURL(state);
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

/**
 * Example usage with Next.js App Router
 * 
 * // app/api/auth/google/route.ts
 * import { ssoHelpers } from '@/lib/authrix/frameworks/helpers';
 * 
 * export async function GET(request: NextRequest) {
 *   const url = new URL(request.url);
 *   const redirectUrl = url.searchParams.get('redirect') || '/dashboard';
 *   const authUrl = ssoHelpers.getGoogleAuthUrl(redirectUrl);
 *   return NextResponse.redirect(authUrl);
 * }
 * 
 * // app/api/auth/google/callback/route.ts
 * export async function GET(request: NextRequest) {
 *   try {
 *     const url = new URL(request.url);
 *     const code = url.searchParams.get('code');
 *     const state = url.searchParams.get('state');
 *     
 *     if (!code || !state) {
 *       return NextResponse.json({ error: 'Missing parameters' }, { status: 400 });
 *     }
 * 
 *     const result = await ssoHelpers.handleCallback('google', code, state);
 *     
 *     const response = NextResponse.redirect(result.redirectUrl);
 *     response.cookies.set('auth_token', result.token, result.cookieOptions);
 *     return response;
 *   } catch (error) {
 *     return NextResponse.redirect('/auth/error?message=' + encodeURIComponent(error.message));
 *   }
 * }
 * 
 * // app/api/auth/forgot-password/route.ts
 * import { forgotPasswordHelpers } from '@/lib/authrix/frameworks/helpers';
 * 
 * export async function POST(request: NextRequest) {
 *   try {
 *     const { email } = await request.json();
 *     const result = await forgotPasswordHelpers.initiate(email);
 *     return NextResponse.json(result);
 *   } catch (error) {
 *     return NextResponse.json({ error: error.message }, { status: 500 });
 *   }
 * }
 * 
 * // app/api/auth/reset-password/route.ts
 * export async function POST(request: NextRequest) {
 *   try {
 *     const { email, code, newPassword } = await request.json();
 *     const result = await forgotPasswordHelpers.reset(email, code, newPassword);
 *     return NextResponse.json(result);
 *   } catch (error) {
 *     return NextResponse.json({ error: error.message }, { status: 500 });
 *   }
 * }
 */

/**
 * Example usage with Express.js
 * 
 * import express from 'express';
 * import { ssoHelpers, forgotPasswordHelpers } from './authrix/frameworks/helpers';
 * 
 * const router = express.Router();
 * 
 * // Google OAuth initiation
 * router.get('/auth/google', (req, res) => {
 *   const redirectUrl = req.query.redirect || '/dashboard';
 *   const authUrl = ssoHelpers.getGoogleAuthUrl(redirectUrl);
 *   res.redirect(authUrl);
 * });
 * 
 * // Google OAuth callback
 * router.get('/auth/google/callback', async (req, res) => {
 *   try {
 *     const { code, state } = req.query;
 *     const result = await ssoHelpers.handleCallback('google', code, state);
 *     
 *     res.cookie('auth_token', result.token, result.cookieOptions);
 *     res.redirect(result.redirectUrl);
 *   } catch (error) {
 *     res.redirect('/auth/error?message=' + encodeURIComponent(error.message));
 *   }
 * });
 * 
 * // Forgot password
 * router.post('/auth/forgot-password', async (req, res) => {
 *   try {
 *     const { email } = req.body;
 *     const result = await forgotPasswordHelpers.initiate(email);
 *     res.json(result);
 *   } catch (error) {
 *     res.status(500).json({ error: error.message });
 *   }
 * });
 * 
 * // Reset password
 * router.post('/auth/reset-password', async (req, res) => {
 *   try {
 *     const { email, code, newPassword } = req.body;
 *     const result = await forgotPasswordHelpers.reset(email, code, newPassword);
 *     res.json(result);
 *   } catch (error) {
 *     res.status(500).json({ error: error.message });
 *   }
 * });
 */

/**
 * Example usage with React (client-side)
 * 
 * import { ssoHelpers } from './authrix/frameworks/helpers';
 * 
 * // Component for social login
 * export function SocialLoginButtons() {
 *   const handleGoogleLogin = () => {
 *     const authUrl = ssoHelpers.getGoogleAuthUrl(window.location.pathname);
 *     window.location.href = authUrl;
 *   };
 * 
 *   const handleGitHubLogin = () => {
 *     const authUrl = ssoHelpers.getGitHubAuthUrl(window.location.pathname);
 *     window.location.href = authUrl;
 *   };
 * 
 *   return (
 *     <div>
 *       <button onClick={handleGoogleLogin}>Login with Google</button>
 *       <button onClick={handleGitHubLogin}>Login with GitHub</button>
 *     </div>
 *   );
 * }
 * 
 * // Component for forgot password
 * export function ForgotPasswordForm() {
 *   const [email, setEmail] = useState('');
 *   const [isLoading, setIsLoading] = useState(false);
 * 
 *   const handleSubmit = async (e) => {
 *     e.preventDefault();
 *     setIsLoading(true);
 *     
 *     try {
 *       const response = await fetch('/api/auth/forgot-password', {
 *         method: 'POST',
 *         headers: { 'Content-Type': 'application/json' },
 *         body: JSON.stringify({ email })
 *       });
 *       
 *       const result = await response.json();
 *       if (result.success) {
 *         alert('Password reset code sent to your email');
 *       }
 *     } catch (error) {
 *       alert('Error: ' + error.message);
 *     } finally {
 *       setIsLoading(false);
 *     }
 *   };
 * 
 *   return (
 *     <form onSubmit={handleSubmit}>
 *       <input
 *         type="email"
 *         value={email}
 *         onChange={(e) => setEmail(e.target.value)}
 *         placeholder="Enter your email"
 *         required
 *       />
 *       <button type="submit" disabled={isLoading}>
 *         {isLoading ? 'Sending...' : 'Send Reset Code'}
 *       </button>
 *     </form>
 *   );
 * }
 */
