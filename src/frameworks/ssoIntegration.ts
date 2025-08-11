// Note: Framework-specific imports are optional and loaded dynamically to avoid dependencies
// import { NextRequest, NextResponse } from "next/server"; // Optional Next.js
// import { Request, Response } from "express"; // Optional Express

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

// Import all OAuth providers
import { getGoogleOAuthURL, handleGoogleCallback } from "../providers/google";
import { getGitHubOAuthURL, handleGitHubCallback } from "../providers/github";
import { getAppleOAuthURL, handleAppleCallback } from "../providers/apple";
import { getDiscordOAuthURL, handleDiscordCallback } from "../providers/discord";
import { getFacebookOAuthURL, handleFacebookCallback } from "../providers/facebook";
import { getLinkedInOAuthURL, handleLinkedInCallback } from "../providers/linkedin";
import { getXOAuthURL, handleXCallback } from "../providers/x";

// Type definitions for Next.js (optional dependency)
interface NextRequest {
  url: string;
  json(): Promise<any>;
}

interface NextResponse {
  json(body: any, init?: { status?: number }): NextResponse;
  redirect(url: string): NextResponse;
  cookies: {
    set(name: string, value: string, options?: any): void;
  };
}

// Helper function to create NextResponse-like object
const createNextResponse = () => {
  let NextResponseClass: any;

  try {
    // Try to import NextResponse dynamically
    const nextServer = require('next/server');
    NextResponseClass = nextServer.NextResponse;
  } catch {
    // Fallback implementation if Next.js is not available
    NextResponseClass = {
      json: (body: any, init?: { status?: number }) => ({
        json: NextResponseClass.json,
        redirect: NextResponseClass.redirect,
        cookies: { set: () => { } },
        body,
        status: init?.status || 200
      }),
      redirect: (url: string) => ({
        json: NextResponseClass.json,
        redirect: NextResponseClass.redirect,
        cookies: { set: () => { } },
        redirectUrl: url
      })
    };
  }

  return NextResponseClass;
};

// Type definitions for Express (optional dependency)
interface Request {
  url: string;
  query: any;
  body: any;
}

interface Response {
  json(body: any): void;
  status(code: number): Response;
  redirect(url: string): void;
  cookie(name: string, value: string, options?: any): void;
}

// Generic OAuth user type (common structure across all providers)
interface GenericOAuthUser {
  id: string;
  email?: string;
  name?: string;
  username?: string;
  avatar?: string;
  provider: string;
  emailVerified: boolean;
  metadata?: Record<string, any>;
  tokens?: {
    access?: string;
    refresh?: string;
    idToken?: string;
    [key: string]: any;
  };
}

// Universal callback result type
interface UniversalCallbackResult {
  user: GenericOAuthUser;
  tokens: any;
  redirectUrl: string;
}

/**
 * Next.js App Router SSO handlers
 */
export const nextSSO = {
  /**
   * Handle Google OAuth initiation
   */
  async initiateGoogle(request: NextRequest): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const redirectUrl = url.searchParams.get('redirect') || '/dashboard';

      const state = generateSSOState({ redirect: redirectUrl });
      const authUrl = getGoogleOAuthURL({ state });

      return NextResponse.redirect(authUrl);
    } catch (error) {
      const NextResponse = createNextResponse();
      return NextResponse.json(
        { error: error instanceof Error ? error.message : 'Failed to initiate Google OAuth' },
        { status: 500 }
      );
    }
  },

  /**
   * Handle Google OAuth callback
   */
  async callbackGoogle(request: NextRequest, options: SSOOptions = {}): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');

      if (!code) {
        return NextResponse.json({ error: 'Authorization code not provided' }, { status: 400 });
      }

      if (!state) {
        return NextResponse.json({ error: 'State parameter not provided' }, { status: 400 });
      }

      // Verify state
      const stateData = verifySSOState(state);

      // Handle Google OAuth using provider callback
      const result = await handleGoogleCallback(code, { includeTokens: true });

      // Set auth cookie
      const response = NextResponse.redirect(stateData.redirect || '/dashboard');
      response.cookies.set('auth_token', result.id, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/'
      });

      return response;
    } catch (error) {
      const NextResponse = createNextResponse();
      const errorUrl = new URL('/auth/error', request.url);
      errorUrl.searchParams.set('message', error instanceof Error ? error.message : 'Authentication failed');
      return NextResponse.redirect(errorUrl);
    }
  },

  /**
   * Handle GitHub OAuth initiation
   */
  async initiateGitHub(request: NextRequest): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const redirectUrl = url.searchParams.get('redirect') || '/dashboard';

      const state = generateSSOState({ redirect: redirectUrl });
      const authUrl = getGitHubOAuthURL({ state });

      return NextResponse.redirect(authUrl);
    } catch (error) {
      const NextResponse = createNextResponse();
      return NextResponse.json(
        { error: error instanceof Error ? error.message : 'Failed to initiate GitHub OAuth' },
        { status: 500 }
      );
    }
  },

  /**
   * Handle GitHub OAuth callback
   */
  async callbackGitHub(request: NextRequest, options: SSOOptions = {}): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');

      if (!code) {
        return NextResponse.json({ error: 'Authorization code not provided' }, { status: 400 });
      }

      if (!state) {
        return NextResponse.json({ error: 'State parameter not provided' }, { status: 400 });
      }

      // Verify state
      const stateData = verifySSOState(state);

      // Handle GitHub OAuth using provider callback
      const result = await handleGitHubCallback(code, { includeToken: true });

      // Set auth cookie
      const response = NextResponse.redirect(stateData.redirect || '/dashboard');
      response.cookies.set('auth_token', result.id, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/'
      });

      return response;
    } catch (error) {
      const NextResponse = createNextResponse();
      const errorUrl = new URL('/auth/error', request.url);
      errorUrl.searchParams.set('message', error instanceof Error ? error.message : 'Authentication failed');
      return NextResponse.redirect(errorUrl);
    }
  },

  /**
   * Handle Apple OAuth initiation
   */
  async initiateApple(request: NextRequest): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const redirectUrl = url.searchParams.get('redirect') || '/dashboard';

      const state = generateSSOState({ redirect: redirectUrl });
      const authUrl = getAppleOAuthURL({ state });

      return NextResponse.redirect(authUrl);
    } catch (error) {
      const NextResponse = createNextResponse();
      return NextResponse.json(
        { error: error instanceof Error ? error.message : 'Failed to initiate Apple OAuth' },
        { status: 500 }
      );
    }
  },

  /**
   * Handle Apple OAuth callback
   */
  async callbackApple(request: NextRequest, options: SSOOptions = {}): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      const idToken = url.searchParams.get('id_token');
      const user = url.searchParams.get('user');

      if (!code) {
        return NextResponse.json({ error: 'Authorization code not provided' }, { status: 400 });
      }

      if (!state) {
        return NextResponse.json({ error: 'State parameter not provided' }, { status: 400 });
      }

      // Verify state
      const stateData = verifySSOState(state);

      // Handle Apple OAuth using provider callback
      const result = await handleAppleCallback(code, {
        idToken: idToken || undefined,
        user: user || undefined,
        state
      });

      // Set auth cookie
      const response = NextResponse.redirect(stateData.redirect || '/dashboard');
      response.cookies.set('auth_token', result.id, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/'
      });

      return response;
    } catch (error) {
      const NextResponse = createNextResponse();
      const errorUrl = new URL('/auth/error', request.url);
      errorUrl.searchParams.set('message', error instanceof Error ? error.message : 'Authentication failed');
      return NextResponse.redirect(errorUrl);
    }
  },

  /**
   * Handle Discord OAuth initiation
   */
  async initiateDiscord(request: NextRequest): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const redirectUrl = url.searchParams.get('redirect') || '/dashboard';

      const state = generateSSOState({ redirect: redirectUrl });
      const authUrl = getDiscordOAuthURL({ state });

      return NextResponse.redirect(authUrl);
    } catch (error) {
      const NextResponse = createNextResponse();
      return NextResponse.json(
        { error: error instanceof Error ? error.message : 'Failed to initiate Discord OAuth' },
        { status: 500 }
      );
    }
  },

  /**
   * Handle Discord OAuth callback
   */
  async callbackDiscord(request: NextRequest, options: SSOOptions = {}): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');

      if (!code) {
        return NextResponse.json({ error: 'Authorization code not provided' }, { status: 400 });
      }

      if (!state) {
        return NextResponse.json({ error: 'State parameter not provided' }, { status: 400 });
      }

      // Verify state
      const stateData = verifySSOState(state);

      // Handle Discord OAuth using provider callback
      const result = await handleDiscordCallback(code, {
        state,
        includeTokens: true
      });

      // Set auth cookie
      const response = NextResponse.redirect(stateData.redirect || '/dashboard');
      response.cookies.set('auth_token', result.id, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/'
      });

      return response;
    } catch (error) {
      const NextResponse = createNextResponse();
      const errorUrl = new URL('/auth/error', request.url);
      errorUrl.searchParams.set('message', error instanceof Error ? error.message : 'Authentication failed');
      return NextResponse.redirect(errorUrl);
    }
  },

  /**
   * Handle Facebook OAuth initiation
   */
  async initiateFacebook(request: NextRequest): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const redirectUrl = url.searchParams.get('redirect') || '/dashboard';

      const state = generateSSOState({ redirect: redirectUrl });
      const authUrl = getFacebookOAuthURL({ state });

      return NextResponse.redirect(authUrl);
    } catch (error) {
      const NextResponse = createNextResponse();
      return NextResponse.json(
        { error: error instanceof Error ? error.message : 'Failed to initiate Facebook OAuth' },
        { status: 500 }
      );
    }
  },

  /**
   * Handle Facebook OAuth callback
   */
  async callbackFacebook(request: NextRequest, options: SSOOptions = {}): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');

      if (!code) {
        return NextResponse.json({ error: 'Authorization code not provided' }, { status: 400 });
      }

      if (!state) {
        return NextResponse.json({ error: 'State parameter not provided' }, { status: 400 });
      }

      // Verify state
      const stateData = verifySSOState(state);

      // Handle Facebook OAuth using provider callback
      const result = await handleFacebookCallback(code, {
        state,
        includeTokens: true
      });

      // Set auth cookie
      const response = NextResponse.redirect(stateData.redirect || '/dashboard');
      response.cookies.set('auth_token', result.id, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/'
      });

      return response;
    } catch (error) {
      const NextResponse = createNextResponse();
      const errorUrl = new URL('/auth/error', request.url);
      errorUrl.searchParams.set('message', error instanceof Error ? error.message : 'Authentication failed');
      return NextResponse.redirect(errorUrl);
    }
  },

  /**
   * Handle LinkedIn OAuth initiation
   */
  async initiateLinkedIn(request: NextRequest): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const redirectUrl = url.searchParams.get('redirect') || '/dashboard';

      const state = generateSSOState({ redirect: redirectUrl });
      const authUrl = getLinkedInOAuthURL({ state });

      return NextResponse.redirect(authUrl);
    } catch (error) {
      const NextResponse = createNextResponse();
      return NextResponse.json(
        { error: error instanceof Error ? error.message : 'Failed to initiate LinkedIn OAuth' },
        { status: 500 }
      );
    }
  },

  /**
   * Handle LinkedIn OAuth callback
   */
  async callbackLinkedIn(request: NextRequest, options: SSOOptions = {}): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');

      if (!code) {
        return NextResponse.json({ error: 'Authorization code not provided' }, { status: 400 });
      }

      if (!state) {
        return NextResponse.json({ error: 'State parameter not provided' }, { status: 400 });
      }

      // Verify state
      const stateData = verifySSOState(state);

      // Handle LinkedIn OAuth using provider callback
      const result = await handleLinkedInCallback(code, {
        state,
        includeTokens: true
      });

      // Set auth cookie
      const response = NextResponse.redirect(stateData.redirect || '/dashboard');
      response.cookies.set('auth_token', result.id, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/'
      });

      return response;
    } catch (error) {
      const NextResponse = createNextResponse();
      const errorUrl = new URL('/auth/error', request.url);
      errorUrl.searchParams.set('message', error instanceof Error ? error.message : 'Authentication failed');
      return NextResponse.redirect(errorUrl);
    }
  },

  /**
   * Handle X/Twitter OAuth initiation
   */
  async initiateX(request: NextRequest): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const redirectUrl = url.searchParams.get('redirect') || '/dashboard';

      const state = generateSSOState({ redirect: redirectUrl });
      const authResult = await getXOAuthURL({ state });

      return NextResponse.redirect(authResult.url);
    } catch (error) {
      const NextResponse = createNextResponse();
      return NextResponse.json(
        { error: error instanceof Error ? error.message : 'Failed to initiate X OAuth' },
        { status: 500 }
      );
    }
  },

  /**
   * Handle X/Twitter OAuth callback
   */
  async callbackX(request: NextRequest, options: SSOOptions = {}): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');

      if (!code) {
        return NextResponse.json({ error: 'Authorization code not provided' }, { status: 400 });
      }

      if (!state) {
        return NextResponse.json({ error: 'State parameter not provided' }, { status: 400 });
      }

      // Verify state
      const stateData = verifySSOState(state);

      // Handle X OAuth using provider callback
      const result = await handleXCallback(code, state, {
        includeToken: true
      });

      // Set auth cookie
      const response = NextResponse.redirect(stateData.redirect || '/dashboard');
      response.cookies.set('auth_token', result.id, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/'
      });

      return response;
    } catch (error) {
      const NextResponse = createNextResponse();
      const errorUrl = new URL('/auth/error', request.url);
      errorUrl.searchParams.set('message', error instanceof Error ? error.message : 'Authentication failed');
      return NextResponse.redirect(errorUrl);
    }
  }
};

/**
 * Next.js App Router forgot password handlers
 */
export const nextForgotPassword = {
  /**
   * Initiate forgot password process
   */
  async initiate(request: NextRequest, options: ForgotPasswordOptions = {}): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const body = await request.json();
      const { email } = body;

      if (!email) {
        return NextResponse.json({ error: 'Email is required' }, { status: 400 });
      }

      const result = await initiateForgotPassword(email, options);

      return NextResponse.json(result);
    } catch (error) {
      const NextResponse = createNextResponse();
      return NextResponse.json(
        { error: error instanceof Error ? error.message : 'Failed to initiate password reset' },
        { status: 500 }
      );
    }
  },

  /**
   * Reset password with code
   */
  async reset(request: NextRequest, options: ResetPasswordOptions = {}): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const body = await request.json();
      const { email, code, newPassword } = body;

      if (!email || !code || !newPassword) {
        return NextResponse.json(
          { error: 'Email, code, and new password are required' },
          { status: 400 }
        );
      }

      const result = await resetPasswordWithCode(email, code, newPassword, options);

      return NextResponse.json(result);
    } catch (error) {
      const NextResponse = createNextResponse();
      return NextResponse.json(
        { error: error instanceof Error ? error.message : 'Failed to reset password' },
        { status: 500 }
      );
    }
  }
};

/**
 * Express.js SSO handlers
 */
export const expressSSO = {
  /**
   * Handle Google OAuth initiation
   */
  initiateGoogle(req: Request, res: Response): void {
    try {
      const redirectUrl = (req.query.redirect as string) || '/dashboard';

      const state = generateSSOState({ redirect: redirectUrl });
      const authUrl = getGoogleOAuthURL({ state });

      res.redirect(authUrl);
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Failed to initiate Google OAuth'
      });
    }
  },

  /**
   * Handle Google OAuth callback
   */
  async callbackGoogle(req: Request, res: Response, options: SSOOptions = {}): Promise<void> {
    try {
      const { code, state } = req.query;

      if (!code) {
        res.status(400).json({ error: 'Authorization code not provided' });
        return;
      }

      if (!state) {
        res.status(400).json({ error: 'State parameter not provided' });
        return;
      }

      // Verify state
      const stateData = verifySSOState(state as string);

      // Handle Google OAuth using provider callback
      const result = await handleGoogleCallback(code as string, { includeTokens: true });

      // Set auth cookie
      res.cookie('auth_token', result.id, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/'
      });
      res.redirect(stateData.redirect || '/dashboard');
    } catch (error) {
      res.redirect(`/auth/error?message=${encodeURIComponent(error instanceof Error ? error.message : 'Authentication failed')}`);
    }
  },

  /**
   * Handle GitHub OAuth initiation
   */
  initiateGitHub(req: Request, res: Response): void {
    try {
      const redirectUrl = (req.query.redirect as string) || '/dashboard';

      const state = generateSSOState({ redirect: redirectUrl });
      const authUrl = getGitHubOAuthURL({ state });

      res.redirect(authUrl);
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Failed to initiate GitHub OAuth'
      });
    }
  },

  /**
   * Handle GitHub OAuth callback
   */
  async callbackGitHub(req: Request, res: Response, options: SSOOptions = {}): Promise<void> {
    try {
      const { code, state } = req.query;

      if (!code) {
        res.status(400).json({ error: 'Authorization code not provided' });
        return;
      }

      if (!state) {
        res.status(400).json({ error: 'State parameter not provided' });
        return;
      }

      // Verify state
      const stateData = verifySSOState(state as string);

      // Handle GitHub OAuth using provider callback
      const result = await handleGitHubCallback(code as string, { includeToken: true });

      // Set auth cookie
      res.cookie('auth_token', result.id, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/'
      });
      res.redirect(stateData.redirect || '/dashboard');
    } catch (error) {
      res.redirect(`/auth/error?message=${encodeURIComponent(error instanceof Error ? error.message : 'Authentication failed')}`);
    }
  },

  /**
   * Handle Apple OAuth initiation
   */
  initiateApple(req: Request, res: Response): void {
    try {
      const redirectUrl = (req.query.redirect as string) || '/dashboard';

      const state = generateSSOState({ redirect: redirectUrl });
      const authUrl = getAppleOAuthURL({ state });

      res.redirect(authUrl);
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Failed to initiate Apple OAuth'
      });
    }
  },

  /**
   * Handle Apple OAuth callback
   */
  async callbackApple(req: Request, res: Response, options: SSOOptions = {}): Promise<void> {
    try {
      const { code, state, id_token, user } = req.body || req.query;

      if (!code) {
        res.status(400).json({ error: 'Authorization code not provided' });
        return;
      }

      if (!state) {
        res.status(400).json({ error: 'State parameter not provided' });
        return;
      }

      // Verify state
      const stateData = verifySSOState(state as string);

      // Handle Apple OAuth using provider callback
      const result = await handleAppleCallback(code as string, {
        idToken: id_token,
        user: user,
        state: state as string
      });

      // Set auth cookie
      res.cookie('auth_token', result.id, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/'
      });
      res.redirect(stateData.redirect || '/dashboard');
    } catch (error) {
      res.redirect(`/auth/error?message=${encodeURIComponent(error instanceof Error ? error.message : 'Authentication failed')}`);
    }
  },

  /**
   * Handle Discord OAuth initiation
   */
  initiateDiscord(req: Request, res: Response): void {
    try {
      const redirectUrl = (req.query.redirect as string) || '/dashboard';

      const state = generateSSOState({ redirect: redirectUrl });
      const authUrl = getDiscordOAuthURL({ state });

      res.redirect(authUrl);
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Failed to initiate Discord OAuth'
      });
    }
  },

  /**
   * Handle Discord OAuth callback
   */
  async callbackDiscord(req: Request, res: Response, options: SSOOptions = {}): Promise<void> {
    try {
      const { code, state } = req.query;

      if (!code) {
        res.status(400).json({ error: 'Authorization code not provided' });
        return;
      }

      if (!state) {
        res.status(400).json({ error: 'State parameter not provided' });
        return;
      }

      // Verify state
      const stateData = verifySSOState(state as string);

      // Handle Discord OAuth using provider callback
      const result = await handleDiscordCallback(code as string, {
        state: state as string,
        includeTokens: true
      });

      // Set auth cookie
      res.cookie('auth_token', result.id, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/'
      });
      res.redirect(stateData.redirect || '/dashboard');
    } catch (error) {
      res.redirect(`/auth/error?message=${encodeURIComponent(error instanceof Error ? error.message : 'Authentication failed')}`);
    }
  },

  /**
   * Handle Facebook OAuth initiation
   */
  initiateFacebook(req: Request, res: Response): void {
    try {
      const redirectUrl = (req.query.redirect as string) || '/dashboard';

      const state = generateSSOState({ redirect: redirectUrl });
      const authUrl = getFacebookOAuthURL({ state });

      res.redirect(authUrl);
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Failed to initiate Facebook OAuth'
      });
    }
  },

  /**
   * Handle Facebook OAuth callback
   */
  async callbackFacebook(req: Request, res: Response, options: SSOOptions = {}): Promise<void> {
    try {
      const { code, state } = req.query;

      if (!code) {
        res.status(400).json({ error: 'Authorization code not provided' });
        return;
      }

      if (!state) {
        res.status(400).json({ error: 'State parameter not provided' });
        return;
      }

      // Verify state
      const stateData = verifySSOState(state as string);

      // Handle Facebook OAuth using provider callback
      const result = await handleFacebookCallback(code as string, {
        state: state as string,
        includeTokens: true
      });

      // Set auth cookie
      res.cookie('auth_token', result.id, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/'
      });
      res.redirect(stateData.redirect || '/dashboard');
    } catch (error) {
      res.redirect(`/auth/error?message=${encodeURIComponent(error instanceof Error ? error.message : 'Authentication failed')}`);
    }
  },

  /**
   * Handle LinkedIn OAuth initiation
   */
  initiateLinkedIn(req: Request, res: Response): void {
    try {
      const redirectUrl = (req.query.redirect as string) || '/dashboard';

      const state = generateSSOState({ redirect: redirectUrl });
      const authUrl = getLinkedInOAuthURL({ state });

      res.redirect(authUrl);
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Failed to initiate LinkedIn OAuth'
      });
    }
  },

  /**
   * Handle LinkedIn OAuth callback
   */
  async callbackLinkedIn(req: Request, res: Response, options: SSOOptions = {}): Promise<void> {
    try {
      const { code, state } = req.query;

      if (!code) {
        res.status(400).json({ error: 'Authorization code not provided' });
        return;
      }

      if (!state) {
        res.status(400).json({ error: 'State parameter not provided' });
        return;
      }

      // Verify state
      const stateData = verifySSOState(state as string);

      // Handle LinkedIn OAuth using provider callback
      const result = await handleLinkedInCallback(code as string, {
        state: state as string,
        includeTokens: true
      });

      // Set auth cookie
      res.cookie('auth_token', result.id, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/'
      });
      res.redirect(stateData.redirect || '/dashboard');
    } catch (error) {
      res.redirect(`/auth/error?message=${encodeURIComponent(error instanceof Error ? error.message : 'Authentication failed')}`);
    }
  },

  /**
   * Handle X/Twitter OAuth initiation
   */
  async initiateX(req: Request, res: Response): Promise<void> {
    try {
      const redirectUrl = (req.query.redirect as string) || '/dashboard';

      const state = generateSSOState({ redirect: redirectUrl });
      const authResult = await getXOAuthURL({ state });

      res.redirect(authResult.url);
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Failed to initiate X OAuth'
      });
    }
  },

  /**
   * Handle X/Twitter OAuth callback
   */
  async callbackX(req: Request, res: Response, options: SSOOptions = {}): Promise<void> {
    try {
      const { code, state } = req.query;

      if (!code) {
        res.status(400).json({ error: 'Authorization code not provided' });
        return;
      }

      if (!state) {
        res.status(400).json({ error: 'State parameter not provided' });
        return;
      }

      // Verify state
      const stateData = verifySSOState(state as string);

      // Handle X OAuth using provider callback
      const result = await handleXCallback(code as string, state as string, {
        includeToken: true
      });

      // Set auth cookie
      res.cookie('auth_token', result.id, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/'
      });
      res.redirect(stateData.redirect || '/dashboard');
    } catch (error) {
      res.redirect(`/auth/error?message=${encodeURIComponent(error instanceof Error ? error.message : 'Authentication failed')}`);
    }
  }
};

/**
 * Express.js forgot password handlers
 */
export const expressForgotPassword = {
  /**
   * Initiate forgot password process
   */
  async initiate(req: Request, res: Response, options: ForgotPasswordOptions = {}): Promise<void> {
    try {
      const { email } = req.body;

      if (!email) {
        res.status(400).json({ error: 'Email is required' });
        return;
      }

      const result = await initiateForgotPassword(email, options);
      res.json(result);
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Failed to initiate password reset'
      });
    }
  },

  /**
   * Reset password with code
   */
  async reset(req: Request, res: Response, options: ResetPasswordOptions = {}): Promise<void> {
    try {
      const { email, code, newPassword } = req.body;

      if (!email || !code || !newPassword) {
        res.status(400).json({
          error: 'Email, code, and new password are required'
        });
        return;
      }

      const result = await resetPasswordWithCode(email, code, newPassword, options);
      res.json(result);
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Failed to reset password'
      });
    }
  }
};

/**
 * Universal helpers for any framework
 */
export const universalSSO = {
  /**
   * Get Google OAuth URL
   */
  getGoogleAuthUrl(redirectUrl: string = '/dashboard'): string {
    const state = generateSSOState({ redirect: redirectUrl });
    return getGoogleOAuthURL({ state });
  },

  /**
   * Get GitHub OAuth URL
   */
  getGitHubAuthUrl(redirectUrl: string = '/dashboard'): string {
    const state = generateSSOState({ redirect: redirectUrl });
    return getGitHubOAuthURL({ state });
  },

  /**
   * Get Apple OAuth URL
   */
  getAppleAuthUrl(redirectUrl: string = '/dashboard'): string {
    const state = generateSSOState({ redirect: redirectUrl });
    return getAppleOAuthURL({ state });
  },

  /**
   * Get Discord OAuth URL
   */
  getDiscordAuthUrl(redirectUrl: string = '/dashboard'): string {
    const state = generateSSOState({ redirect: redirectUrl });
    return getDiscordOAuthURL({ state });
  },

  /**
   * Get Facebook OAuth URL
   */
  getFacebookAuthUrl(redirectUrl: string = '/dashboard'): string {
    const state = generateSSOState({ redirect: redirectUrl });
    return getFacebookOAuthURL({ state });
  },

  /**
   * Get LinkedIn OAuth URL
   */
  getLinkedInAuthUrl(redirectUrl: string = '/dashboard'): string {
    const state = generateSSOState({ redirect: redirectUrl });
    return getLinkedInOAuthURL({ state });
  },

  /**
   * Get X/Twitter OAuth URL
   */
  async getXAuthUrl(redirectUrl: string = '/dashboard'): Promise<string> {
    const state = generateSSOState({ redirect: redirectUrl });
    const authResult = await getXOAuthURL({ state });
    return authResult.url;
  },

  /**
   * Handle OAuth callback for any provider
   */
  async handleCallback(
    provider: 'google' | 'github' | 'apple' | 'discord' | 'facebook' | 'linkedin' | 'x',
    code: string,
    state: string,
    options: any = {}
  ): Promise<UniversalCallbackResult> {
    // Verify state
    const stateData = verifySSOState(state);

    // Handle SSO based on provider
    let result: GenericOAuthUser;
    switch (provider) {
      case 'google':
        result = await handleGoogleCallback(code, { includeTokens: true, ...options });
        break;
      case 'github':
        result = await handleGitHubCallback(code, { includeToken: true, ...options });
        break;
      case 'apple':
        result = await handleAppleCallback(code, { state, ...options });
        break;
      case 'discord':
        result = await handleDiscordCallback(code, { state, includeTokens: true, ...options });
        break;
      case 'facebook':
        result = await handleFacebookCallback(code, { state, includeTokens: true, ...options });
        break;
      case 'linkedin':
        result = await handleLinkedInCallback(code, { state, includeTokens: true, ...options });
        break;
      case 'x':
        result = await handleXCallback(code, state, { includeToken: true, ...options });
        break;
      default:
        throw new Error(`Unsupported provider: ${provider}`);
    }

    return {
      user: result,
      tokens: result.tokens || null,
      redirectUrl: stateData.redirect || '/dashboard'
    };
  },

  /**
   * Get all available OAuth URLs
   */
  async getAllAuthUrls(redirectUrl: string = '/dashboard'): Promise<Record<string, string>> {
    return {
      google: this.getGoogleAuthUrl(redirectUrl),
      github: this.getGitHubAuthUrl(redirectUrl),
      apple: this.getAppleAuthUrl(redirectUrl),
      discord: this.getDiscordAuthUrl(redirectUrl),
      facebook: this.getFacebookAuthUrl(redirectUrl),
      linkedin: this.getLinkedInAuthUrl(redirectUrl),
      x: await this.getXAuthUrl(redirectUrl)
    };
  },

  /**
   * Get supported providers list
   */
  getSupportedProviders(): string[] {
    return ['google', 'github', 'apple', 'discord', 'facebook', 'linkedin', 'x'];
  }
};

/**
 * Universal forgot password helpers
 */
export const universalForgotPassword = {
  /**
   * Initiate password reset
   */
  async initiate(email: string, options: ForgotPasswordOptions = {}) {
    return await initiateForgotPassword(email, options);
  },

  /**
   * Reset password
   */
  async reset(email: string, code: string, newPassword: string, options: ResetPasswordOptions = {}) {
    return await resetPasswordWithCode(email, code, newPassword, options);
  }
};
