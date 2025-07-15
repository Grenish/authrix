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
import { getGoogleOAuthURL } from "../providers/google";
import { getGitHubOAuthURL } from "../providers/github";

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
        cookies: { set: () => {} },
        body,
        status: init?.status || 200
      }),
      redirect: (url: string) => ({
        json: NextResponseClass.json,
        redirect: NextResponseClass.redirect,
        cookies: { set: () => {} },
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
      const authUrl = getGoogleOAuthURL(state);
      
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
      
      // Handle Google SSO
      const result = await handleGoogleSSO(code, options);
      
      // Set auth cookie
      const response = NextResponse.redirect(stateData.redirect || '/dashboard');
      response.cookies.set('auth_token', result.token, result.cookieOptions);
      
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
      const authUrl = getGitHubOAuthURL(state);
      
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
      
      // Handle GitHub SSO
      const result = await handleGitHubSSO(code, options);
      
      // Set auth cookie
      const response = NextResponse.redirect(stateData.redirect || '/dashboard');
      response.cookies.set('auth_token', result.token, result.cookieOptions);
      
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
      const authUrl = getGoogleOAuthURL(state);
      
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
      
      // Handle Google SSO
      const result = await handleGoogleSSO(code as string, options);
      
      // Set auth cookie
      res.cookie('auth_token', result.token, result.cookieOptions);
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
      const authUrl = getGitHubOAuthURL(state);
      
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
      
      // Handle GitHub SSO
      const result = await handleGitHubSSO(code as string, options);
      
      // Set auth cookie
      res.cookie('auth_token', result.token, result.cookieOptions);
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
    return getGoogleOAuthURL(state);
  },

  /**
   * Get GitHub OAuth URL
   */
  getGitHubAuthUrl(redirectUrl: string = '/dashboard'): string {
    const state = generateSSOState({ redirect: redirectUrl });
    return getGitHubOAuthURL(state);
  },

  /**
   * Handle OAuth callback
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
