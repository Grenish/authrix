import {
  handleGoogleSSO,
  handleGitHubSSO,
  handleAppleSSO,
  handleDiscordSSO,
  handleFacebookSSO,
  handleLinkedInSSO,
  handleXSSO,
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

// Optional Next.js type shims (when Next.js isn't installed)
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

// Dynamically use NextResponse if available; otherwise provide a minimal fallback
const createNextResponse = () => {
  let NextResponseClass: any;
  try {
    const nextServer = require('next/server');
    NextResponseClass = nextServer.NextResponse;
  } catch {
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

// Optional Express type shims
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

// Common OAuth user shape
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

interface UniversalCallbackResult {
  user: GenericOAuthUser;
  tokens: any;
  redirectUrl: string;
}

// Next.js App Router SSO handlers
export const nextSSO = {
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

  async callbackGoogle(request: NextRequest, options: SSOOptions = {}): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');

      if (!code) return NextResponse.json({ error: 'Authorization code not provided' }, { status: 400 });
      if (!state) return NextResponse.json({ error: 'State parameter not provided' }, { status: 400 });

      const stateData = verifySSOState(state);
      const ssoResult = await handleGoogleSSO(code, options);
      const response = NextResponse.redirect(stateData.redirect || '/dashboard');
      response.cookies.set('auth_token', ssoResult.token, { ...ssoResult.cookieOptions });
      return response;
    } catch (error) {
      const NextResponse = createNextResponse();
      const errorUrl = new URL('/auth/error', request.url);
      errorUrl.searchParams.set('message', error instanceof Error ? error.message : 'Authentication failed');
      return NextResponse.redirect(errorUrl);
    }
  },

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

  async callbackGitHub(request: NextRequest, options: SSOOptions = {}): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');

      if (!code) return NextResponse.json({ error: 'Authorization code not provided' }, { status: 400 });
      if (!state) return NextResponse.json({ error: 'State parameter not provided' }, { status: 400 });

      const stateData = verifySSOState(state);
      const ssoResult = await handleGitHubSSO(code, options);
      const response = NextResponse.redirect(stateData.redirect || '/dashboard');
      response.cookies.set('auth_token', ssoResult.token, { ...ssoResult.cookieOptions });
      return response;
    } catch (error) {
      const NextResponse = createNextResponse();
      const errorUrl = new URL('/auth/error', request.url);
      errorUrl.searchParams.set('message', error instanceof Error ? error.message : 'Authentication failed');
      return NextResponse.redirect(errorUrl);
    }
  },

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

  async callbackApple(request: NextRequest, options: SSOOptions = {}): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');

      if (!code) return NextResponse.json({ error: 'Authorization code not provided' }, { status: 400 });
      if (!state) return NextResponse.json({ error: 'State parameter not provided' }, { status: 400 });

      const stateData = verifySSOState(state);
      const ssoResult = await handleAppleSSO(code, options);
      const response = NextResponse.redirect(stateData.redirect || '/dashboard');
      response.cookies.set('auth_token', ssoResult.token, { ...ssoResult.cookieOptions });
      return response;
    } catch (error) {
      const NextResponse = createNextResponse();
      const errorUrl = new URL('/auth/error', request.url);
      errorUrl.searchParams.set('message', error instanceof Error ? error.message : 'Authentication failed');
      return NextResponse.redirect(errorUrl);
    }
  },

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

  async callbackDiscord(request: NextRequest, options: SSOOptions = {}): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');

      if (!code) return NextResponse.json({ error: 'Authorization code not provided' }, { status: 400 });
      if (!state) return NextResponse.json({ error: 'State parameter not provided' }, { status: 400 });

      const stateData = verifySSOState(state);
      const ssoResult = await handleDiscordSSO(code, options);
      const response = NextResponse.redirect(stateData.redirect || '/dashboard');
      response.cookies.set('auth_token', ssoResult.token, { ...ssoResult.cookieOptions });
      return response;
    } catch (error) {
      const NextResponse = createNextResponse();
      const errorUrl = new URL('/auth/error', request.url);
      errorUrl.searchParams.set('message', error instanceof Error ? error.message : 'Authentication failed');
      return NextResponse.redirect(errorUrl);
    }
  },

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

  async callbackFacebook(request: NextRequest, options: SSOOptions = {}): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');

      if (!code) return NextResponse.json({ error: 'Authorization code not provided' }, { status: 400 });
      if (!state) return NextResponse.json({ error: 'State parameter not provided' }, { status: 400 });

      const stateData = verifySSOState(state);
      const ssoResult = await handleFacebookSSO(code, options);
      const response = NextResponse.redirect(stateData.redirect || '/dashboard');
      response.cookies.set('auth_token', ssoResult.token, { ...ssoResult.cookieOptions });
      return response;
    } catch (error) {
      const NextResponse = createNextResponse();
      const errorUrl = new URL('/auth/error', request.url);
      errorUrl.searchParams.set('message', error instanceof Error ? error.message : 'Authentication failed');
      return NextResponse.redirect(errorUrl);
    }
  },

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

  async callbackLinkedIn(request: NextRequest, options: SSOOptions = {}): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');

      if (!code) return NextResponse.json({ error: 'Authorization code not provided' }, { status: 400 });
      if (!state) return NextResponse.json({ error: 'State parameter not provided' }, { status: 400 });

      const stateData = verifySSOState(state);
      const ssoResult = await handleLinkedInSSO(code, options);
      const response = NextResponse.redirect(stateData.redirect || '/dashboard');
      response.cookies.set('auth_token', ssoResult.token, { ...ssoResult.cookieOptions });
      return response;
    } catch (error) {
      const NextResponse = createNextResponse();
      const errorUrl = new URL('/auth/error', request.url);
      errorUrl.searchParams.set('message', error instanceof Error ? error.message : 'Authentication failed');
      return NextResponse.redirect(errorUrl);
    }
  },

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

  async callbackX(request: NextRequest, options: SSOOptions = {}): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const url = new URL(request.url);
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');

      if (!code) return NextResponse.json({ error: 'Authorization code not provided' }, { status: 400 });
      if (!state) return NextResponse.json({ error: 'State parameter not provided' }, { status: 400 });

      const stateData = verifySSOState(state);
      const ssoResult = await handleXSSO(code, state, options);
      const response = NextResponse.redirect(stateData.redirect || '/dashboard');
      response.cookies.set('auth_token', ssoResult.token, { ...ssoResult.cookieOptions });
      return response;
    } catch (error) {
      const NextResponse = createNextResponse();
      const errorUrl = new URL('/auth/error', request.url);
      errorUrl.searchParams.set('message', error instanceof Error ? error.message : 'Authentication failed');
      return NextResponse.redirect(errorUrl);
    }
  }
};

// Next.js App Router forgot password handlers
export const nextForgotPassword = {
  async initiate(request: NextRequest, options: ForgotPasswordOptions = {}): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const body = await request.json();
      const { email } = body;

      if (!email) return NextResponse.json({ error: 'Email is required' }, { status: 400 });

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

  async reset(request: NextRequest, options: ResetPasswordOptions = {}): Promise<NextResponse> {
    try {
      const NextResponse = createNextResponse();
      const body = await request.json();
      const { email, code, newPassword } = body;

      if (!email || !code || !newPassword) {
        return NextResponse.json({ error: 'Email, code, and new password are required' }, { status: 400 });
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

// Express.js SSO handlers
export const expressSSO = {
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

  async callbackGoogle(req: Request, res: Response, options: SSOOptions = {}): Promise<void> {
    try {
      const { code, state } = req.query;
      if (!code) return void res.status(400).json({ error: 'Authorization code not provided' });
      if (!state) return void res.status(400).json({ error: 'State parameter not provided' });

      const stateData = verifySSOState(state as string);
      const ssoResult = await handleGoogleSSO(code as string, options);
      res.cookie('auth_token', ssoResult.token, { ...ssoResult.cookieOptions });
      res.redirect(stateData.redirect || '/dashboard');
    } catch (error) {
      res.redirect(`/auth/error?message=${encodeURIComponent(error instanceof Error ? error.message : 'Authentication failed')}`);
    }
  },

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

  async callbackGitHub(req: Request, res: Response, options: SSOOptions = {}): Promise<void> {
    try {
      const { code, state } = req.query;
      if (!code) return void res.status(400).json({ error: 'Authorization code not provided' });
      if (!state) return void res.status(400).json({ error: 'State parameter not provided' });

      const stateData = verifySSOState(state as string);
      const ssoResult = await handleGitHubSSO(code as string, options);
      res.cookie('auth_token', ssoResult.token, { ...ssoResult.cookieOptions });
      res.redirect(stateData.redirect || '/dashboard');
    } catch (error) {
      res.redirect(`/auth/error?message=${encodeURIComponent(error instanceof Error ? error.message : 'Authentication failed')}`);
    }
  },

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

  async callbackApple(req: Request, res: Response, options: SSOOptions = {}): Promise<void> {
    try {
      const { code, state } = req.body || req.query;
      if (!code) return void res.status(400).json({ error: 'Authorization code not provided' });
      if (!state) return void res.status(400).json({ error: 'State parameter not provided' });

      const stateData = verifySSOState(state as string);
      const ssoResult = await handleAppleSSO(code as string, options);
      res.cookie('auth_token', ssoResult.token, { ...ssoResult.cookieOptions });
      res.redirect(stateData.redirect || '/dashboard');
    } catch (error) {
      res.redirect(`/auth/error?message=${encodeURIComponent(error instanceof Error ? error.message : 'Authentication failed')}`);
    }
  },

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

  async callbackDiscord(req: Request, res: Response, options: SSOOptions = {}): Promise<void> {
    try {
      const { code, state } = req.query;
      if (!code) return void res.status(400).json({ error: 'Authorization code not provided' });
      if (!state) return void res.status(400).json({ error: 'State parameter not provided' });

      const stateData = verifySSOState(state as string);
      const ssoResult = await handleDiscordSSO(code as string, options);
      res.cookie('auth_token', ssoResult.token, { ...ssoResult.cookieOptions });
      res.redirect(stateData.redirect || '/dashboard');
    } catch (error) {
      res.redirect(`/auth/error?message=${encodeURIComponent(error instanceof Error ? error.message : 'Authentication failed')}`);
    }
  },

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

  async callbackFacebook(req: Request, res: Response, options: SSOOptions = {}): Promise<void> {
    try {
      const { code, state } = req.query;
      if (!code) return void res.status(400).json({ error: 'Authorization code not provided' });
      if (!state) return void res.status(400).json({ error: 'State parameter not provided' });

      const stateData = verifySSOState(state as string);
      const ssoResult = await handleFacebookSSO(code as string, options);
      res.cookie('auth_token', ssoResult.token, { ...ssoResult.cookieOptions });
      res.redirect(stateData.redirect || '/dashboard');
    } catch (error) {
      res.redirect(`/auth/error?message=${encodeURIComponent(error instanceof Error ? error.message : 'Authentication failed')}`);
    }
  },

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

  async callbackLinkedIn(req: Request, res: Response, options: SSOOptions = {}): Promise<void> {
    try {
      const { code, state } = req.query;
      if (!code) return void res.status(400).json({ error: 'Authorization code not provided' });
      if (!state) return void res.status(400).json({ error: 'State parameter not provided' });

      const stateData = verifySSOState(state as string);
      const ssoResult = await handleLinkedInSSO(code as string, options);
      res.cookie('auth_token', ssoResult.token, { ...ssoResult.cookieOptions });
      res.redirect(stateData.redirect || '/dashboard');
    } catch (error) {
      res.redirect(`/auth/error?message=${encodeURIComponent(error instanceof Error ? error.message : 'Authentication failed')}`);
    }
  },

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

  async callbackX(req: Request, res: Response, options: SSOOptions = {}): Promise<void> {
    try {
      const { code, state } = req.query;
      if (!code) return void res.status(400).json({ error: 'Authorization code not provided' });
      if (!state) return void res.status(400).json({ error: 'State parameter not provided' });

      const stateData = verifySSOState(state as string);
      const ssoResult = await handleXSSO(code as string, state as string, options);
      res.cookie('auth_token', ssoResult.token, { ...ssoResult.cookieOptions });
      res.redirect(stateData.redirect || '/dashboard');
    } catch (error) {
      res.redirect(`/auth/error?message=${encodeURIComponent(error instanceof Error ? error.message : 'Authentication failed')}`);
    }
  }
};

// Express.js forgot password handlers
export const expressForgotPassword = {
  async initiate(req: Request, res: Response, options: ForgotPasswordOptions = {}): Promise<void> {
    try {
      const { email } = req.body;
      if (!email) return void res.status(400).json({ error: 'Email is required' });

      const result = await initiateForgotPassword(email, options);
      res.json(result);
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Failed to initiate password reset'
      });
    }
  },

  async reset(req: Request, res: Response, options: ResetPasswordOptions = {}): Promise<void> {
    try {
      const { email, code, newPassword } = req.body;
      if (!email || !code || !newPassword) {
        return void res.status(400).json({ error: 'Email, code, and new password are required' });
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

// Universal SSO helpers
export const universalSSO = {
  getGoogleAuthUrl(redirectUrl: string = '/dashboard'): string {
    const state = generateSSOState({ redirect: redirectUrl });
    return getGoogleOAuthURL({ state });
  },

  getGitHubAuthUrl(redirectUrl: string = '/dashboard'): string {
    const state = generateSSOState({ redirect: redirectUrl });
    return getGitHubOAuthURL({ state });
  },

  getAppleAuthUrl(redirectUrl: string = '/dashboard'): string {
    const state = generateSSOState({ redirect: redirectUrl });
    return getAppleOAuthURL({ state });
  },

  getDiscordAuthUrl(redirectUrl: string = '/dashboard'): string {
    const state = generateSSOState({ redirect: redirectUrl });
    return getDiscordOAuthURL({ state });
  },

  getFacebookAuthUrl(redirectUrl: string = '/dashboard'): string {
    const state = generateSSOState({ redirect: redirectUrl });
    return getFacebookOAuthURL({ state });
  },

  getLinkedInAuthUrl(redirectUrl: string = '/dashboard'): string {
    const state = generateSSOState({ redirect: redirectUrl });
    return getLinkedInOAuthURL({ state });
  },

  async getXAuthUrl(redirectUrl: string = '/dashboard'): Promise<string> {
    const state = generateSSOState({ redirect: redirectUrl });
    const authResult = await getXOAuthURL({ state });
    return authResult.url;
  },

  async handleCallback(
    provider: 'google' | 'github' | 'apple' | 'discord' | 'facebook' | 'linkedin' | 'x',
    code: string,
    state: string,
    options: any = {}
  ): Promise<UniversalCallbackResult> {
    const stateData = verifySSOState(state);

    let result: GenericOAuthUser;
    switch (provider) {
      case 'google': {
        const { handleGoogleCallback } = await import('../providers/google');
        result = await handleGoogleCallback(code, { includeTokens: true, ...options });
        break;
      }
      case 'github': {
        const { handleGitHubCallback } = await import('../providers/github');
        result = await handleGitHubCallback(code, { includeToken: true, ...options });
        break;
      }
      case 'apple': {
        const { handleAppleCallback } = await import('../providers/apple');
        result = await handleAppleCallback(code, { state, ...options });
        break;
      }
      case 'discord': {
        const { handleDiscordCallback } = await import('../providers/discord');
        result = await handleDiscordCallback(code, { state, includeTokens: true, ...options });
        break;
      }
      case 'facebook': {
        const { handleFacebookCallback } = await import('../providers/facebook');
        result = await handleFacebookCallback(code, { state, includeTokens: true, ...options });
        break;
      }
      case 'linkedin': {
        const { handleLinkedInCallback } = await import('../providers/linkedin');
        result = await handleLinkedInCallback(code, { state, includeTokens: true, ...options });
        break;
      }
      case 'x': {
        const { handleXCallback } = await import('../providers/x');
        result = await handleXCallback(code, state, { includeToken: true, ...options });
        break;
      }
      default:
        throw new Error(`Unsupported provider: ${provider}`);
    }

    return {
      user: result,
      tokens: result.tokens || null,
      redirectUrl: stateData.redirect || '/dashboard'
    };
  },

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

  getSupportedProviders(): string[] {
    return ['google', 'github', 'apple', 'discord', 'facebook', 'linkedin', 'x'];
  }
};

// Universal forgot password helpers
export const universalForgotPassword = {
  async initiate(email: string, options: ForgotPasswordOptions = {}) {
    return await initiateForgotPassword(email, options);
  },
  async reset(email: string, code: string, newPassword: string, options: ResetPasswordOptions = {}) {
    return await resetPasswordWithCode(email, code, newPassword, options);
  }
};