import { getGoogleOAuthURL, handleGoogleCallback, resetGoogleOAuthConfig } from '../../providers/google';

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch;

// Mock environment variables
const originalEnv = process.env;

// Polyfill atob/btoa for Node test environment
(global as any).atob = (str: string) => Buffer.from(str, 'base64').toString('binary');
(global as any).btoa = (str: string) => Buffer.from(str, 'binary').toString('base64');

function makeIdToken(payload: Record<string, any>) {
  const header = { alg: 'RS256', typ: 'JWT' };
  const base64url = (obj: any) => Buffer.from(JSON.stringify(obj)).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${base64url(header)}.${base64url(payload)}.signature`;
}

describe('Google OAuth Provider', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  resetGoogleOAuthConfig();
    process.env = {
      ...originalEnv,
      GOOGLE_CLIENT_ID: 'test-client-id.googleusercontent.com',
      GOOGLE_CLIENT_SECRET: 'test-client-secret',
      GOOGLE_REDIRECT_URI: 'http://localhost:3000/auth/callback/google'
    };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('getGoogleOAuthURL', () => {
    it('should generate correct OAuth URL', () => {
      const state = 'random-state-string';
      const url = getGoogleOAuthURL({
        state,
        accessType: 'offline',
        prompt: 'consent',
        includeGrantedScopes: true
      });

      expect(url).toContain('https://accounts.google.com/o/oauth2/v2/auth');
      expect(url).toContain('client_id=test-client-id.googleusercontent.com');
      expect(url).toContain('redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fcallback%2Fgoogle');
      expect(url).toContain('response_type=code');
      expect(url).toContain('scope=openid+profile+email');
      expect(url).toContain('access_type=offline');
      expect(url).toContain('prompt=consent');
      expect(url).toContain('state=random-state-string');
    });

    it('should throw error if environment variables are missing', () => {
      process.env = {};

      expect(() => getGoogleOAuthURL({ state: 'state' })).toThrow(
        /Missing Google OAuth environment variables/
      );
    });
  });

  describe('handleGoogleCallback', () => {
    it('should handle successful callback', async () => {
      const now = Math.floor(Date.now() / 1000);
      const idToken = makeIdToken({
        aud: 'test-client-id.googleusercontent.com',
        iss: 'accounts.google.com',
        exp: now + 3600
      });

      const mockTokenResponse = {
        ok: true,
        json: () => Promise.resolve({
          id_token: idToken,
          access_token: 'access-token-123',
          scope: 'openid profile email',
          token_type: 'Bearer',
          expires_in: 3600
        })
      };

      const mockUserResponse = {
        ok: true,
        json: () => Promise.resolve({
          aud: 'test-client-id.googleusercontent.com',
          sub: '12345',
          email: 'test@example.com',
          name: 'Test User',
          picture: 'https://lh3.googleusercontent.com/a/avatar',
          email_verified: true
        })
      };

      mockFetch
        .mockResolvedValueOnce(mockTokenResponse)
        .mockResolvedValueOnce(mockUserResponse);

      const result = await handleGoogleCallback('auth-code');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://oauth2.googleapis.com/token',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/x-www-form-urlencoded'
          })
        })
      );

      expect(mockFetch).toHaveBeenCalledWith(
        'https://www.googleapis.com/oauth2/v3/userinfo',
        expect.objectContaining({
          headers: expect.objectContaining({ Authorization: expect.stringContaining('Bearer') })
        })
      );

      expect(result).toEqual({
        id: '12345',
        email: 'test@example.com',
        name: 'Test User',
        avatar: 'https://lh3.googleusercontent.com/a/avatar',
        provider: 'google',
        emailVerified: true,
        metadata: expect.any(Object)
      });
    });

    it('should handle token request failure', async () => {
      const mockTokenResponse = {
        ok: false,
        status: 400,
        text: () => Promise.resolve('Bad Request')
      };

      mockFetch.mockResolvedValueOnce(mockTokenResponse);

      await expect(handleGoogleCallback('invalid-code')).rejects.toThrow(
        /(Google authentication failed|Token exchange failed)/
      );
    });

    it('should handle missing id_token', async () => {
      const mockTokenResponse = {
        ok: true,
        json: () => Promise.resolve({ error: 'invalid_grant' })
      };

      mockFetch.mockResolvedValueOnce(mockTokenResponse);

      await expect(handleGoogleCallback('invalid-code')).rejects.toThrow(
        /(Google authentication failed|No ID token received)/
      );
    });

    it('should handle token info request failure', async () => {
      const now = Math.floor(Date.now() / 1000);
      const idToken = makeIdToken({ aud: 'wrong-client', iss: 'accounts.google.com', exp: now + 3600 });
      const mockTokenResponse = {
        ok: true,
        json: () => Promise.resolve({ id_token: idToken })
      };
      mockFetch.mockResolvedValueOnce(mockTokenResponse);

      await expect(handleGoogleCallback('auth-code')).rejects.toThrow(
        /(Google authentication failed|Security validation failed|Token audience mismatch)/
      );
    });

    it('should handle audience mismatch', async () => {
      const now = Math.floor(Date.now() / 1000);
      const idToken = makeIdToken({ aud: 'wrong-client-id.googleusercontent.com', iss: 'accounts.google.com', exp: now + 3600 });
      const mockTokenResponse = {
        ok: true,
        json: () => Promise.resolve({ id_token: idToken })
      };
      mockFetch.mockResolvedValueOnce(mockTokenResponse);
  await expect(handleGoogleCallback('auth-code')).rejects.toThrow(/(Google authentication failed|Security validation failed)/);
    });

    it('should handle unverified email', async () => {
      const now = Math.floor(Date.now() / 1000);
      const idToken = makeIdToken({ aud: 'test-client-id.googleusercontent.com', iss: 'accounts.google.com', exp: now + 3600 });
      const mockTokenResponse = {
        ok: true,
        json: () => Promise.resolve({ id_token: idToken, access_token: 'access' })
      };

      const mockUserResponse = {
        ok: true,
        json: () => Promise.resolve({
          aud: 'test-client-id.googleusercontent.com',
          sub: '12345',
          email: 'test@example.com',
          name: 'Test User',
          picture: 'https://lh3.googleusercontent.com/a/avatar',
          email_verified: false
        })
      };

      mockFetch
        .mockResolvedValueOnce(mockTokenResponse)
        .mockResolvedValueOnce(mockUserResponse);

      await expect(handleGoogleCallback('auth-code')).rejects.toThrow(
        /(Google authentication failed|Email address is not verified)/
      );
    });

    it('should throw error if environment variables are missing', async () => {
      process.env = {};

      await expect(handleGoogleCallback('auth-code')).rejects.toThrow(
        /Missing Google OAuth environment variables/
      );
    });
  });
});
