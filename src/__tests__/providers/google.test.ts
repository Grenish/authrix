import { getGoogleOAuthURL, handleGoogleCallback } from '../../providers/google';

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch;

// Mock environment variables
const originalEnv = process.env;

describe('Google OAuth Provider', () => {
  beforeEach(() => {
    jest.clearAllMocks();
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
      const url = getGoogleOAuthURL(state);

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

      expect(() => getGoogleOAuthURL('state')).toThrow(
        'Missing Google OAuth environment variables'
      );
    });
  });

  describe('handleGoogleCallback', () => {
    it('should handle successful callback', async () => {
      const mockTokenResponse = {
        ok: true,
        json: () => Promise.resolve({ 
          id_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token'
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
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        })
      );

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('https://oauth2.googleapis.com/tokeninfo?id_token=')
      );

      expect(result).toEqual({
        id: '12345',
        email: 'test@example.com',
        name: 'Test User',
        avatar: 'https://lh3.googleusercontent.com/a/avatar',
        provider: 'google'
      });
    });

    it('should handle token request failure', async () => {
      const mockTokenResponse = {
        ok: false,
        statusText: 'Bad Request'
      };

      mockFetch.mockResolvedValueOnce(mockTokenResponse);

      await expect(handleGoogleCallback('invalid-code')).rejects.toThrow(
        'An error occurred during Google authentication'
      );
    });

    it('should handle missing id_token', async () => {
      const mockTokenResponse = {
        ok: true,
        json: () => Promise.resolve({ error: 'invalid_grant' })
      };

      mockFetch.mockResolvedValueOnce(mockTokenResponse);

      await expect(handleGoogleCallback('invalid-code')).rejects.toThrow(
        'An error occurred during Google authentication'
      );
    });

    it('should handle token info request failure', async () => {
      const mockTokenResponse = {
        ok: true,
        json: () => Promise.resolve({ 
          id_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token'
        })
      };

      const mockUserResponse = {
        ok: false,
        statusText: 'Unauthorized'
      };

      mockFetch
        .mockResolvedValueOnce(mockTokenResponse)
        .mockResolvedValueOnce(mockUserResponse);

      await expect(handleGoogleCallback('auth-code')).rejects.toThrow(
        'An error occurred during Google authentication'
      );
    });

    it('should handle audience mismatch', async () => {
      const mockTokenResponse = {
        ok: true,
        json: () => Promise.resolve({ 
          id_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token'
        })
      };

      const mockUserResponse = {
        ok: true,
        json: () => Promise.resolve({
          aud: 'wrong-client-id.googleusercontent.com',
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

      await expect(handleGoogleCallback('auth-code')).rejects.toThrow(
        'An error occurred during Google authentication'
      );
    });

    it('should handle unverified email', async () => {
      const mockTokenResponse = {
        ok: true,
        json: () => Promise.resolve({ 
          id_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token'
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
          email_verified: false
        })
      };

      mockFetch
        .mockResolvedValueOnce(mockTokenResponse)
        .mockResolvedValueOnce(mockUserResponse);

      await expect(handleGoogleCallback('auth-code')).rejects.toThrow(
        'An error occurred during Google authentication'
      );
    });

    it('should throw error if environment variables are missing', async () => {
      process.env = {};

      await expect(handleGoogleCallback('auth-code')).rejects.toThrow(
        'Missing Google OAuth environment variables'
      );
    });
  });
});
