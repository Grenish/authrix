import { getGitHubOAuthURL, handleGitHubCallback, resetGitHubOAuthConfig } from '../../providers/github';

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch;

// Mock environment variables
const originalEnv = process.env;

describe('GitHub OAuth Provider', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  resetGitHubOAuthConfig();
    process.env = {
      ...originalEnv,
      GITHUB_CLIENT_ID: 'test-client-id',
      GITHUB_CLIENT_SECRET: 'test-client-secret',
      GITHUB_REDIRECT_URI: 'http://localhost:3000/auth/callback/github'
    };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('getGitHubOAuthURL', () => {
    it('should generate correct OAuth URL', () => {
      const state = 'random-state-string';
      const url = getGitHubOAuthURL({state});

      expect(url).toContain('https://github.com/login/oauth/authorize');
      expect(url).toContain('client_id=test-client-id');
      expect(url).toContain('redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fcallback%2Fgithub');
      expect(url).toContain('scope=read%3Auser+user%3Aemail');
      expect(url).toContain('state=random-state-string');
    });

    it('should throw error if environment variables are missing', () => {
      process.env = {};

      expect(() => getGitHubOAuthURL({ state: 'state' })).toThrow(
        /Missing GitHub OAuth environment variables/
      );
    });
  });

  describe('handleGitHubCallback', () => {
    it('should handle successful callback', async () => {
      const mockTokenResponse = {
        ok: true,
        json: () => Promise.resolve({ access_token: 'github-access-token' })
      };

      const mockUserResponse = {
        ok: true,
        json: () => Promise.resolve({
          id: 12345,
          name: 'Test User',
          avatar_url: 'https://avatars.githubusercontent.com/u/12345'
        })
      };

      const mockEmailResponse = {
        ok: true,
        json: () => Promise.resolve([
          { email: 'test@example.com', primary: true, verified: true },
          { email: 'other@example.com', primary: false, verified: true }
        ])
      };

      mockFetch
        .mockResolvedValueOnce(mockTokenResponse)
        .mockResolvedValueOnce(mockUserResponse)
        .mockResolvedValueOnce(mockEmailResponse);

      const result = await handleGitHubCallback('auth-code');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://github.com/login/oauth/access_token',
        expect.objectContaining({
          method: 'POST',
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            client_id: 'test-client-id',
            client_secret: 'test-client-secret',
            code: 'auth-code',
            redirect_uri: 'http://localhost:3000/auth/callback/github'
          })
        })
      );

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.github.com/user',
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer github-access-token'
          })
        })
      );

      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.github.com/user/emails',
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer github-access-token'
          })
        })
      );

      expect(result).toEqual(expect.objectContaining({
        id: '12345',
        email: 'test@example.com',
        name: 'Test User',
        avatar: 'https://avatars.githubusercontent.com/u/12345',
        provider: 'github'
      }));
    });

    it('should handle token request failure', async () => {
      const mockTokenResponse = {
        ok: false,
        statusText: 'Bad Request'
      };

      mockFetch.mockResolvedValueOnce(mockTokenResponse);

      await expect(handleGitHubCallback('invalid-code')).rejects.toThrow(
        /(An unexpected error occurred|GitHub authentication failed|An error occurred during GitHub authentication)/
      );
    });

    it('should handle missing access token', async () => {
      const mockTokenResponse = {
        ok: true,
        json: () => Promise.resolve({ error: 'invalid_grant' })
      };

      mockFetch.mockResolvedValueOnce(mockTokenResponse);

      await expect(handleGitHubCallback('invalid-code')).rejects.toThrow(
        /(GitHub OAuth error|GitHub authentication failed|An error occurred during GitHub authentication)/
      );
    });

    it('should handle user API failure', async () => {
      const mockTokenResponse = {
        ok: true,
        json: () => Promise.resolve({ access_token: 'github-access-token' })
      };

      const mockUserResponse = {
        ok: false,
        statusText: 'Unauthorized'
      };

      mockFetch
        .mockResolvedValueOnce(mockTokenResponse)
        .mockResolvedValueOnce(mockUserResponse);

      await expect(handleGitHubCallback('auth-code')).rejects.toThrow(
        /(GitHub authentication failed|An error occurred during GitHub authentication)/
      );
    });

    it('should handle email API failure', async () => {
      const mockTokenResponse = {
        ok: true,
        json: () => Promise.resolve({ access_token: 'github-access-token' })
      };

      const mockUserResponse = {
        ok: true,
        json: () => Promise.resolve({
          id: 12345,
          name: 'Test User',
          avatar_url: 'https://avatars.githubusercontent.com/u/12345'
        })
      };

      const mockEmailResponse = {
        ok: false,
        statusText: 'Forbidden'
      };

      mockFetch
        .mockResolvedValueOnce(mockTokenResponse)
        .mockResolvedValueOnce(mockUserResponse)
        .mockResolvedValueOnce(mockEmailResponse);

      await expect(handleGitHubCallback('auth-code')).rejects.toThrow(
        /(GitHub authentication failed|An error occurred during GitHub authentication)/
      );
    });

    it('should handle missing verified primary email', async () => {
      const mockTokenResponse = {
        ok: true,
        json: () => Promise.resolve({ access_token: 'github-access-token' })
      };

      const mockUserResponse = {
        ok: true,
        json: () => Promise.resolve({
          id: 12345,
          name: 'Test User',
          avatar_url: 'https://avatars.githubusercontent.com/u/12345'
        })
      };

      const mockEmailResponse = {
        ok: true,
        json: () => Promise.resolve([
          { email: 'test@example.com', primary: false, verified: true },
          { email: 'other@example.com', primary: true, verified: false }
        ])
      };

      mockFetch
        .mockResolvedValueOnce(mockTokenResponse)
        .mockResolvedValueOnce(mockUserResponse)
        .mockResolvedValueOnce(mockEmailResponse);

      await expect(handleGitHubCallback('auth-code')).rejects.toThrow(
        /(No verified primary email found|GitHub authentication failed|An error occurred during GitHub authentication)/
      );
    });

    it('should throw error if environment variables are missing', async () => {
      process.env = {};

      await expect(handleGitHubCallback('auth-code')).rejects.toThrow(
        /Missing GitHub OAuth environment variables/
      );
    });
  });
});
