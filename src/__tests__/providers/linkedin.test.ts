import { getLinkedInOAuthURL, handleLinkedInCallback, resetLinkedInOAuthConfig } from '../../providers/linkedin';

// Mock fetch globally
const mockFetch = jest.fn();
// @ts-ignore
(global as any).fetch = mockFetch;

// Mock environment variables
const originalEnv = process.env as NodeJS.ProcessEnv;

// Polyfill atob/btoa for Node test environment
(global as any).atob = (str: string) => Buffer.from(str, 'base64').toString('binary');
(global as any).btoa = (str: string) => Buffer.from(str, 'binary').toString('base64');

function makeIdToken(payload: Record<string, any>) {
  const header = { alg: 'RS256', typ: 'JWT' };
  const base64url = (obj: any) => Buffer.from(JSON.stringify(obj)).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${base64url(header)}.${base64url(payload)}.signature`;
}

describe('LinkedIn OAuth Provider', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    resetLinkedInOAuthConfig();
    process.env = {
      ...originalEnv,
      LINKEDIN_CLIENT_ID: 'linkedin-client-id',
      LINKEDIN_CLIENT_SECRET: 'linkedin-client-secret',
      LINKEDIN_REDIRECT_URI: 'http://localhost:3000/auth/callback/linkedin'
    } as any;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('getLinkedInOAuthURL', () => {
    it('should generate correct OAuth URL', () => {
      const state = 'state-xyz';
      const url = getLinkedInOAuthURL({ state });

      expect(url).toContain('https://www.linkedin.com/oauth/v2/authorization');
      expect(url).toContain('client_id=linkedin-client-id');
      expect(url).toContain('redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fcallback%2Flinkedin');
      expect(url).toContain('response_type=code');
      expect(url).toContain('scope=openid+profile+email');
      expect(url).toContain('state=state-xyz');
    });

    it('should throw error if environment variables are missing', () => {
      process.env = {} as any;

      expect(() => getLinkedInOAuthURL({ state: 'state' })).toThrow(/Missing LinkedIn OAuth environment variables/);
    });
  });

  describe('handleLinkedInCallback', () => {
    it('should handle successful callback using id_token and userinfo', async () => {
      const now = Math.floor(Date.now() / 1000);
      const idToken = makeIdToken({
        aud: 'linkedin-client-id',
        iss: 'https://www.linkedin.com',
        exp: now + 3600,
        sub: 'li-123',
        email: 'li@example.com',
        email_verified: true,
        name: 'LI User',
        picture: 'https://cdn.linkedin.com/pic.jpg'
      });

      const mockTokenResponse = {
        ok: true,
        json: () => Promise.resolve({
          id_token: idToken,
          access_token: 'access-token',
          token_type: 'Bearer',
          expires_in: 3600
        })
      } as any;

      const mockUserResponse = {
        ok: true,
        json: () => Promise.resolve({
          sub: 'li-123',
          email: 'li@example.com',
          email_verified: true,
          name: 'LI User',
          picture: 'https://cdn.linkedin.com/pic.jpg'
        })
      } as any;

      mockFetch
        .mockResolvedValueOnce(mockTokenResponse)
        .mockResolvedValueOnce(mockUserResponse);

      const result = await handleLinkedInCallback('auth-code');

      expect(result).toEqual(
        expect.objectContaining({
          id: 'li-123',
          email: 'li@example.com',
          name: 'LI User',
          provider: 'linkedin',
          emailVerified: true
        })
      );
    });

    it('should handle token request failure', async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 400, text: () => Promise.resolve('Bad Request') } as any);

      await expect(handleLinkedInCallback('bad-code')).rejects.toThrow(/(LinkedIn authentication failed|Token exchange failed)/);
    });

    it('should handle missing env', async () => {
      process.env = {} as any;
      await expect(handleLinkedInCallback('code')).rejects.toThrow(/Missing LinkedIn OAuth environment variables/);
    });
  });
});
