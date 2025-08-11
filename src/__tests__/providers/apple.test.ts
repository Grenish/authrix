import { getAppleOAuthURL, handleAppleCallback, resetAppleOAuthConfig } from '../../providers/apple';

const mockFetch = jest.fn();
// @ts-ignore
(global as any).fetch = mockFetch;

const originalEnv = process.env as NodeJS.ProcessEnv;

(global as any).atob = (str: string) => Buffer.from(str, 'base64').toString('binary');
(global as any).btoa = (str: string) => Buffer.from(str, 'binary').toString('base64');

function makeIdToken(payload: Record<string, any>) {
  const header = { alg: 'ES256', typ: 'JWT' };
  const base64url = (obj: any) => Buffer.from(JSON.stringify(obj)).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${base64url(header)}.${base64url(payload)}.signature`;
}

describe('Apple OAuth Provider', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    resetAppleOAuthConfig();
    process.env = {
      ...originalEnv,
      APPLE_CLIENT_ID: 'apple-client-id',
      APPLE_TEAM_ID: 'team-id',
      APPLE_KEY_ID: 'key-id',
      APPLE_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----',
      APPLE_REDIRECT_URI: 'http://localhost:3000/auth/callback/apple'
    } as any;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('getAppleOAuthURL', () => {
    it('should generate correct OAuth URL', () => {
      const state = 'state-abc';
      const url = getAppleOAuthURL({ state });
      expect(url).toContain('https://appleid.apple.com/auth/authorize');
      expect(url).toContain('client_id=apple-client-id');
      expect(url).toContain('redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fcallback%2Fapple');
      expect(url).toContain('response_type=code+id_token');
      expect(url).toContain('scope=name+email');
      expect(url).toContain('state=state-abc');
    });
  });

  describe('handleAppleCallback', () => {
    it('should handle successful callback', async () => {
      const now = Math.floor(Date.now() / 1000);
      const idToken = makeIdToken({
        aud: 'apple-client-id',
        iss: 'https://appleid.apple.com',
        exp: now + 3600,
        sub: 'apple-123',
        email: 'apple@example.com',
        email_verified: 'true',
        real_user_status: 2
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

      mockFetch.mockResolvedValueOnce(mockTokenResponse);

      const result = await handleAppleCallback('auth-code');

      expect(result).toEqual(expect.objectContaining({
        id: 'apple-123',
        email: 'apple@example.com',
        provider: 'apple',
        emailVerified: true
      }));
    });

    it('should error on token failure', async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 400, text: () => Promise.resolve('Bad Request') } as any);
      await expect(handleAppleCallback('bad')).rejects.toThrow(/(Apple authentication failed|Token exchange failed)/);
    });
  });
});
