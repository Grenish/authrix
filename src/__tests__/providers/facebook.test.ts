import { getFacebookOAuthURL, handleFacebookCallback, resetFacebookOAuthConfig } from '../../providers/facebook';

const mockFetch = jest.fn();
// @ts-ignore
(global as any).fetch = mockFetch;

const originalEnv = process.env as NodeJS.ProcessEnv;

(global as any).atob = (str: string) => Buffer.from(str, 'base64').toString('binary');
(global as any).btoa = (str: string) => Buffer.from(str, 'binary').toString('base64');

function jsonResponse(data: any) {
  return { ok: true, json: () => Promise.resolve(data) } as any;
}

describe('Facebook OAuth Provider', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    resetFacebookOAuthConfig();
    process.env = {
      ...originalEnv,
      FACEBOOK_APP_ID: 'fb-app-id',
      FACEBOOK_APP_SECRET: 'fb-secret',
      FACEBOOK_REDIRECT_URI: 'http://localhost:3000/auth/callback/facebook'
    } as any;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('getFacebookOAuthURL', () => {
    it('should generate correct OAuth URL', () => {
      const state = 'state-fb';
      const url = getFacebookOAuthURL({ state });
      expect(url).toContain('https://www.facebook.com');
      expect(url).toContain('client_id=fb-app-id');
      expect(url).toContain('redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fcallback%2Ffacebook');
      expect(url).toContain('response_type=code');
      expect(url).toContain('scope=email%2Cpublic_profile');
      expect(url).toContain('state=state-fb');
    });
  });

  describe('handleFacebookCallback', () => {
    it('should handle successful callback', async () => {
      const tokenRes = jsonResponse({ access_token: 'acc', token_type: 'Bearer', expires_in: 3600 });
      const meRes = jsonResponse({ id: 'fb1', email: 'fb@example.com', name: 'FB User', verified: true, picture: { data: { url: 'https://pic' } } });

      mockFetch
        .mockResolvedValueOnce(tokenRes)
        .mockResolvedValueOnce(meRes);

      const result = await handleFacebookCallback('code');
      expect(result).toEqual(expect.objectContaining({ id: 'fb1', email: 'fb@example.com', provider: 'facebook' }));
    });

    it('should handle token failure', async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 400, text: () => Promise.resolve('Bad Request') } as any);
      await expect(handleFacebookCallback('bad')).rejects.toThrow(/(Facebook authentication failed|Token exchange failed)/);
    });
  });
});
