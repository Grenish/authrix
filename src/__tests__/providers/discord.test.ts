import { getDiscordOAuthURL, handleDiscordCallback, resetDiscordOAuthConfig } from '../../providers/discord';

const mockFetch = jest.fn();
// @ts-ignore
(global as any).fetch = mockFetch;

const originalEnv = process.env as NodeJS.ProcessEnv;

(global as any).atob = (str: string) => Buffer.from(str, 'base64').toString('binary');
(global as any).btoa = (str: string) => Buffer.from(str, 'binary').toString('base64');

function jsonResponse(data: any) {
  return { ok: true, json: () => Promise.resolve(data) } as any;
}

describe('Discord OAuth Provider', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    resetDiscordOAuthConfig();
    process.env = {
      ...originalEnv,
      DISCORD_CLIENT_ID: 'discord-client',
      DISCORD_CLIENT_SECRET: 'discord-secret',
      DISCORD_REDIRECT_URI: 'http://localhost:3000/auth/callback/discord'
    } as any;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('getDiscordOAuthURL', () => {
    it('should generate correct OAuth URL', () => {
      const state = 'state-1';
      const url = getDiscordOAuthURL({ state });
      expect(url).toContain('https://discord.com/oauth2/authorize');
      expect(url).toContain('client_id=discord-client');
      expect(url).toContain('redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fcallback%2Fdiscord');
      expect(url).toContain('response_type=code');
      expect(url).toContain('scope=identify+email');
      expect(url).toContain('state=state-1');
    });
  });

  describe('handleDiscordCallback', () => {
    it('should handle successful callback', async () => {
      const tokenRes = jsonResponse({ access_token: 'acc', token_type: 'Bearer', expires_in: 3600, refresh_token: 'ref', scope: 'identify email' });
      const userRes = jsonResponse({ id: 'd1', username: 'name', global_name: 'Display', email: 'd@example.com', verified: true, avatar: 'abc' });

      mockFetch
        .mockResolvedValueOnce(tokenRes)
        .mockResolvedValueOnce(userRes);

      const result = await handleDiscordCallback('code');
      expect(result).toEqual(expect.objectContaining({ id: 'd1', email: 'd@example.com', provider: 'discord' }));
    });

    it('should handle token failure', async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 400, text: () => Promise.resolve('Bad Request') } as any);
      await expect(handleDiscordCallback('bad')).rejects.toThrow(/(Discord authentication failed|Token exchange failed)/);
    });
  });
});
