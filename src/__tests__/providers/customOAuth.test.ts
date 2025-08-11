import { CustomOAuthProvider } from '../../providers/customOAuth';

const mockFetch = jest.fn();
// @ts-ignore
(global as any).fetch = mockFetch;

// Polyfills needed by provider
// @ts-ignore
(global as any).atob = (str: string) => Buffer.from(str, 'base64').toString('binary');
// @ts-ignore
(global as any).btoa = (str: string) => Buffer.from(str, 'binary').toString('base64');
// Minimal crypto.getRandomValues polyfill
// @ts-ignore
if (!(global as any).crypto) {
  // @ts-ignore
  (global as any).crypto = {};
}
// @ts-ignore
(global as any).crypto.getRandomValues = (arr: Uint8Array) => {
  const nodeCrypto = require('crypto');
  const buf: Buffer = nodeCrypto.randomBytes(arr.length);
  arr.set(buf);
  return arr;
};

function jsonResponse(data: any) {
  return { ok: true, json: () => Promise.resolve(data), headers: { get: () => 'application/json' } } as any;
}

describe('CustomOAuthProvider', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('generates authorization URL with provided params', async () => {
    const provider = new CustomOAuthProvider({
      name: 'custom-oauth',
      clientId: 'cid',
      clientSecret: 'sec',
      redirectUri: 'http://localhost/callback/custom',
      endpoints: {
        authorization: 'https://auth.example.com/authorize',
        token: 'https://auth.example.com/token',
        userInfo: 'https://auth.example.com/user'
      },
      scopes: ['openid', 'profile', 'email']
    });

    const url = await provider.getAuthorizationURL({ state: 'abc123', additionalParams: { prompt: 'consent' } });
    expect(url).toContain('https://auth.example.com/authorize');
    expect(url).toContain('client_id=cid');
    expect(url).toContain('redirect_uri=http%3A%2F%2Flocalhost%2Fcallback%2Fcustom');
    expect(url).toContain('response_type=code');
  expect(url).toContain('scope=openid+profile+email');
    expect(url).toContain('state=abc123');
    expect(url).toContain('prompt=consent');
  });

  it('handles callback success', async () => {
    const provider = new CustomOAuthProvider({
      name: 'custom-oauth',
      clientId: 'cid',
      clientSecret: 'sec',
      redirectUri: 'http://localhost/callback/custom',
      endpoints: {
        authorization: 'https://auth.example.com/authorize',
        token: 'https://auth.example.com/token',
        userInfo: 'https://auth.example.com/user'
      },
      scopes: ['openid', 'profile', 'email']
    });

    mockFetch
      .mockResolvedValueOnce(jsonResponse({ access_token: 'acc', token_type: 'Bearer' }))
      .mockResolvedValueOnce(jsonResponse({ sub: 'u1', email: 'u@example.com', name: 'User', picture: 'https://img', email_verified: true }));

    const result = await provider.handleCallback('code', { state: 'abc', includeTokens: true });
    expect(result.user).toEqual(expect.objectContaining({ id: 'u1', email: 'u@example.com', provider: 'custom-oauth' }));
    expect(result.tokens).toBeDefined();
    expect(result.tokens?.access).toBe('acc');
  });

  it('handles token exchange failure', async () => {
    const provider = new CustomOAuthProvider({
      name: 'custom-oauth',
      clientId: 'cid',
      clientSecret: 'sec',
      redirectUri: 'http://localhost/callback/custom',
      endpoints: {
        authorization: 'https://auth.example.com/authorize',
        token: 'https://auth.example.com/token',
        userInfo: 'https://auth.example.com/user'
      }
    });

    mockFetch.mockResolvedValueOnce({ ok: false, status: 400, text: () => Promise.resolve('Bad Request'), headers: { get: () => 'application/json' } } as any);
    await expect(provider.handleCallback('bad', { state: 'abc' })).rejects.toThrow(/authentication failed/i);
  });

  it('handles userinfo failure when no id_token present', async () => {
    const provider = new CustomOAuthProvider({
      name: 'custom-oauth',
      clientId: 'cid',
      clientSecret: 'sec',
      redirectUri: 'http://localhost/callback/custom',
      endpoints: {
        authorization: 'https://auth.example.com/authorize',
        token: 'https://auth.example.com/token',
        userInfo: 'https://auth.example.com/user'
      }
    });

    mockFetch
      .mockResolvedValueOnce(jsonResponse({ access_token: 'acc', token_type: 'Bearer' }))
      .mockResolvedValueOnce({ ok: false, status: 500, text: () => Promise.resolve('Oops') } as any);

    await expect(provider.handleCallback('code', { state: 'abc' })).rejects.toThrow(/authentication failed|Failed to fetch user info/i);
  });
});
