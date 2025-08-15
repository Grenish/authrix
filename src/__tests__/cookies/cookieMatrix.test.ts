import { internalCookies } from '../../internal/cookies';
import { authConfig, initAuth } from '../../config';

// Basic mock adapter
const mockAdapter: any = { findUserById: async () => null };

describe('Cookie normalization matrix', () => {
  beforeAll(() => {
    initAuth({ db: mockAdapter, cookieName: 'auth_test_token' } as any);
  });

  test('header framework converts ms to s', () => {
    const opts = internalCookies.normalizeCookieOptions({ framework: 'header', maxAge: 7 * 24 * 60 * 60 * 1000 });
    expect(opts.maxAge).toBe(604800);
  });

  test('express framework preserves ms', () => {
    const opts = internalCookies.normalizeCookieOptions({ framework: 'express', maxAge: 3000 });
    expect(opts.maxAge).toBe(3000);
  });

  test('central cookie name retrieval consistent', () => {
    expect(internalCookies.getAuthCookieName()).toBe(authConfig.cookieName);
  });

  test('auth cookie string uses seconds', () => {
    const cookie = internalCookies.createAuthCookieString('token', { maxAge: 7 * 24 * 60 * 60 * 1000 });
    expect(cookie).toMatch(/Max-Age=604800/);
  });
});
