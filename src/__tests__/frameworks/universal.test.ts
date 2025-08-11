import { 
  signupUniversal, 
  signinUniversal, 
  logoutUniversal, 
  validateAuth,
  getAuthTokenFromCookies,
  parseCookies,
  type UniversalLogoutResult
} from '../../frameworks/universal';

// Mock all dependencies
jest.mock('../../config', () => ({
  authConfig: {
    cookieName: 'auth-token',
    db: {
      findUserByEmail: jest.fn(),
      createUser: jest.fn(),
      findUserById: jest.fn()
    }
  }
}));

jest.mock('../../core/signup', () => ({
  signupCore: jest.fn()
}));

jest.mock('../../core/signin', () => ({
  signinCore: jest.fn()
}));

jest.mock('../../core/logout', () => ({
  logoutCore: jest.fn()
}));

jest.mock('../../core/session', () => ({
  getCurrentUserFromToken: jest.fn(),
  isTokenValid: jest.fn()
}));

import { signupCore } from '../../core/signup';
import { signinCore } from '../../core/signin';
import { logoutCore } from '../../core/logout';
import { getCurrentUserFromToken, isTokenValid } from '../../core/session';

const mockSignupCore = signupCore as jest.MockedFunction<typeof signupCore>;
const mockSigninCore = signinCore as jest.MockedFunction<typeof signinCore>;
const mockLogoutCore = logoutCore as jest.MockedFunction<typeof logoutCore>;
const mockGetCurrentUserFromToken = getCurrentUserFromToken as jest.MockedFunction<typeof getCurrentUserFromToken>;
const mockIsTokenValid = isTokenValid as jest.MockedFunction<typeof isTokenValid>;

describe('Universal Framework', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('signupUniversal', () => {
    it('should sign up a new user successfully', async () => {
      const mockResponse = {
        user: { id: '1', email: 'test@example.com' },
        token: 'token123',
        cookieOptions: {
          httpOnly: true,
          secure: false,
          maxAge: 1000 * 60 * 60 * 24 * 7,
          sameSite: 'lax' as const,
          path: '/'
        },
        isNewUser: true
      };
      
      mockSignupCore.mockResolvedValueOnce(mockResponse);

      const result = await signupUniversal('test@example.com', 'password');

  expect(mockSignupCore).toHaveBeenCalledWith('test@example.com', 'password');
  expect(result).toEqual(mockResponse);
    });

    it('should handle signup error', async () => {
      mockSignupCore.mockRejectedValueOnce(new Error('Email already registered'));

      const result = await signupUniversal('test@example.com', 'password');

      expect(result).toEqual({
        success: false,
        error: { message: 'Email already registered' }
      });
    });
  });

  describe('signinUniversal', () => {
    it('should sign in user successfully', async () => {
      const mockResponse = {
        user: { id: '1', email: 'test@example.com' },
        token: 'token123',
        cookieOptions: {
          httpOnly: true,
          secure: false,
          maxAge: 1000 * 60 * 60 * 24 * 7,
          sameSite: 'lax' as const,
          path: '/'
        }
      };
      
      mockSigninCore.mockResolvedValueOnce(mockResponse);

      const result = await signinUniversal('test@example.com', 'password');

  expect(mockSigninCore).toHaveBeenCalledWith('test@example.com', 'password');
  expect(result).toEqual(mockResponse);
    });

    it('should handle signin error', async () => {
      mockSigninCore.mockRejectedValueOnce(new Error('Invalid credentials'));

      const result = await signinUniversal('test@example.com', 'password');

      expect(result).toEqual({
        success: false,
        error: { message: 'Invalid credentials' }
      });
    });
  });

  describe('logoutUniversal', () => {
    it('should logout successfully', async () => {
      const mockResponse: UniversalLogoutResult = {
        success: true,
        message: 'Logged out successfully',
        cookiesToClear: [
          {
            name: 'auth-token',
            options: {
              httpOnly: true,
              secure: false,
              sameSite: 'lax',
              path: '/',
              expires: new Date(0)
            }
          }
        ]
      };
      
      mockLogoutCore.mockReturnValueOnce(mockResponse);

      const result = await logoutUniversal();

      expect(mockLogoutCore).toHaveBeenCalled();
      expect(result).toEqual(mockResponse);
    });
  });

  describe('validateAuth', () => {
    it('should validate token successfully', async () => {
      const mockUser = { id: '1', email: 'test@example.com', createdAt: new Date() };
      
      mockGetCurrentUserFromToken.mockResolvedValueOnce(mockUser);

      const result = await validateAuth('token123');

      expect(mockGetCurrentUserFromToken).toHaveBeenCalledWith('token123');
      expect(result).toEqual({
        isValid: true,
        user: mockUser,
        error: null
      });
    });

    it('should handle invalid token', async () => {
      const result = await validateAuth(null);

      expect(result).toEqual({
        isValid: false,
        user: null,
        error: 'No token provided'
      });
    });

    it('should handle token validation error', async () => {
      mockIsTokenValid.mockResolvedValueOnce(false);

      const result = await validateAuth('invalid-token');

      expect(result).toEqual({
        isValid: false,
        user: null,
        error: 'Invalid or expired token'
      });
    });
  });

  describe('parseCookies', () => {
    it('should parse cookie string correctly', () => {
      const cookieString = 'name1=value1; name2=value2; name3=value3';
      
      const result = parseCookies(cookieString);

      expect(result).toEqual({
        name1: 'value1',
        name2: 'value2',
        name3: 'value3'
      });
    });

    it('should handle empty cookie string', () => {
      const result = parseCookies('');

      expect(result).toEqual({});
    });

    it('should handle malformed cookies', () => {
      const cookieString = 'name1=value1; malformed; name2=value2';
      
      const result = parseCookies(cookieString);

      expect(result).toEqual({
        name1: 'value1',
        name2: 'value2'
      });
    });
  });

  describe('getAuthTokenFromCookies', () => {
    it('should get auth token from cookies', () => {
      const cookies = { 'auth-token': 'token123', 'other': 'value' };
      
      const result = getAuthTokenFromCookies(cookies);

      expect(result).toBe('token123');
    });

    it('should return null if token not found', () => {
      const cookies = { 'other': 'value' };
      
      const result = getAuthTokenFromCookies(cookies);

      expect(result).toBeNull();
    });
  });
});
