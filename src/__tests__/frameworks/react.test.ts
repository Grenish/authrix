/**
 * @jest-environment jsdom
 */

import { 
  signupReact, 
  signinReact, 
  logoutReact, 
  getCurrentUserReact,
  isAuthenticatedReact,
  getAuthToken,
  hasAuthToken,
  createUseAuthToken,
  withAuthReact
} from '../../frameworks/react';

// Mock authConfig
jest.mock('../../config', () => ({
  authConfig: {
    cookieName: 'auth-token'
  }
}));

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch;

// Mock document.cookie
Object.defineProperty(document, 'cookie', {
  writable: true,
  value: ''
});

describe('React Framework', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    document.cookie = '';
  });

  describe('signupReact', () => {
    it('should sign up a user successfully', async () => {
      const mockResponse = {
        ok: true,
        json: () => Promise.resolve({ user: { id: '1', email: 'test@example.com' } })
      };
      mockFetch.mockResolvedValueOnce(mockResponse);

      const result = await signupReact('test@example.com', 'password');

      expect(mockFetch).toHaveBeenCalledWith('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com', password: 'password' }),
        credentials: 'include'
      });
      expect(result).toEqual({ user: { id: '1', email: 'test@example.com' } });
    });

    it('should handle signup failure', async () => {
      const mockResponse = {
        ok: false,
        json: () => Promise.resolve({ error: { message: 'Email already exists' } })
      };
      mockFetch.mockResolvedValueOnce(mockResponse);

      await expect(signupReact('test@example.com', 'password')).rejects.toThrow('Email already exists');
    });

    it('should use custom API endpoint', async () => {
      const mockResponse = {
        ok: true,
        json: () => Promise.resolve({ user: { id: '1', email: 'test@example.com' } })
      };
      mockFetch.mockResolvedValueOnce(mockResponse);

      await signupReact('test@example.com', 'password', '/custom/signup');

      expect(mockFetch).toHaveBeenCalledWith('/custom/signup', expect.any(Object));
    });
  });

  describe('signinReact', () => {
    it('should sign in a user successfully', async () => {
      const mockResponse = {
        ok: true,
        json: () => Promise.resolve({ user: { id: '1', email: 'test@example.com' } })
      };
      mockFetch.mockResolvedValueOnce(mockResponse);

      const result = await signinReact('test@example.com', 'password');

      expect(mockFetch).toHaveBeenCalledWith('/api/auth/signin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com', password: 'password' }),
        credentials: 'include'
      });
      expect(result).toEqual({ user: { id: '1', email: 'test@example.com' } });
    });

    it('should handle signin failure', async () => {
      const mockResponse = {
        ok: false,
        json: () => Promise.resolve({ error: { message: 'Invalid credentials' } })
      };
      mockFetch.mockResolvedValueOnce(mockResponse);

      await expect(signinReact('test@example.com', 'password')).rejects.toThrow('Invalid credentials');
    });
  });

  describe('logoutReact', () => {
    it('should logout successfully', async () => {
      const mockResponse = {
        ok: true,
        json: () => Promise.resolve({ message: 'Logged out successfully' })
      };
      mockFetch.mockResolvedValueOnce(mockResponse);

      const result = await logoutReact();

      expect(mockFetch).toHaveBeenCalledWith('/api/auth/logout', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' }
      });
      expect(result).toEqual({ message: 'Logged out successfully' });
    });

    it('should handle logout failure', async () => {
      const mockResponse = {
        ok: false,
        json: () => Promise.resolve({ error: { message: 'Logout failed' } })
      };
      mockFetch.mockResolvedValueOnce(mockResponse);

      await expect(logoutReact()).rejects.toThrow('Logout failed');
    });
  });

  describe('getCurrentUserReact', () => {
    it('should get current user successfully', async () => {
      const mockResponse = {
        ok: true,
        json: () => Promise.resolve({ user: { id: '1', email: 'test@example.com' } })
      };
      mockFetch.mockResolvedValueOnce(mockResponse);

      const result = await getCurrentUserReact();

      expect(mockFetch).toHaveBeenCalledWith('/api/auth/me', {
  method: 'GET',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' }
      });
      expect(result).toEqual({ id: '1', email: 'test@example.com' });
    });

    it('should return null for unauthorized request', async () => {
      const mockResponse = {
        ok: false,
        status: 401
      };
      mockFetch.mockResolvedValueOnce(mockResponse);

      const result = await getCurrentUserReact();

      expect(result).toBeNull();
    });

    it('should handle errors gracefully', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      const result = await getCurrentUserReact();

      expect(result).toBeNull();
    });
  });

  describe('isAuthenticatedReact', () => {
    it('should return true for authenticated user', async () => {
      const mockResponse = {
        ok: true,
        json: () => Promise.resolve({ user: { id: '1', email: 'test@example.com' } })
      };
      mockFetch.mockResolvedValueOnce(mockResponse);

      const result = await isAuthenticatedReact();

      expect(result).toBe(true);
    });

    it('should return false for unauthenticated user', async () => {
      const mockResponse = {
        ok: false,
        status: 401
      };
      mockFetch.mockResolvedValueOnce(mockResponse);

      const result = await isAuthenticatedReact();

      expect(result).toBe(false);
    });
  });

  describe('getAuthToken', () => {
    it('should get auth token from cookies', () => {
      document.cookie = 'auth-token=abc123; Path=/';

      const token = getAuthToken();

      expect(token).toBe('abc123');
    });

    it('should return null if no token exists', () => {
      document.cookie = '';

      const token = getAuthToken();

      expect(token).toBeNull();
    });
  });

  describe('hasAuthToken', () => {
    it('should return true if token exists', () => {
      document.cookie = 'auth-token=abc123; Path=/';

      const hasToken = hasAuthToken();

      expect(hasToken).toBe(true);
    });

    it('should return false if no token exists', () => {
      document.cookie = '';

      const hasToken = hasAuthToken();

      expect(hasToken).toBe(false);
    });
  });

  describe('createUseAuthToken', () => {
    it('should create a hook function', () => {
      const useAuthToken = createUseAuthToken();

      expect(typeof useAuthToken).toBe('function');
    });
  });

  describe('withAuthReact', () => {
    it('should create a higher-order component', () => {
      const AuthHOC = withAuthReact();
      const MockComponent = () => null;
      const WrappedComponent = AuthHOC(MockComponent);

      expect(typeof WrappedComponent).toBe('function');
    });

    it('should accept options', () => {
      const AuthHOC = withAuthReact({
        fallback: null,
        redirectTo: '/login',
        checkAuthEndpoint: '/api/auth/check'
      });

      expect(typeof AuthHOC).toBe('function');
    });
  });
});
