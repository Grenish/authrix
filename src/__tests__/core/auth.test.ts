import { describe, it, expect, beforeEach, jest } from '@jest/globals';

// Create mock adapter first
const mockAdapter = {
  findUserByEmail: jest.fn() as jest.MockedFunction<any>,
  createUser: jest.fn() as jest.MockedFunction<any>,
  getUserById: jest.fn() as jest.MockedFunction<any>,
};

// Mock the config before importing core functions
jest.mock('../../config', () => {
  const mockAuthConfig = {
    getInstance: jest.fn().mockReturnValue({
      db: mockAdapter,
      jwtSecret: 'test-secret',
      cookieName: 'auth_token',
      tokenExpiry: '24h'
    })
  };
  
  return {
    authConfig: mockAuthConfig.getInstance(),
    AuthConfigSingleton: mockAuthConfig
  };
});

import { signupCore } from '../../core/signup';
import { signinCore } from '../../core/signin';
import { logoutCore } from '../../core/logout';

// Mock bcrypt
jest.mock('bcryptjs', () => ({
  compare: jest.fn() as jest.MockedFunction<any>,
  hash: jest.fn() as jest.MockedFunction<any>
}));

import bcrypt from 'bcryptjs';
const mockBcrypt = bcrypt as jest.Mocked<typeof bcrypt>;

// Mock the config
// (Already mocked above)

describe('Core Authentication', () => {
  beforeEach(() => {
    // Clear all mocks before each test
    jest.clearAllMocks();
    
    // Setup default mock implementations
    mockAdapter.findUserByEmail.mockResolvedValue(null);
    mockAdapter.createUser.mockResolvedValue({
      id: 'test-user-id',
      email: 'test@example.com',
      password: 'hashed-password',
      createdAt: new Date()
    });
  });

  describe('signupCore', () => {
    it('should create a new user successfully', async () => {
      const email = 'test@example.com';
  const password = 'P@ssw0rdZ9!';
      
      const result = await signupCore(email, password);
      
      expect(result).toBeDefined();
      expect(result.user).toBeDefined();
      expect(result.user.id).toBe('test-user-id');
      expect(result.user.email).toBe(email);
      expect(result.token).toBeDefined();
      expect(typeof result.token).toBe('string');
      expect(result.cookieOptions).toBeDefined();
      expect(mockAdapter.findUserByEmail).toHaveBeenCalledWith(email);
      expect(mockAdapter.createUser).toHaveBeenCalled();
    });

    it('should reject signup with existing email', async () => {
      const email = 'existing@example.com';
  const password = 'P@ssw0rdZ9!';
      
      // Mock existing user
      mockAdapter.findUserByEmail.mockResolvedValue({
        id: 'existing-user-id',
        email: email,
        password: 'hashed-password',
        createdAt: new Date()
      });
      
  await expect(signupCore(email, password)).rejects.toThrow('An account with this email already exists');
      expect(mockAdapter.findUserByEmail).toHaveBeenCalledWith(email);
      expect(mockAdapter.createUser).not.toHaveBeenCalled();
    });

    it('should validate email format', async () => {
      const invalidEmail = 'invalid-email';
  const password = 'P@ssw0rdZ9!';
      
      await expect(signupCore(invalidEmail, password)).rejects.toThrow();
    });

    it('should validate password requirements', async () => {
      const email = 'test@example.com';
      const weakPassword = '123';
      
      await expect(signupCore(email, weakPassword)).rejects.toThrow();
    });

    it('should handle empty email', async () => {
      const email = '';
  const password = 'P@ssw0rdZ9!';
      
      await expect(signupCore(email, password)).rejects.toThrow();
    });

    it('should handle empty password', async () => {
      const email = 'test@example.com';
      const password = '';
      
      await expect(signupCore(email, password)).rejects.toThrow();
    });
  });

  describe('signinCore', () => {
    const existingUser = {
      id: 'test-user-id',
      email: 'test@example.com',
      password: '$2b$10$mockHashedPassword', // Mock bcrypt hash
      createdAt: new Date()
    };

    beforeEach(() => {
      mockAdapter.findUserByEmail.mockResolvedValue(existingUser);
    });

    it('should sign in with correct credentials', async () => {
      const email = 'test@example.com';
  const password = 'P@ssw0rdZ9!';
      
      // Mock password verification
      (mockBcrypt.compare as jest.MockedFunction<any>).mockResolvedValueOnce(true);
      
      const result = await signinCore(email, password);
      
      expect(result).toBeDefined();
      expect(result.user).toBeDefined();
      expect(result.user.id).toBe(existingUser.id);
      expect(result.user.email).toBe(email);
      expect(result.token).toBeDefined();
      expect(typeof result.token).toBe('string');
      expect(result.cookieOptions).toBeDefined();
      expect(mockAdapter.findUserByEmail).toHaveBeenCalledWith(email);
    });

    it('should reject signin with non-existent user', async () => {
      const email = 'nonexistent@example.com';
      const password = 'password123';
      
      mockAdapter.findUserByEmail.mockResolvedValue(null);
      
      await expect(signinCore(email, password)).rejects.toThrow('Invalid email or password');
      expect(mockAdapter.findUserByEmail).toHaveBeenCalledWith(email);
    });

    it('should reject signin with wrong password', async () => {
      const email = 'test@example.com';
      const password = 'wrongpassword';
      
      // Mock password verification failure
      (mockBcrypt.compare as jest.MockedFunction<any>).mockResolvedValueOnce(false);
      
      await expect(signinCore(email, password)).rejects.toThrow('Invalid email or password');
    });

    it('should handle empty email', async () => {
      const email = '';
      const password = 'password123';
      
      await expect(signinCore(email, password)).rejects.toThrow();
    });

    it('should handle empty password', async () => {
      const email = 'test@example.com';
      const password = '';
      
      await expect(signinCore(email, password)).rejects.toThrow();
    });
  });

  describe('logoutCore', () => {
    it('should return logout response', () => {
      const result = logoutCore();
      
      expect(result).toBeDefined();
      expect(result.message).toBe('Logged out successfully');
  expect(Array.isArray(result.cookiesToClear)).toBe(true);
  expect(result.cookiesToClear.length).toBeGreaterThan(0);
  expect(result.cookiesToClear[0].options.expires).toEqual(new Date(0)); // Cookie should be expired
    });

    it('should set cookie expiration to past date', () => {
      const result = logoutCore();
      
  const exp = result.cookiesToClear[0].options.expires;
  expect(exp).toBeInstanceOf(Date);
  expect(exp.getTime()).toBeLessThan(Date.now());
    });

    it('should maintain security settings in cookie options', () => {
      const result = logoutCore();
      
  const opts = result.cookiesToClear[0].options;
  expect(opts.httpOnly).toBe(true);
  expect(opts.secure).toBeDefined();
  expect(opts.sameSite).toBeDefined();
    });
  });

  describe('Error Handling', () => {
    it('should handle adapter errors gracefully', async () => {
      const email = 'test@example.com';
      const password = 'password123';
      
      mockAdapter.findUserByEmail.mockRejectedValue(new Error('Database error'));
      
      await expect(signupCore(email, password)).rejects.toThrow('Database error');
    });

    it('should handle createUser errors', async () => {
      const email = 'test@example.com';
      const password = 'password123';
      
      mockAdapter.createUser.mockRejectedValue(new Error('Create user failed'));
      
      await expect(signupCore(email, password)).rejects.toThrow('Create user failed');
    });
  });
});
