import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';

// Create mock adapter first
const mockAdapter = {
  findUserByEmail: jest.fn() as jest.MockedFunction<any>,
  findUserByUsername: jest.fn() as jest.MockedFunction<any>,
  createUser: jest.fn() as jest.MockedFunction<any>,
  updateUser: jest.fn() as jest.MockedFunction<any>,
  clearAllUsers: jest.fn() as jest.MockedFunction<any>,
};

// Mock the config before importing core functions
jest.mock('../../config', () => {
  const mockAuthConfig = {
    getInstance: jest.fn().mockReturnValue({
      db: mockAdapter,
      jwtSecret: 'test-secret-key-for-sso-testing',
      cookieName: 'auth_token'
    })
  };
  
  return {
    authConfig: mockAuthConfig.getInstance(),
    initAuth: jest.fn(),
    AuthConfigSingleton: { getInstance: mockAuthConfig.getInstance }
  };
});

// Mock the OAuth providers
jest.mock('../../providers/google', () => ({
  handleGoogleCallback: jest.fn()
}));

jest.mock('../../providers/github', () => ({
  handleGitHubCallback: jest.fn()
}));

import { 
  handleGoogleSSO, 
  handleGitHubSSO, 
  processSSOAuthentication,
  generateSSOState,
  verifySSOState,
  SSOUser 
} from '../../core/sso';

describe('SSO Core Functions', () => {
  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    
    // Set up default mock implementations
    mockAdapter.findUserByEmail.mockResolvedValue(null);
    mockAdapter.findUserByUsername.mockResolvedValue(null);
    mockAdapter.createUser.mockImplementation((userData: any) => Promise.resolve({
      id: 'test-user-id',
      ...userData,
      createdAt: new Date()
    }));
    mockAdapter.updateUser.mockImplementation((id: any, updates: any) => Promise.resolve({
      id,
      email: 'test@example.com',
      ...updates
    }));
  });

  describe('generateSSOState and verifySSOState', () => {
    it('should generate and verify valid state', () => {
      const testData = { redirect: '/dashboard', userId: '123' };
      const state = generateSSOState(testData);
      
      expect(state).toBeDefined();
      expect(typeof state).toBe('string');
      
      const verifiedData = verifySSOState(state);
      expect(verifiedData).toMatchObject(testData);
      expect(verifiedData.timestamp).toBeDefined();
      expect(verifiedData.nonce).toBeDefined();
    });

    it('should reject expired state', async () => {
      const state = generateSSOState({ test: 'data' });
      
      // Wait for state to expire (using very short maxAge)
      await new Promise(resolve => setTimeout(resolve, 10));
      
      expect(() => verifySSOState(state, 5)).toThrow('State has expired');
    });

    it('should reject invalid state format', () => {
      expect(() => verifySSOState('invalid-state')).toThrow('Invalid SSO state');
    });
  });

  describe('processSSOAuthentication', () => {
    it('should create new user for SSO authentication', async () => {
      const ssoUser: SSOUser = {
        id: 'google_123456789',
        email: 'john.doe@example.com',
        name: 'John Doe',
        provider: 'google',
        verified: true
      };

      const result = await processSSOAuthentication(ssoUser, {
        autoCreateUser: true
      });

      expect(result.isNewUser).toBe(true);
      expect(result.user.email).toBe('john.doe@example.com');
      expect(result.provider).toBe('google');
      expect(result.token).toBeDefined();
      expect(result.cookieOptions).toBeDefined();
      expect(mockAdapter.createUser).toHaveBeenCalled();
    });

    it('should handle existing user for SSO authentication', async () => {
      // Mock existing user
      const existingUser = {
        id: 'existing-user-id',
        email: 'jane.doe@example.com',
        firstName: 'Jane',
        password: 'hashedpassword123'
      };
      
      mockAdapter.findUserByEmail.mockImplementation((email: string) => {
        if (email === 'jane.doe@example.com') {
          return Promise.resolve(existingUser);
        }
        return Promise.resolve(null);
      });

      const ssoUser: SSOUser = {
        id: 'github_987654321',
        email: 'jane.doe@example.com',
        name: 'Jane Smith',
        provider: 'github',
        verified: true
      };

      const result = await processSSOAuthentication(ssoUser, {
        autoCreateUser: true,
        updateExistingUser: true,
        mergeUserData: true
      });

      expect(result.isNewUser).toBe(false);
      expect(result.user.email).toBe('jane.doe@example.com');
      expect(result.provider).toBe('github');
      expect(mockAdapter.createUser).not.toHaveBeenCalled();
    });

    it('should reject unverified email when required', async () => {
      const ssoUser: SSOUser = {
        id: 'google_777888999',
        email: 'unverified@example.com',
        provider: 'google',
        verified: false
      };

      await expect(processSSOAuthentication(ssoUser, {
        requireVerifiedEmail: true
      })).rejects.toThrow('SSO email is not verified');
    });

    it('should throw error when autoCreateUser is false and user does not exist', async () => {
      const ssoUser: SSOUser = {
        id: 'google_000111222',
        email: 'nonexistent@example.com',
        provider: 'google',
        verified: true
      };

      await expect(processSSOAuthentication(ssoUser, {
        autoCreateUser: false
      })).rejects.toThrow('No account found for nonexistent@example.com');
    });

    it('should apply custom user mapping', async () => {
      const ssoUser: SSOUser = {
        id: 'github_custom123',
        email: 'custom@example.com',
        name: 'Custom User',
        provider: 'github',
        verified: true,
        customField: 'custom value'
      };

      const customMapping = (user: SSOUser) => ({
        firstName: 'CustomFirst',
        lastName: 'CustomLast',
        customData: user.customField
      });

      const result = await processSSOAuthentication(ssoUser, {
        customUserMapping: customMapping
      });

      expect(result.user.email).toBe('custom@example.com');
      expect(result.provider).toBe('github');
      expect(mockAdapter.createUser).toHaveBeenCalledWith(
        expect.objectContaining({
          firstName: 'CustomFirst',
          lastName: 'CustomLast',
          customData: 'custom value'
        })
      );
    });
  });

  describe('handleGoogleSSO', () => {
    it('should handle Google OAuth callback successfully', async () => {
      const { handleGoogleCallback } = await import('../../providers/google');
      
      // Mock the Google callback
      (handleGoogleCallback as jest.MockedFunction<any>).mockResolvedValue({
        id: 'google_123',
        email: 'google.user@example.com',
        name: 'Google User',
        avatar: 'https://example.com/avatar.jpg'
      });

      const result = await handleGoogleSSO('test-auth-code');

      expect(result.provider).toBe('google');
      expect(result.user.email).toBe('google.user@example.com');
      expect(result.token).toBeDefined();
    });

    it('should handle Google OAuth errors', async () => {
      const { handleGoogleCallback } = await import('../../providers/google');
      
      (handleGoogleCallback as jest.MockedFunction<any>).mockRejectedValue(new Error('OAuth failed'));

      await expect(handleGoogleSSO('invalid-code')).rejects.toThrow('Google SSO failed: OAuth failed');
    });
  });

  describe('handleGitHubSSO', () => {
    it('should handle GitHub OAuth callback successfully', async () => {
      const { handleGitHubCallback } = await import('../../providers/github');
      
      // Mock the GitHub callback
      (handleGitHubCallback as jest.MockedFunction<any>).mockResolvedValue({
        id: 'github_456',
        email: 'github.user@example.com',
        name: 'GitHub User',
        avatar: 'https://github.com/avatar.jpg'
      });

      const result = await handleGitHubSSO('test-auth-code');

      expect(result.provider).toBe('github');
      expect(result.user.email).toBe('github.user@example.com');
      expect(result.token).toBeDefined();
    });

    it('should handle GitHub OAuth errors', async () => {
      const { handleGitHubCallback } = await import('../../providers/github');
      
      (handleGitHubCallback as jest.MockedFunction<any>).mockRejectedValue(new Error('GitHub API error'));

      await expect(handleGitHubSSO('invalid-code')).rejects.toThrow('GitHub SSO failed: GitHub API error');
    });
  });

  describe('Error handling', () => {
    it('should throw error when SSO user data is invalid', async () => {
      const invalidSSOUser = {
        provider: 'google'
        // Missing required fields
      } as SSOUser;

      await expect(processSSOAuthentication(invalidSSOUser)).rejects.toThrow();
    });
  });
});
