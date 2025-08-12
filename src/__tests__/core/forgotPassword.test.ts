import { describe, it, expect, beforeEach, jest } from '@jest/globals';

// Create mock adapter first
const mockAdapter = {
  findUserByEmail: jest.fn() as jest.MockedFunction<any>,
  updateUser: jest.fn() as jest.MockedFunction<any>,
};

// Mock the config before importing core functions
jest.mock('../../config', () => {
  const mockAuthConfig = {
    getInstance: jest.fn().mockReturnValue({
      db: mockAdapter,
      jwtSecret: 'test-secret-key-for-forgot-password-testing',
      cookieName: 'auth_token'
    })
  };
  
  return {
    authConfig: mockAuthConfig.getInstance(),
    initAuth: jest.fn(),
    AuthConfigSingleton: { getInstance: mockAuthConfig.getInstance }
  };
});

// Mock the hash utility with concrete functions to avoid TS type inference issues
jest.mock('../../utils/hash', () => {
  let counter = 0;
  let verifyResult = false;
  return {
    hashPassword: async (password: any) => `hashed_${password}`,
    verifyPassword: async () => verifyResult,
    setVerifyPasswordResult: (val: boolean) => { verifyResult = val; },
    validatePassword: (pwd: string) => {
      const errors: string[] = [];
      if (pwd.length < 8) errors.push('Password must be at least 8 characters long');
      if (!/[A-Z]/.test(pwd)) errors.push('Password must contain at least one uppercase letter');
      if (!/[a-z]/.test(pwd)) errors.push('Password must contain at least one lowercase letter');
      if (!/[0-9]/.test(pwd)) errors.push('Password must contain at least one number');
      return { isValid: errors.length === 0, errors };
    },
    // Produce strong and varying passwords per call without relying on real randomness
    generateSecurePassword: (len: number = 12) => {
      counter++;
      const upp = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      const low = 'abcdefghijklmnopqrstuvwxyz';
      const num = '0123456789';
      const sym = '!@#$%^&*';
      const pick = (set: string, i: number) => set[i % set.length];
      const required = [
        pick(upp, counter),
        pick(low, counter + 1),
        pick(num, counter + 2),
        pick(sym, counter + 3)
      ];
      const pool = upp + low + num + sym;
      let rest = '';
      for (let i = 0; i < Math.max(0, len - required.length); i++) {
        rest += pick(pool, counter + i + 4);
      }
      const base = (required.join('') + rest).slice(0, len);
      const rot = counter % Math.max(1, len);
      return base.slice(rot) + base.slice(0, rot);
    }
  };
});

import { 
  initiateForgotPassword, 
  resetPasswordWithCode,
  generateTemporaryPassword,
  sendTemporaryPassword,
  ForgotPasswordOptions,
  ResetPasswordOptions 
} from '../../core/forgotPassword';

describe('Forgot Password Functions', () => {
  function extractLastResetCode(): string {
    const calls = (console.log as jest.MockedFunction<any>).mock.calls;
    for (let i = calls.length - 1; i >= 0; i--) {
      const first = calls[i][0];
      if (typeof first === 'string' && first.includes('[AUTHRIX] Password reset code')) {
        const m = first.match(/: (\d+)/);
        if (m) return m[1];
      }
    }
    return '123456';
  }
  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    
    // Set up default mock implementations
    mockAdapter.findUserByEmail.mockResolvedValue(null);

    // In-memory 2FA store for tests
    const codes: any[] = [];
    (mockAdapter as any).storeTwoFactorCode = async (code: any) => {
      codes.push({ ...code });
    };
    (mockAdapter as any).getTwoFactorCode = async (id: string) => {
      return codes.find(c => c.id === id) || null;
    };
    (mockAdapter as any).updateTwoFactorCode = async (id: string, updates: any) => {
      const idx = codes.findIndex(c => c.id === id);
      if (idx >= 0) codes[idx] = { ...codes[idx], ...updates };
    };
    (mockAdapter as any).getUserTwoFactorCodes = async (userId: string, type?: string) => {
      return codes
        .filter(c => c.userId === userId && (!type || c.type === type))
        .map(c => ({ ...c }));
    };
    
    // Add updateUser method to mock adapter
    mockAdapter.updateUser = jest.fn().mockImplementation((id: any, updates: any) => Promise.resolve({
      id,
      email: 'test@example.com',
      ...updates
    }));

    // Mock console.log to capture password reset codes
    jest.spyOn(console, 'log').mockImplementation(() => {});
    
    // Clear rate limiting store between tests
    const { clearRateLimitStore } = require('../../core/forgotPassword');
    if (clearRateLimitStore) {
      clearRateLimitStore();
    }
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('initiateForgotPassword', () => {
    it('should successfully initiate forgot password for existing user', async () => {
      const testUser = {
        id: 'test-user-id',
        email: 'test@example.com',
        username: 'testuser',
        password: 'hashed_password'
      };

      mockAdapter.findUserByEmail.mockResolvedValue(testUser);

  const result = await initiateForgotPassword('test@example.com', { useEmailService: false });

      expect(result.success).toBe(true);
      expect(result.message).toContain('Password reset code sent');
      expect(result.codeExpiration).toBeDefined();
      expect(console.log).toHaveBeenCalledWith(expect.stringContaining('[AUTHRIX] Password reset code'));
    });

    it('should handle non-existent user gracefully when requireExistingUser is true', async () => {
      mockAdapter.findUserByEmail.mockResolvedValue(null);

      const result = await initiateForgotPassword('nonexistent@example.com', {
        requireExistingUser: true
      });

      expect(result.success).toBe(true);
      expect(result.message).toContain('If an account with this email exists');
    });

    it('should throw error for non-existent user when requireExistingUser is false', async () => {
      mockAdapter.findUserByEmail.mockResolvedValue(null);

      await expect(initiateForgotPassword('nonexistent@example.com', {
        requireExistingUser: false
      })).rejects.toThrow('No account found with this email address');
    });

    it('should validate email format', async () => {
      await expect(initiateForgotPassword('invalid-email')).rejects.toThrow('Invalid email format');
    });

    it('should use custom options', async () => {
      const testUser = {
        id: 'test-user-id',
        email: 'test@example.com',
        username: 'testuser',
        password: 'hashed_password'
      };

      mockAdapter.findUserByEmail.mockResolvedValue(testUser);

      const options: ForgotPasswordOptions = {
        codeLength: 8,
        codeExpiration: 30,
        customEmailTemplate: (email, code, username) => ({
          subject: 'Custom Reset',
          text: `Custom code: ${code} for ${username}`,
          html: `<p>Custom code: <strong>${code}</strong></p>`
        })
      };

  const result = await initiateForgotPassword('test@example.com', { ...options, useEmailService: false });

      expect(result.success).toBe(true);
      expect(console.log).toHaveBeenCalledWith(expect.stringMatching(/[0-9]{8}/)); // 8-digit code
    });

    it('should enforce rate limiting', async () => {
      const testUser = {
        id: 'test-user-id',
        email: 'test@example.com',
        password: 'hashed_password'
      };

      mockAdapter.findUserByEmail.mockResolvedValue(testUser);

      // First request should succeed
  await initiateForgotPassword('test@example.com', { useEmailService: false });

      // Second immediate request should fail
      await expect(initiateForgotPassword('test@example.com', {
        rateLimitDelay: 60
      })).rejects.toThrow('Please wait 60 seconds');
    });
  });

  describe('resetPasswordWithCode', () => {
    it('should successfully reset password with valid code', async () => {
      const testUser = { id: 'test-user-id', email: 'test@example.com', username: 'testuser', password: 'old_hashed_password' };
      mockAdapter.findUserByEmail.mockResolvedValue(testUser);
      await initiateForgotPassword('test@example.com', { useEmailService: false });
      const code = extractLastResetCode();
      const result = await resetPasswordWithCode('test@example.com', code, 'NewPassword123!');
      expect(result.success).toBe(true);
      expect(result.message).toBe('Password has been reset successfully');
      expect(result.user?.email).toBe('test@example.com');
      expect(mockAdapter.updateUser).toHaveBeenCalledWith(
        'test-user-id',
        expect.objectContaining({ password: 'hashed_NewPassword123!', passwordChangedAt: expect.any(Date) })
      );
    });

    it('should validate password requirements (too weak)', async () => {
      const testUser = { id: 'test-user-id', email: 'test@example.com', password: 'old_password' };
      mockAdapter.findUserByEmail.mockResolvedValue(testUser);
      await expect(
        resetPasswordWithCode('test@example.com', '123456', 'weak')
      ).rejects.toThrow('Password validation failed');
    });

    it('should enforce strong password requirements when enabled', async () => {
      const testUser = { id: 'test-user-id', email: 'test@example.com', password: 'old_password' };
      mockAdapter.findUserByEmail.mockResolvedValue(testUser);
      await expect(
        resetPasswordWithCode('test@example.com', '123456', 'weakpassword', { requireStrongPassword: true })
      ).rejects.toThrow(/Password validation failed: .*one uppercase letter/i);
    });

    it('should reject invalid reset code', async () => {
      const testUser = { id: 'test-user-id', email: 'test@example.com', password: 'old_password' };
      mockAdapter.findUserByEmail.mockResolvedValue(testUser);
      await expect(
        resetPasswordWithCode('test@example.com', 'invalid_code', 'NewPassword123!')
      ).rejects.toThrow('No valid reset code found');
    });

    it('should reject empty or missing code', async () => {
      await expect(
        resetPasswordWithCode('test@example.com', '', 'NewPassword123!')
      ).rejects.toThrow('Reset code is required');
    });

    it('should prevent password reuse when enabled', async () => {
      const testUser = { id: 'test-user-id', email: 'test@example.com', password: '$2b$14$current_hashed_password_mock______________111111' };
      mockAdapter.findUserByEmail.mockResolvedValue(testUser);
      await initiateForgotPassword('test@example.com', { useEmailService: false });
      const code = extractLastResetCode();
      const mockedHash: any = jest.requireMock('../../utils/hash');
      // Force verifyPassword to report equality
      mockedHash.setVerifyPasswordResult(true);
      if (mockedHash.verifyPassword) {
        (mockedHash as any).verifyPassword = async () => true;
      }
      await expect(
        resetPasswordWithCode('test@example.com', code, 'SamePassword123!', { preventReuse: true })
      ).rejects.toThrow('New password cannot be the same as your current password');
      // Then ensure changing verify result allows reset with different password
      mockedHash.setVerifyPasswordResult(false);
      await initiateForgotPassword('test@example.com', { useEmailService: false });
      const code2 = extractLastResetCode();
      const success = await resetPasswordWithCode('test@example.com', code2, 'DifferentPassword123!', { preventReuse: true });
      expect(success.success).toBe(true);
    });
  });

  describe('generateTemporaryPassword', () => {
    it('should generate password with correct length', () => {
      const password = generateTemporaryPassword(16);
      expect(password).toHaveLength(16);
    });

    it('should generate password with default length', () => {
      const password = generateTemporaryPassword();
      expect(password).toHaveLength(12);
    });

    it('should include required character types', () => {
  const password = generateTemporaryPassword(20);

  expect(password).toMatch(/[A-Z]/); // uppercase
  expect(password).toMatch(/[a-z]/); // lowercase
  expect(password).toMatch(/[0-9]/); // numbers
  expect(password).toMatch(/[!@#$%^&*]/); // special characters
    });

    it('should generate different passwords each time', () => {
  const password1 = generateTemporaryPassword();
  const password2 = generateTemporaryPassword();
      
  expect(password1).not.toBe(password2);
    });
  });

  describe('sendTemporaryPassword', () => {
    it('should send temporary password and update user', async () => {
      const testUser = {
        id: 'test-user-id',
        email: 'test@example.com',
        username: 'testuser',
        password: 'old_password'
      };

      mockAdapter.findUserByEmail.mockResolvedValue(testUser);

  const result = await sendTemporaryPassword('test@example.com', { useEmailService: false });

      expect(result.success).toBe(true);
      expect(result.message).toContain('Temporary password sent');
      expect(mockAdapter.updateUser).toHaveBeenCalledWith(
        'test-user-id',
        expect.objectContaining({
          password: expect.stringMatching(/^hashed_/),
          passwordChangedAt: expect.any(Date),
          mustChangePassword: true
        })
      );
      expect(console.log).toHaveBeenCalledWith(expect.stringContaining('[AUTHRIX] Temporary password'));
    });

    it('should handle non-existent user gracefully', async () => {
      mockAdapter.findUserByEmail.mockResolvedValue(null);

      const result = await sendTemporaryPassword('nonexistent@example.com', {
        requireExistingUser: true
      });

      expect(result.success).toBe(true);
      expect(result.message).toContain('If an account with this email exists');
    });

    it('should use custom temporary password length', async () => {
      const testUser = {
        id: 'test-user-id',
        email: 'test@example.com',
        password: 'old_password'
      };

      mockAdapter.findUserByEmail.mockResolvedValue(testUser);

  await sendTemporaryPassword('test@example.com', {
        temporaryPasswordLength: 20
  , useEmailService: false });

      // Check that a 20-character password was logged
      const logCall = (console.log as jest.MockedFunction<any>).mock.calls.find((call: any) => 
        call[0].includes('[AUTHRIX] Temporary password')
      );
      const passwordMatch = logCall[0].match(/: (.+)$/);
      const tempPassword = passwordMatch ? passwordMatch[1] : '';
      
      expect(tempPassword).toHaveLength(20);
    });
  });

  describe('Error handling', () => {
    it('should handle database adapter without updateUser method', async () => {
      const originalUpdateUser = mockAdapter.updateUser;
      delete mockAdapter.updateUser;

      const testUser = { id: 'test-user-id', email: 'alt2@example.com', password: 'old_password' };
      mockAdapter.findUserByEmail.mockResolvedValue(testUser);

      await initiateForgotPassword('alt2@example.com', { useEmailService: false });
      const code = extractLastResetCode();

      await expect(
      resetPasswordWithCode('alt2@example.com', code, 'NewPassword123!')
      ).rejects.toThrow('Database adapter does not support password updates');

      mockAdapter.updateUser = originalUpdateUser;
    });

    it('should handle missing required fields', async () => {
      await expect(resetPasswordWithCode(
        '',
        '123456',
        'NewPassword123!'
      )).rejects.toThrow();

      await expect(resetPasswordWithCode(
        'test@example.com',
        '',
        'NewPassword123!'
      )).rejects.toThrow('Reset code is required');

  await expect(resetPasswordWithCode(
        'test@example.com',
        '123456',
        ''
  )).rejects.toThrow('New password is required');
    });
  });
});
