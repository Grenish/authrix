import { describe, it, expect } from '@jest/globals';
import { 
  hashPassword, 
  verifyPassword, 
  validatePassword, 
  generateSecurePassword, 
  needsRehash 
} from '../../utils/hash';
import bcrypt from 'bcryptjs';

describe('Hash Utilities', () => {
  const strongPassword = 'TestPassw0rd9!'; // Changed to avoid sequential characters
  const weakPassword = 'test';
  const emptyPassword = '';

  describe('validatePassword', () => {
    it('should accept strong passwords', () => {
      const result = validatePassword(strongPassword);
      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject weak passwords', () => {
      const result = validatePassword(weakPassword);
      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should reject empty passwords', () => {
      const result = validatePassword(emptyPassword);
      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should reject passwords without special characters', () => {
      const result = validatePassword('TestPassword123');
      expect(result.isValid).toBe(false);
      expect(result.errors.some(e => e.includes('special character'))).toBe(true);
    });

    it('should reject passwords with sequential characters', () => {
      const result = validatePassword('TestAbcD9!'); // Contains "abc" which is sequential
      expect(result.isValid).toBe(false);
      expect(result.errors.some(e => e.includes('sequential'))).toBe(true);
    });
  });

  describe('hashPassword', () => {
    it('should hash a strong password successfully', async () => {
      const hashedPassword = await hashPassword(strongPassword);
      
      expect(hashedPassword).toBeDefined();
      expect(typeof hashedPassword).toBe('string');
      expect(hashedPassword).not.toBe(strongPassword);
      expect(hashedPassword.length).toBeGreaterThan(0);
    });

    it('should generate different hashes for the same password', async () => {
      const hash1 = await hashPassword(strongPassword);
      const hash2 = await hashPassword(strongPassword);
      
      expect(hash1).not.toBe(hash2);
    });

    it('should reject weak passwords by default', async () => {
      await expect(hashPassword(weakPassword)).rejects.toThrow('Password validation failed');
    });

    it('should accept weak passwords when validation is skipped', async () => {
      const hashedPassword = await hashPassword(weakPassword, { skipValidation: true });
      
      expect(hashedPassword).toBeDefined();
      expect(typeof hashedPassword).toBe('string');
    });

    it('should handle special characters in strong passwords', async () => {
      const complexPassword = 'TestPa$$w0rd9!'; // Changed to avoid sequential characters
      const hashedPassword = await hashPassword(complexPassword);
      
      expect(hashedPassword).toBeDefined();
      expect(typeof hashedPassword).toBe('string');
    });

    it('should create bcrypt compatible hash', async () => {
      const hashedPassword = await hashPassword(strongPassword);
      
      // Should be verifiable with bcrypt
      const isValid = await bcrypt.compare(strongPassword, hashedPassword);
      expect(isValid).toBe(true);
    });

    it('should generate hashes with sufficient length', async () => {
      const hashedPassword = await hashPassword(strongPassword);
      
      // bcrypt hashes are typically 60 characters long
      expect(hashedPassword.length).toBeGreaterThanOrEqual(50);
    });

    it('should start with bcrypt identifier', async () => {
      const hashedPassword = await hashPassword(strongPassword);
      
      // bcrypt hashes start with $2a$, $2b$, $2x$, or $2y$
      expect(hashedPassword).toMatch(/^\$2[abxy]\$/);
    });

    it('should use higher rounds for security', async () => {
      const hashedPassword = await hashPassword(strongPassword);
      const rounds = parseInt(hashedPassword.split('$')[2]);
      
      expect(rounds).toBeGreaterThanOrEqual(14);
    });

    it('should enforce rate limiting', async () => {
      const identifier = 'test-user-1';
      
      // Should allow initial operations
      await hashPassword(strongPassword, { identifier });
      
      // Simulate many operations to trigger rate limit (but not too many to avoid timeout)
      const promises = Array(12).fill(0).map(() => 
        hashPassword(strongPassword, { identifier, skipValidation: true }).catch(e => e.message)
      );
      
      const results = await Promise.all(promises);
      const rateLimitErrors = results.filter(r => 
        typeof r === 'string' && r.includes('Too many password operations')
      );
      
      expect(rateLimitErrors.length).toBeGreaterThan(0);
    }, 30000); // Increase timeout for this test
  });

  describe('verifyPassword', () => {
    let hashedPassword: string;

    beforeAll(async () => {
      hashedPassword = await hashPassword(strongPassword);
    });

    it('should verify correct password', async () => {
      const isValid = await verifyPassword(strongPassword, hashedPassword);
      expect(isValid).toBe(true);
    });

    it('should reject incorrect password', async () => {
      const isValid = await verifyPassword('WrongPassword123!', hashedPassword);
      expect(isValid).toBe(false);
    });

    it('should handle empty password securely', async () => {
      const isValid = await verifyPassword('', hashedPassword);
      expect(isValid).toBe(false);
    });

    it('should handle empty hash securely', async () => {
      const isValid = await verifyPassword(strongPassword, '');
      expect(isValid).toBe(false);
    });

    it('should handle invalid hash format', async () => {
      const isValid = await verifyPassword(strongPassword, 'invalid-hash');
      expect(isValid).toBe(false);
    });

    it('should enforce rate limiting', async () => {
      const identifier = 'test-user-2';
      
      // Use a simple hash for this test to avoid timeout
      const simpleHash = await hashPassword('TestPa$$w0rd8!', { skipValidation: true });
      
      // Simulate many verification attempts (fewer to avoid timeout)
      const promises = Array(12).fill(0).map(() => 
        verifyPassword(strongPassword, simpleHash, { identifier }).catch(e => e.message)
      );
      
      const results = await Promise.all(promises);
      const rateLimitErrors = results.filter(r => 
        typeof r === 'string' && r.includes('Too many password verification attempts')
      );
      
      expect(rateLimitErrors.length).toBeGreaterThan(0);
    }, 30000); // Increase timeout
  });

  describe('generateSecurePassword', () => {
    it('should generate password with default settings', () => {
      const password = generateSecurePassword();
      
      expect(password).toBeDefined();
      expect(password.length).toBe(16);
      expect(/[a-z]/.test(password)).toBe(true);
      expect(/[A-Z]/.test(password)).toBe(true);
      expect(/\d/.test(password)).toBe(true);
      expect(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)).toBe(true);
    });

    it('should generate password with custom length', () => {
      const password = generateSecurePassword(20);
      expect(password.length).toBe(20);
    });

    it('should generate password without symbols when disabled', () => {
      const password = generateSecurePassword(16, { includeSymbols: false });
      expect(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)).toBe(false);
    });

    it('should exclude similar characters when enabled', () => {
      const password = generateSecurePassword(16, { excludeSimilar: true });
      // Should not contain confusing characters like 0, O, 1, l, I
      expect(/[0O1lI]/.test(password)).toBe(false);
    });

    it('should throw error for invalid length', () => {
      expect(() => generateSecurePassword(4)).toThrow('Password length must be between 8 and 128');
      expect(() => generateSecurePassword(200)).toThrow('Password length must be between 8 and 128');
    });

    it('should throw error when no character sets enabled', () => {
      expect(() => generateSecurePassword(16, {
        includeLowercase: false,
        includeUppercase: false,
        includeNumbers: false,
        includeSymbols: false
      })).toThrow('At least one character set must be enabled');
    });
  });

  describe('needsRehash', () => {
    it('should detect old hash that needs rehashing', () => {
      // Old hash with lower rounds
      const oldHash = '$2b$10$test.hash.with.lower.rounds.for.testing.purposes';
      expect(needsRehash(oldHash)).toBe(true);
    });

    it('should detect current hash that does not need rehashing', async () => {
      const currentHash = await hashPassword(strongPassword);
      expect(needsRehash(currentHash)).toBe(false);
    });

    it('should detect invalid hash format', () => {
      expect(needsRehash('invalid-hash')).toBe(true);
    });
  });
});
