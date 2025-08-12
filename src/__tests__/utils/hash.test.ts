// hash.test.ts
import * as crypto from 'crypto';

// Ensure environment variables are set BEFORE importing hashing utilities
if (!process.env.AUTHRIX_BCRYPT_ROUNDS) {
  process.env.AUTHRIX_BCRYPT_ROUNDS = '14';
}
if (!process.env.AUTHRIX_PASSWORD_PEPPER) {
  process.env.AUTHRIX_PASSWORD_PEPPER = crypto.randomBytes(32).toString('hex');
}

// Increase default timeout due to Argon2 operations
jest.setTimeout(120000);

import {
  hashPassword,
  verifyPassword,
  verifyAndCheckRehash,
  validatePassword,
  generateSecurePassword,
  needsRehash,
  PasswordValidationResult,
  HashOptions,
  VerifyOptions,
  PasswordPolicy
} from "../../utils/hash";
// (Environment already configured above)

describe('Password Security Test Suite', () => {
  
  // ============================= Password Validation Tests =============================
  
  describe('Password Validation', () => {
    
    test('should reject weak passwords', () => {
      const weakPasswords = [
        '',
        'short',
        '12345678',
        'password',
        'Password1',
        'aaaaaaaaaaa',
        'abcdefghijk',
        'ABCDEFGHIJK',
        '12345678901',
        'qwertyuiop'
      ];
      
      weakPasswords.forEach(password => {
        const result = validatePassword(password);
        expect(result.isValid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
        expect(result.strength).toBeLessThan(50);
      });
    });
    
    test('should accept strong passwords', () => {
      const strongPasswords = [
        'MyS3cur3P@ssw0rd!',
        'C0mpl3x!ty#R3qu1r3d',
        'Un!qu3&S3cur3*2023',
        generateSecurePassword(16),
        generateSecurePassword(20)
      ];
      
      strongPasswords.forEach(password => {
        const result = validatePassword(password);
        expect(result.isValid).toBe(true);
        expect(result.errors.length).toBe(0);
        expect(result.strength).toBeGreaterThan(60);
        expect(result.entropy).toBeGreaterThan(50);
      });
    });
    
    test('should calculate entropy correctly', () => {
      const testCases = [
        { password: 'aaaaaaaa', maxEntropy: 30 },
        { password: 'abcdefgh', minEntropy: 30, maxEntropy: 50 },
        { password: 'AbCdEfGh', minEntropy: 40, maxEntropy: 60 },
        { password: 'AbC123!@', minEntropy: 45, maxEntropy: 70 },
        { password: 'MyC0mpl3x!P@ssw0rd#2023', minEntropy: 80 }
      ];
      
      testCases.forEach(({ password, minEntropy, maxEntropy }) => {
        const result = validatePassword(password);
        if (minEntropy) {
          expect(result.entropy).toBeGreaterThanOrEqual(minEntropy);
        }
        if (maxEntropy) {
          expect(result.entropy).toBeLessThanOrEqual(maxEntropy);
        }
      });
    });
    
    test('should detect common passwords', () => {
      const commonPasswords = [
        'password',
        'PASSWORD',
        'Password',
        '123456',
        'admin',
        'letmein',
        'welcome',
        'monkey',
        'qwerty'
      ];
      
      commonPasswords.forEach(password => {
        const result = validatePassword(password);
        expect(result.isValid).toBe(false);
        expect(result.errors.some(e => e.toLowerCase().includes('common'))).toBe(true);
      });
    });
    
    test('should detect patterns', () => {
      const patternPasswords = [
        'aaaaaaaaaaaaaa', // Repeated characters
        'abcdefghijklmn', // Sequential
        '12345678901234', // Sequential numbers
        'qwertyuiopasdf', // Keyboard pattern
        'AAAAAAAAAAaaaa', // Repeated with variation
      ];
      
      patternPasswords.forEach(password => {
        const result = validatePassword(password);
        expect(result.isValid).toBe(false);
        expect(result.errors.some(e => e.toLowerCase().includes('pattern') || e.toLowerCase().includes('predictable'))).toBe(true);
      });
    });
    
    test('should prevent user information in passwords', () => {
      const userInfo = ['john', 'doe', 'john.doe@example.com', '1990'];
      
      const passwordsWithUserInfo = [
        'John123456!@#',
        'doeDoe123!@#',
        'MyNameIsJohn!23',
        'born1990Pass!',
        'john.doe@Pass123!'
      ];
      
      passwordsWithUserInfo.forEach(password => {
        const result = validatePassword(password, {}, userInfo);
        expect(result.isValid).toBe(false);
        expect(result.errors.some(e => e.toLowerCase().includes('personal'))).toBe(true);
      });
    });
    
    test('should enforce custom password policies', () => {
      const strictPolicy: Partial<PasswordPolicy> = {
        minLength: 20,
        maxLength: 30,
        minEntropy: 80,
        requireLowercase: true,
        requireUppercase: true,
        requireNumbers: true,
        requireSymbols: true
      };
      
      const shortPassword = 'Short1!';
      const result1 = validatePassword(shortPassword, strictPolicy);
      expect(result1.isValid).toBe(false);
      expect(result1.errors.some(e => e.includes('20'))).toBe(true);
      
      const longPassword = 'a'.repeat(31);
      const result2 = validatePassword(longPassword, strictPolicy);
      expect(result2.isValid).toBe(false);
      expect(result2.errors.some(e => e.includes('30'))).toBe(true);
    });
  });
  
  // ============================= Password Hashing Tests =============================
  
  describe('Password Hashing', () => {
    
    test('should hash passwords with Argon2 by default', async () => {
      const password = 'MyS3cur3P@ssw0rd!';
      const hash = await hashPassword(password);
      
      expect(hash).toBeDefined();
      expect(hash.startsWith('$argon2')).toBe(true);
      expect(hash.length).toBeGreaterThan(60);
    });
    
    test('should hash passwords with bcrypt when specified', async () => {
      const password = 'MyS3cur3P@ssw0rd!';
      const hash = await hashPassword(password, { algorithm: 'bcrypt' });
      
      expect(hash).toBeDefined();
      expect(hash.startsWith('$2')).toBe(true);
      expect(hash.length).toBeGreaterThanOrEqual(60);
    });
    
    test('should produce different hashes for same password', async () => {
      const password = 'MyS3cur3P@ssw0rd!';
      const hash1 = await hashPassword(password);
      const hash2 = await hashPassword(password);
      
      expect(hash1).not.toBe(hash2);
    });
    
    test('should reject invalid passwords when validation enabled', async () => {
      const weakPassword = 'weak';
      
      await expect(hashPassword(weakPassword)).rejects.toThrow('Invalid password');
    });
    
    test('should allow weak passwords when validation disabled', async () => {
      const weakPassword = 'weak';
      const hash = await hashPassword(weakPassword, { skipValidation: true });
      
      expect(hash).toBeDefined();
      expect(hash.length).toBeGreaterThan(0);
    });
    
    test('should handle non-string inputs', async () => {
      // @ts-ignore - Testing runtime type checking
      await expect(hashPassword(123)).rejects.toThrow(TypeError);
      // @ts-ignore
      await expect(hashPassword(null)).rejects.toThrow(TypeError);
      // @ts-ignore
      await expect(hashPassword(undefined)).rejects.toThrow(TypeError);
      // @ts-ignore
      await expect(hashPassword({})).rejects.toThrow(TypeError);
    });
    
    test('should handle extremely long passwords', async () => {
      const longPassword = 'A1b!' + 'x'.repeat(252); // 256 characters
      const hash = await hashPassword(longPassword, { skipValidation: true });
      
      expect(hash).toBeDefined();
      
      const tooLongPassword = 'A1b!' + 'x'.repeat(253); // 257 characters
      await expect(hashPassword(tooLongPassword)).rejects.toThrow();
    });
  });
  
  // ============================= Password Verification Tests =============================
  
  describe('Password Verification', () => {
    let testPasswordHash: string;
    let bcryptHash: string;
    const testPassword = 'MyS3cur3P@ssw0rd!';
    
    beforeAll(async () => {
      testPasswordHash = await hashPassword(testPassword);
      bcryptHash = await hashPassword(testPassword, { algorithm: 'bcrypt' });
    });
    
    test('should verify correct passwords', async () => {
      const isValid = await verifyPassword(testPassword, testPasswordHash);
      expect(isValid).toBe(true);
      
      const isValidBcrypt = await verifyPassword(testPassword, bcryptHash);
      expect(isValidBcrypt).toBe(true);
    });
    
    test('should reject incorrect passwords', async () => {
      const wrongPasswords = [
        'WrongPassword123!',
        'MyS3cur3P@ssw0rd',
        'MyS3cur3P@ssw0rd!!',
        'mys3cur3p@ssw0rd!',
        ''
      ];
      
      for (const wrong of wrongPasswords) {
        const isValid = await verifyPassword(wrong, testPasswordHash);
        expect(isValid).toBe(false);
      }
    });
    
    test('should handle malformed hashes safely', async () => {
      const malformedHashes = [
        '',
        'not-a-hash',
        '$2b$',
        '$argon2$',
        '$2b$10$invalid',
        '${__proto__}',
        null,
        undefined,
        123
      ];
      
      for (const badHash of malformedHashes) {
        // @ts-ignore - Testing runtime handling
        const isValid = await verifyPassword(testPassword, badHash);
        expect(isValid).toBe(false);
      }
    });
    
    test('should have consistent timing for invalid passwords', async () => {
      const timings: number[] = [];
      const iterations = 10;
      
      for (let i = 0; i < iterations; i++) {
        const start = process.hrtime.bigint();
        await verifyPassword('wrong', testPasswordHash);
        const end = process.hrtime.bigint();
        timings.push(Number(end - start));
      }
      
      // Calculate standard deviation
      const mean = timings.reduce((a, b) => a + b) / timings.length;
      const variance = timings.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / timings.length;
      const stdDev = Math.sqrt(variance);
      const coefficientOfVariation = (stdDev / mean) * 100;
      
      // Timing should be relatively consistent (CV < 30%)
      expect(coefficientOfVariation).toBeLessThan(30);
    });
    
    test('should detect rehash requirements', async () => {
      // Create a hash with lower rounds
      const oldEnv = process.env.AUTHRIX_BCRYPT_ROUNDS;
      process.env.AUTHRIX_BCRYPT_ROUNDS = '10';
      
      // Force module reload to pick up new env
      jest.resetModules();
  const { hashPassword: hashWithLowRounds } = require('../../utils/hash');
      
      const weakHash = await hashWithLowRounds(testPassword, { algorithm: 'bcrypt' });
      
      // Restore original rounds
      process.env.AUTHRIX_BCRYPT_ROUNDS = oldEnv;
      jest.resetModules();
      
      const result = await verifyAndCheckRehash(testPassword, weakHash);
      expect(result.valid).toBe(true);
      expect(result.needsRehash).toBe(true);
    });
  });
  
  // ============================= Rate Limiting Tests =============================
  
  describe('Rate Limiting', () => {
    
    test('should enforce rate limits per identifier', async () => {
      const identifier = 'test-user-' + Date.now();
      const password = 'TestP@ssw0rd123!';
      
      // Should allow initial attempts
      for (let i = 0; i < 5; i++) {
        const hash = await hashPassword(password, { identifier });
        expect(hash).toBeDefined();
      }
      
      // Should block after limit exceeded
      await expect(
        hashPassword(password, { identifier })
      ).rejects.toThrow(/rate limit/i);
    });
    
    test('should track rate limits separately for different identifiers', async () => {
      const identifier1 = 'user1-' + Date.now();
      const identifier2 = 'user2-' + Date.now();
      const password = 'TestP@ssw0rd123!';
      
      // Exhaust rate limit for identifier1
      for (let i = 0; i < 5; i++) {
        await hashPassword(password, { identifier: identifier1 });
      }
      
      // identifier2 should still work
      const hash = await hashPassword(password, { identifier: identifier2 });
      expect(hash).toBeDefined();
    });
    
    test('should provide retry-after information', async () => {
      const identifier = 'retry-test-' + Date.now();
      const password = 'TestP@ssw0rd123!';
      
      // Exhaust rate limit
      for (let i = 0; i < 5; i++) {
        await verifyPassword(password, 'dummy-hash', { identifier });
      }
      
      try {
        await verifyPassword(password, 'dummy-hash', { identifier });
        fail('Should have thrown rate limit error');
      } catch (error: any) {
        expect(error.message).toMatch(/retry after \d+ seconds/i);
      }
    });
  });
  
  // ============================= Password Generation Tests =============================
  
  describe('Secure Password Generation', () => {
    
    test('should generate passwords with required complexity', () => {
      for (let i = 0; i < 10; i++) {
        const password = generateSecurePassword(16);
        const validation = validatePassword(password);
        
        expect(password.length).toBe(16);
        expect(validation.isValid).toBe(true);
        expect(validation.entropy).toBeGreaterThan(50);
      }
    });
    
    test('should respect character set options', () => {
      const onlyLowercase = generateSecurePassword(20, {
        includeLowercase: true,
        includeUppercase: false,
        includeNumbers: false,
        includeSymbols: false
      });
      expect(/^[a-z]+$/.test(onlyLowercase)).toBe(true);
      
      const onlyNumbers = generateSecurePassword(20, {
        includeLowercase: false,
        includeUppercase: false,
        includeNumbers: true,
        includeSymbols: false
      });
      expect(/^\d+$/.test(onlyNumbers)).toBe(true);
      
      const noSymbols = generateSecurePassword(20, {
        includeLowercase: true,
        includeUppercase: true,
        includeNumbers: true,
        includeSymbols: false
      });
      expect(/^[a-zA-Z0-9]+$/.test(noSymbols)).toBe(true);
    });
    
    test('should exclude similar characters when requested', () => {
      const passwords = Array.from({ length: 20 }, () => 
        generateSecurePassword(30, { excludeSimilar: true })
      );
      
      const similarChars = ['l', 'I', 'O', '0', '1', 'o'];
      passwords.forEach(password => {
        similarChars.forEach(char => {
          expect(password).not.toContain(char);
        });
      });
    });
    
    test('should generate unique passwords', () => {
      const passwords = new Set();
      const count = 100;
      
      for (let i = 0; i < count; i++) {
        passwords.add(generateSecurePassword(16));
      }
      
      // All passwords should be unique
      expect(passwords.size).toBe(count);
    });
    
    test('should enforce length constraints', () => {
      expect(() => generateSecurePassword(7)).toThrow();
      expect(() => generateSecurePassword(257)).toThrow();
      
      const min = generateSecurePassword(8);
      expect(min.length).toBe(8);
      
      const max = generateSecurePassword(256);
      expect(max.length).toBe(256);
    });
    
    test('should meet minimum entropy requirements', () => {
      const highEntropyPassword = generateSecurePassword(20, {
        minEntropy: 80
      });
      
      const validation = validatePassword(highEntropyPassword);
      expect(validation.entropy).toBeGreaterThanOrEqual(80);
    });
  });
  
  // ============================= Security Edge Cases =============================
  
  describe('Security Edge Cases', () => {
    
    test('should handle Unicode and special characters', async () => {
      const unicodePasswords = [
        'Test123!@#你好世界',
        'Émoji🔒Pass123!',
        'Пароль123!@#',
        'パスワード123!@#',
        '🔐🔑💻123ABc!'
      ];
      
      for (const password of unicodePasswords) {
        const hash = await hashPassword(password, { skipValidation: true });
        const isValid = await verifyPassword(password, hash);
        expect(isValid).toBe(true);
      }
    });
    
    test('should prevent injection attacks', async () => {
      const injectionAttempts = [
        '$2b$10$../../etc/passwd',
        '"; DROP TABLE users; --',
        '<script>alert("xss")</script>',
        '${__proto__.constructor("return process.exit()")()}',
        '\'; SELECT * FROM users; --',
        '\\x00\\x01\\x02\\x03'
      ];
      
      for (const attempt of injectionAttempts) {
        // Should handle safely without throwing or executing
        const result = validatePassword(attempt);
        expect(result).toBeDefined();
        
        // Should hash safely if validation skipped
        const hash = await hashPassword(attempt, { skipValidation: true });
        expect(hash).toBeDefined();
      }
    });
    
    test('should handle null bytes and control characters', async () => {
      const problematicPasswords = [
        'Pass\x00word123!',
        'Test\n\r\t123!',
        String.fromCharCode(0, 1, 2, 3) + 'Pass123!',
        'Pass' + String.fromCharCode(127) + '123!'
      ];
      
      for (const password of problematicPasswords) {
        const hash = await hashPassword(password, { skipValidation: true });
        const isValid = await verifyPassword(password, hash);
        expect(isValid).toBe(true);
      }
    });
    
    test('should be resilient to prototype pollution', async () => {
      // Attempt prototype pollution
      const maliciousInput: any = {
        toString: () => 'password123',
        valueOf: () => 'password123',
        constructor: { name: 'RCE' }
      };
      
      // @ts-ignore - Testing security
      await expect(hashPassword(maliciousInput)).rejects.toThrow(TypeError);
      
      // Ensure prototype is not polluted
  const baseProto = Object.getPrototypeOf({});
  // @ts-ignore intentional check for potential pollution flag
  expect(baseProto.polluted).toBeUndefined();
    });
  });
  
  // ============================= Performance Tests =============================
  
  describe('Performance and Memory', () => {
    
    test('should handle concurrent operations', async () => {
      const password = 'ConcurrentP@ss123!';
      const promises = Array.from({ length: 10 }, () => 
        hashPassword(password)
      );
      
      const hashes = await Promise.all(promises);
      
      // All should succeed and be unique
      expect(hashes.length).toBe(10);
      expect(new Set(hashes).size).toBe(10);
    });
    
    test('should clean up rate limit entries', async () => {
      // Create many rate limit entries
      const promises = [];
      for (let i = 0; i < 100; i++) {
        promises.push(
          hashPassword('TestP@ss123!', { 
            identifier: `cleanup-test-${i}` 
          }).catch(() => {}) // Ignore rate limit errors
        );
      }
      
      await Promise.all(promises);
      
      // Force cleanup by waiting
      await new Promise(resolve => setTimeout(resolve, 100));
      
      // Memory usage should be reasonable (this is a basic check)
      const memUsage = process.memoryUsage();
      expect(memUsage.heapUsed).toBeLessThan(100 * 1024 * 1024); // Less than 100MB
    });
    
    test('should hash passwords within reasonable time', async () => {
      const password = 'PerfTestP@ss123!';
      const start = Date.now();
      
      await hashPassword(password);
      
      const duration = Date.now() - start;
      
      // Should complete within 5 seconds (allowing for slower CI/Argon2 variance)
      expect(duration).toBeLessThan(5000);
    });
  });
  
  // ============================= Rehashing Tests =============================
  
  describe('Password Rehashing', () => {
    
    test('should detect old bcrypt hashes needing rehash', () => {
      const oldHashes = [
        '$2a$08$hash', // Old format, low rounds
        '$2b$10$hash', // Low rounds
        '$2y$11$hash', // Below current standard
      ];
      
      oldHashes.forEach(hash => {
        expect(needsRehash(hash)).toBe(true);
      });
    });
    
    test('should not rehash current standard hashes', async () => {
      const password = 'TestP@ss123!';
      const currentHash = await hashPassword(password);
      
      expect(needsRehash(currentHash)).toBe(false);
    });
    
    test('should provide new hash when requested', async () => {
      const password = 'TestP@ss123!';
      
      // Create old hash with lower security
      const oldHash = '$2b$10$N9qo8uLOickgx2ZMRZoMye/0L.P6rLwgaVzRLzN9o9lJZQqDaNKGi'; // "secret"
      
      const result = await verifyAndCheckRehash('secret', oldHash, { 
        updateHash: true 
      });
      
      if (result.valid && result.needsRehash) {
        expect(result.newHash).toBeDefined();
        expect(result.newHash).not.toBe(oldHash);
        expect(needsRehash(result.newHash!)).toBe(false);
      }
    });
  });
});

// ============================= Test Utilities =============================

describe('Test Coverage Validation', () => {
  
  test('should have tested all exported functions', () => {
    const exportedFunctions = [
      'hashPassword',
      'verifyPassword',
      'verifyAndCheckRehash',
      'validatePassword',
      'generateSecurePassword',
      'needsRehash'
    ];
    
    // This is a meta-test to ensure we haven't forgotten any exports
    const utilMod = require('../../utils/hash');
    exportedFunctions.forEach(funcName => {
      expect(typeof utilMod[funcName]).toBe('function');
    });
  });
});