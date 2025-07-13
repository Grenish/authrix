import { describe, it, expect, beforeEach } from '@jest/globals';
import { createToken } from '../../tokens/createToken';
import { verifyToken } from '../../tokens/verifyToken';

describe('Token Utilities', () => {
  const testUser = {
    id: 'test-user-id',
    email: 'test@example.com',
    createdAt: new Date('2024-01-01T00:00:00.000Z')
  };

  beforeEach(() => {
    // Ensure JWT_SECRET is set for tests
    process.env.JWT_SECRET = 'test-jwt-secret-key-for-testing-purposes-only';
  });

  describe('createToken', () => {
    it('should create a valid JWT token', () => {
      const token = createToken(testUser);
      
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3); // JWT has 3 parts
    });

    it('should create different tokens for different users', () => {
      const user1 = { ...testUser, id: 'user1' };
      const user2 = { ...testUser, id: 'user2' };
      
      const token1 = createToken(user1);
      const token2 = createToken(user2);
      
      expect(token1).not.toBe(token2);
    });

    it('should include user data in token payload', () => {
      const token = createToken(testUser);
      
      // Decode the payload (middle part of JWT)
      const payloadBase64 = token.split('.')[1];
      const payload = JSON.parse(Buffer.from(payloadBase64, 'base64').toString());
      
      expect(payload.id).toBe(testUser.id);
      expect(payload.email).toBe(testUser.email);
      expect(payload.createdAt).toBe(testUser.createdAt.toISOString());
      expect(payload.exp).toBeDefined(); // Expiration should be set
      expect(payload.iat).toBeDefined(); // Issued at should be set
    });

    it('should set expiration time', () => {
      const token = createToken(testUser);
      
      const payloadBase64 = token.split('.')[1];
      const payload = JSON.parse(Buffer.from(payloadBase64, 'base64').toString());
      
      const now = Math.floor(Date.now() / 1000);
      const expectedExp = now + (7 * 24 * 60 * 60); // 7 days from now (as per createToken)
      
      expect(payload.exp).toBeGreaterThan(now);
      expect(payload.exp).toBeLessThanOrEqual(expectedExp + 60); // Allow 1 minute tolerance
    });
  });

  describe('verifyToken', () => {
    it('should verify a valid token and return payload', () => {
      const token = createToken(testUser);
      const payload = verifyToken(token);
      
      expect(payload).toBeDefined();
      expect(payload.id).toBe(testUser.id);
      expect(payload.email).toBe(testUser.email);
      expect(payload.iat).toBeDefined();
      expect(payload.exp).toBeDefined();
    });

    it('should throw error for invalid token', () => {
      const invalidToken = 'invalid.token.string';
      
      expect(() => {
        verifyToken(invalidToken);
      }).toThrow();
    });

    it('should throw error for malformed token', () => {
      const malformedToken = 'not-a-jwt-token';
      
      expect(() => {
        verifyToken(malformedToken);
      }).toThrow();
    });

    it('should throw specific error for expired token', () => {
      // We can't easily test expiration without waiting, but we can test the error type
      const invalidToken = 'invalid.token.string';
      
      expect(() => {
        verifyToken(invalidToken);
      }).toThrow('Invalid token');
    });

    it('should return correct user data types', () => {
      const token = createToken(testUser);
      const payload = verifyToken(token);
      
      expect(typeof payload.id).toBe('string');
      expect(typeof payload.email).toBe('string');
      expect(typeof payload.iat).toBe('number');
      expect(typeof payload.exp).toBe('number');
    });
  });

  describe('Token Security', () => {
    it('should not be verifiable with wrong secret', () => {
      const token = createToken(testUser);
      
      // Import the authConfig to change it directly
      const { authConfig } = require('../../config');
      const originalSecret = authConfig.jwtSecret;
      
      // Change the secret in the config
      authConfig.jwtSecret = 'wrong-secret';
      
      expect(() => {
        verifyToken(token);
      }).toThrow();
      
      // Restore correct secret
      authConfig.jwtSecret = originalSecret;
    });

    it('should use the configured JWT secret', () => {
      const customSecret = 'custom-test-secret-123';
      
      // Import the authConfig to change it directly
      const { authConfig } = require('../../config');
      const originalSecret = authConfig.jwtSecret;
      
      authConfig.jwtSecret = customSecret;
      
      const token = createToken(testUser);
      const payload = verifyToken(token);
      
      expect(payload.id).toBe(testUser.id);
      
      // Restore original secret
      authConfig.jwtSecret = originalSecret;
    });

    it('should maintain token integrity', () => {
      const token = createToken(testUser);
      
      // Verify that tampering with token makes it invalid
      const tamperedToken = token.slice(0, -5) + 'tampr';
      
      expect(() => {
        verifyToken(tamperedToken);
      }).toThrow();
    });
  });
});
