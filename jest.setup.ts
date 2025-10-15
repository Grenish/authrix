// Jest setup file
import { jest } from '@jest/globals';

// Global test configuration
jest.setTimeout(10000);

// Mock console.warn for tests to avoid noise
const originalWarn = console.warn;
beforeEach(() => {
  console.warn = jest.fn();
});

afterEach(() => {
  console.warn = originalWarn;
});

// Setup test environment variables
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret-key-for-testing-purposes-only';

// Ensure a stable pepper for all tests to avoid runtime switching
if (!process.env.AUTHRIX_PASSWORD_PEPPER) {
  // 64-hex test-only pepper (do not use in production)
  process.env.AUTHRIX_PASSWORD_PEPPER = '7e3f2b9c1a4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7';
}

// Initialize authConfig for tests
import { authConfig } from './src/config';
authConfig.jwtSecret = process.env.JWT_SECRET!;
