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

// Initialize authConfig for tests
import { authConfig } from './src/config';
authConfig.jwtSecret = process.env.JWT_SECRET!;
