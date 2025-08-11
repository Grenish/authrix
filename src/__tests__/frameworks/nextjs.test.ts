import { describe, it, expect, beforeEach } from '@jest/globals';
import { getNextJsEnvironmentInfo, redetectNextJsEnvironment } from '../../frameworks/nextjs';

describe('Next.js Framework Detection', () => {
  beforeEach(() => {
    // Reset environment for each test
    redetectNextJsEnvironment();
  });

  describe('getNextJsEnvironmentInfo', () => {
    it('should return environment information object', () => {
      const info = getNextJsEnvironmentInfo();
      
      expect(info).toBeDefined();
      expect(typeof info).toBe('object');
      expect(info).toHaveProperty('isNextJsAvailable');
      expect(info).toHaveProperty('context');
      expect(info).toHaveProperty('hasAppRouterSupport');
      expect(info).toHaveProperty('hasPagesRouterSupport');
      expect(info).toHaveProperty('hasMiddlewareSupport');
      expect(info).toHaveProperty('detectionComplete');
      expect(info).toHaveProperty('runtimeInfo');
    });

    it('should have boolean values for availability flags', () => {
      const info = getNextJsEnvironmentInfo();
      
      expect(typeof info.isNextJsAvailable).toBe('boolean');
      expect(typeof info.hasAppRouterSupport).toBe('boolean');
      expect(typeof info.hasPagesRouterSupport).toBe('boolean');
      expect(typeof info.hasMiddlewareSupport).toBe('boolean');
      expect(typeof info.detectionComplete).toBe('boolean');
    });

    it('should have valid context value', () => {
      const info = getNextJsEnvironmentInfo();
      const validContexts = ['app-router', 'pages-router', 'middleware', 'unknown'];
      
      expect(validContexts).toContain(info.context);
    });

    it('should include runtime information', () => {
      const info = getNextJsEnvironmentInfo();
      
      expect(info.runtimeInfo).toBeDefined();
      expect(typeof info.runtimeInfo.hasRequire).toBe('boolean');
      expect(typeof info.runtimeInfo.hasGlobalThis).toBe('boolean');
      expect(typeof info.runtimeInfo.hasProcess).toBe('boolean');
      expect(typeof info.runtimeInfo.hasNextData).toBe('boolean');
    });

    it('should detect Node.js environment correctly', () => {
      const info = getNextJsEnvironmentInfo();
      
      // In Jest test environment, these should be true
      expect(info.runtimeInfo.hasGlobalThis).toBe(true);
      expect(info.runtimeInfo.hasProcess).toBe(true);
      expect(info.runtimeInfo.hasRequire).toBe(true);
    });
  });

  describe('redetectNextJsEnvironment', () => {
    it('should return environment information after redetection', () => {
      const info = redetectNextJsEnvironment();
      
      expect(info).toBeDefined();
      expect(typeof info).toBe('object');
      expect(info.detectionComplete).toBe(true);
    });

    it('should be able to run multiple times', () => {
      const info1 = redetectNextJsEnvironment();
      const info2 = redetectNextJsEnvironment();
      
      expect(info1).toBeDefined();
      expect(info2).toBeDefined();
      expect(info1.detectionComplete).toBe(true);
      expect(info2.detectionComplete).toBe(true);
    });

    it('should maintain consistent results', () => {
      const info1 = getNextJsEnvironmentInfo();
      const info2 = redetectNextJsEnvironment();
      const info3 = getNextJsEnvironmentInfo();
      
      // Basic properties should remain consistent
      expect(info1.runtimeInfo.hasProcess).toBe(info2.runtimeInfo.hasProcess);
      expect(info2.runtimeInfo.hasProcess).toBe(info3.runtimeInfo.hasProcess);
      expect(info1.runtimeInfo.hasRequire).toBe(info2.runtimeInfo.hasRequire);
      expect(info2.runtimeInfo.hasRequire).toBe(info3.runtimeInfo.hasRequire);
    });
  });

  describe('Detection Logic', () => {
    it('should detect test environment consistently', () => {
      const info = getNextJsEnvironmentInfo();
      
      // In test environment, Next.js should not be available unless specifically installed
      expect(info.isNextJsAvailable).toBe(false);
      // Context can vary based on require availability; ensure it's one of valid contexts
      expect(['unknown','pages-router','middleware','app-router']).toContain(info.context);
    });

    it('should handle missing Next.js gracefully', () => {
      // This test verifies that detection doesn't throw errors when Next.js is not available
      expect(() => {
        getNextJsEnvironmentInfo();
      }).not.toThrow();
      
      expect(() => {
        redetectNextJsEnvironment();
      }).not.toThrow();
    });

    it('should complete detection process', () => {
      const info = getNextJsEnvironmentInfo();
      
      expect(info.detectionComplete).toBe(true);
    });
  });

  describe('Environment Variables', () => {
    it('should handle missing NEXT_RUNTIME gracefully', () => {
      // Ensure no Next.js specific environment variables are set
      delete process.env.NEXT_RUNTIME;
      delete process.env.NEXT_PUBLIC_VERCEL_URL;
      
      const info = redetectNextJsEnvironment();
      
      expect(info.runtimeInfo.nextRuntime).toBeUndefined();
    });

    it('should detect NEXT_RUNTIME when present', () => {
      process.env.NEXT_RUNTIME = 'nodejs';
      
      const info = redetectNextJsEnvironment();
      
      expect(info.runtimeInfo.nextRuntime).toBe('nodejs');
      
      // Clean up
      delete process.env.NEXT_RUNTIME;
    });
  });
});
