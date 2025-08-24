import { 
  createAuthMiddleware, 
  authMiddleware as expressAuthMiddleware,
  optionalAuthMiddleware,
} from '../../middleware/flexibleAuth';
import type { Response, NextFunction } from 'express';

// Mock dependencies
jest.mock('../../frameworks/universal', () => ({
  validateAuth: jest.fn(),
}));

jest.mock('../../config', () => ({
  authConfig: {
    cookieName: 'auth-token',
    jwtSecret: 'test-jwt-secret-123'
  }
}));

import { validateAuth } from '../../frameworks/universal';

const mockValidateAuth = validateAuth as jest.MockedFunction<typeof validateAuth>;
// No-op placeholders for removed helpers

describe('Flexible Auth Middleware', () => {
  let mockReq: any;
  let mockRes: any;
  let mockNext: NextFunction;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockReq = {
      cookies: {},
      headers: {}
    };
    
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    
    mockNext = jest.fn();
  });

  describe('createAuthMiddleware', () => {
    it('should authenticate user with valid token from cookies', async () => {
      const authResult = {
        isValid: true,
        user: { id: '1', email: 'test@example.com', createdAt: new Date() },
        error: null
      };

      mockReq.cookies = { 'auth-token': 'valid-token' };
      mockValidateAuth.mockResolvedValueOnce(authResult);

      const middleware = createAuthMiddleware();
      await middleware(mockReq, mockRes, mockNext);

      expect(mockValidateAuth).toHaveBeenCalledWith('valid-token');
      expect(mockReq.auth).toEqual(authResult);
      expect(mockReq.user).toEqual(authResult.user);
      expect(mockReq.isAuthenticated).toBe(true);
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should authenticate user with token from Authorization header', async () => {
      const authResult = {
        isValid: true,
        user: { id: '1', email: 'test@example.com', createdAt: new Date() },
        error: null
      };

      mockReq.headers = { authorization: 'Bearer valid-token' };
      mockValidateAuth.mockResolvedValueOnce(authResult);

      const middleware = createAuthMiddleware();
      await middleware(mockReq, mockRes, mockNext);

      expect(mockValidateAuth).toHaveBeenCalledWith('valid-token');
      expect(mockReq.isAuthenticated).toBe(true);
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should extract token from cookie header when cookies not parsed', async () => {
      const authResult = {
        isValid: true,
        user: { id: '1', email: 'test@example.com', createdAt: new Date() },
        error: null
      };

      mockReq.headers = { cookie: 'auth-token=valid-token; other=value' };
      mockValidateAuth.mockResolvedValueOnce(authResult);

      const middleware = createAuthMiddleware();
      await middleware(mockReq, mockRes, mockNext);

      expect(mockValidateAuth).toHaveBeenCalledWith('valid-token');
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should handle invalid authentication when required', async () => {
      const authResult = {
        isValid: false,
        user: null,
        error: 'Invalid token'
      };

      mockReq.cookies = { 'auth-token': 'invalid-token' };
      mockValidateAuth.mockResolvedValueOnce(authResult);

      const middleware = createAuthMiddleware({ required: true });
      await middleware(mockReq, mockRes, mockNext);

      expect(mockReq.isAuthenticated).toBe(false);
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        error: { message: 'Invalid token' }
      });
    });

    it('should handle invalid authentication when optional', async () => {
      const authResult = {
        isValid: false,
        user: null,
        error: 'Invalid token'
      };

      mockReq.cookies = { 'auth-token': 'invalid-token' };
      mockValidateAuth.mockResolvedValueOnce(authResult);

      const middleware = createAuthMiddleware({ required: false });
      await middleware(mockReq, mockRes, mockNext);

      expect(mockReq.isAuthenticated).toBe(false);
      expect(mockNext).toHaveBeenCalledWith();
      expect(mockRes.status).not.toHaveBeenCalled();
    });

    it('should use custom token extractor', async () => {
      const authResult = {
        isValid: true,
        user: { id: '1', email: 'test@example.com', createdAt: new Date() },
        error: null
      };

      const customTokenExtractor = jest.fn().mockReturnValue('custom-token');
      mockValidateAuth.mockResolvedValueOnce(authResult);

      const middleware = createAuthMiddleware({ 
        tokenExtractor: customTokenExtractor 
      });
      await middleware(mockReq, mockRes, mockNext);

      expect(customTokenExtractor).toHaveBeenCalledWith(mockReq);
      expect(mockValidateAuth).toHaveBeenCalledWith('custom-token');
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should use custom error handler', async () => {
      const authResult = {
        isValid: false,
        user: null,
        error: 'Authentication failed'
      };

      const customErrorHandler = jest.fn();
      mockValidateAuth.mockResolvedValueOnce(authResult);

      const middleware = createAuthMiddleware({ 
        required: true,
        errorHandler: customErrorHandler 
      });
      await middleware(mockReq, mockRes, mockNext);

      expect(customErrorHandler).toHaveBeenCalledWith(
        expect.any(Error),
        mockReq,
        mockRes,
        mockNext
      );
    });

    it('should handle middleware errors', async () => {
      mockValidateAuth.mockRejectedValueOnce(new Error('Validation error'));

      const middleware = createAuthMiddleware();
      await middleware(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        error: { message: 'Validation error' }
      });
    });

    it('should handle no token gracefully', async () => {
      const authResult = {
        isValid: false,
        user: null,
        error: 'No token provided'
      };

      mockValidateAuth.mockResolvedValueOnce(authResult);

      const middleware = createAuthMiddleware({ required: false });
      await middleware(mockReq, mockRes, mockNext);

      expect(mockReq.isAuthenticated).toBe(false);
      expect(mockNext).toHaveBeenCalledWith();
    });
  });

  describe('Express.js specific middlewares', () => {
    it('should work as Express middleware (required auth)', async () => {
      const authResult = {
        isValid: true,
        user: { id: '1', email: 'test@example.com', createdAt: new Date() },
        error: null
      };

      mockReq.cookies = { 'auth-token': 'valid-token' };
      mockValidateAuth.mockResolvedValueOnce(authResult);

  expressAuthMiddleware(mockReq as any, mockRes as Response, mockNext);

      // Wait for async operation
      await new Promise(resolve => setTimeout(resolve, 0));

      expect(mockReq.isAuthenticated).toBe(true);
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should work as optional Express middleware', async () => {
      const authResult = {
        isValid: false,
        user: null,
        error: 'No token provided'
      };

      mockValidateAuth.mockResolvedValueOnce(authResult);

  optionalAuthMiddleware(mockReq as any, mockRes as Response, mockNext);

      // Wait for async operation
      await new Promise(resolve => setTimeout(resolve, 0));

      expect(mockReq.isAuthenticated).toBe(false);
      expect(mockNext).toHaveBeenCalledWith();
    });
  });

  describe('token extraction priority', () => {
    it('should prioritize cookies over headers', async () => {
      const authResult = {
        isValid: true,
        user: { id: '1', email: 'test@example.com', createdAt: new Date() },
        error: null
      };

      mockReq.cookies = { 'auth-token': 'cookie-token' };
      mockReq.headers = { authorization: 'Bearer header-token' };
      mockValidateAuth.mockResolvedValueOnce(authResult);

      const middleware = createAuthMiddleware();
      await middleware(mockReq, mockRes, mockNext);

      expect(mockValidateAuth).toHaveBeenCalledWith('cookie-token');
    });

    it('should fall back to Authorization header when no cookies', async () => {
      const authResult = {
        isValid: true,
        user: { id: '1', email: 'test@example.com', createdAt: new Date() },
        error: null
      };

      mockReq.headers = { authorization: 'Bearer header-token' };
      mockValidateAuth.mockResolvedValueOnce(authResult);

      const middleware = createAuthMiddleware();
      await middleware(mockReq, mockRes, mockNext);

      expect(mockValidateAuth).toHaveBeenCalledWith('header-token');
    });
  });
});
