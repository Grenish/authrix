import { authMiddleware, type AuthenticatedRequest } from '../../middleware/authMiddleware';
import type { Response, NextFunction } from 'express';

// Mock dependencies
jest.mock('../../config', () => ({
  authConfig: {
    cookieName: 'auth-token',
    db: {
      findUserById: jest.fn()
    },
    jwtSecret: 'test-jwt-secret-123'
  }
}));

jest.mock('../../tokens/verifyToken', () => ({
  verifyToken: jest.fn()
}));

jest.mock('../../utils/errors', () => ({
  UnauthorizedError: class extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'UnauthorizedError';
    }
  },
  InternalServerError: class extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'InternalServerError';
    }
  }
}));

import { authConfig } from '../../config';
import { verifyToken } from '../../tokens/verifyToken';
import { createToken } from '../../tokens/createToken';

const mockVerifyToken = verifyToken as jest.MockedFunction<typeof verifyToken>;

// Type assertion to avoid null checks
const mockDb = authConfig.db! as jest.Mocked<NonNullable<typeof authConfig.db>>;

describe('Auth Middleware', () => {
  let mockReq: Partial<AuthenticatedRequest>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockReq = {
      cookies: {}
    };
    
    mockRes = {
      clearCookie: jest.fn()
    };
    
    mockNext = jest.fn();
  });

  describe('authMiddleware', () => {
    it('should authenticate user with valid token', async () => {
      const mockUser = {
        id: '1',
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: new Date('2023-01-01')
      };

      mockReq.cookies = { 'auth-token': 'valid-token' };
      mockVerifyToken.mockReturnValueOnce({ id: '1', email: 'test@example.com' });
      mockDb.findUserById.mockResolvedValueOnce(mockUser);

      await authMiddleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext
      );

      expect(mockVerifyToken).toHaveBeenCalledWith('valid-token');
      expect(mockDb.findUserById).toHaveBeenCalledWith('1');
      expect(mockReq.user).toEqual({
        id: '1',
        email: 'test@example.com',
        createdAt: new Date('2023-01-01')
      });
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should handle missing token', async () => {
      mockReq.cookies = {};

      await authMiddleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalledWith(
        expect.any(Error)
      );
      const calledError = (mockNext as jest.Mock).mock.calls[0][0];
  // Just assert an auth failure occurred
  expect(calledError.message.toLowerCase()).toMatch(/invalid|expired/);
      expect(calledError.message).toBe('Authentication token is missing.');
    });

    it('should handle invalid token', async () => {
      mockReq.cookies = { 'auth-token': 'invalid-token' };
      mockVerifyToken.mockImplementationOnce(() => {
        throw new Error('Invalid token');
      });

      await authMiddleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalledWith(
        expect.any(Error)
      );
    });

    it('should fail fast on tampered token (signature mismatch)', async () => {
      // Simulate tampered token by making verify throw JsonWebTokenError equivalent
      mockReq.cookies = { 'auth-token': 'tampered-token' };
      mockVerifyToken.mockImplementationOnce(() => { throw new Error('Invalid token'); });

      await authMiddleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext
      );

      const calledError = (mockNext as jest.Mock).mock.calls[ (mockNext as jest.Mock).mock.calls.length -1][0];
      expect(calledError).toBeInstanceOf(Error);
      expect(calledError.name).toBe('UnauthorizedError');
    });

    it('should handle user not found', async () => {
      mockReq.cookies = { 'auth-token': 'valid-token' };
      mockVerifyToken.mockReturnValueOnce({ id: '1', email: 'test@example.com' });
      mockDb.findUserById.mockResolvedValueOnce(null);

      await authMiddleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext
      );

      expect(mockRes.clearCookie).toHaveBeenCalledWith('auth-token');
      expect(mockNext).toHaveBeenCalledWith(
        expect.any(Error)
      );
      const calledError = (mockNext as jest.Mock).mock.calls[0][0];
      expect(calledError.name).toBe('UnauthorizedError');
      expect(calledError.message).toBe('User not found or token is invalid.');
    });

    it('should handle database not configured', async () => {
      // Temporarily remove db
      const originalDb = authConfig.db;
      (authConfig as any).db = null;

      mockReq.cookies = { 'auth-token': 'valid-token' };
      mockVerifyToken.mockReturnValueOnce({ id: '1', email: 'test@example.com' });

      await authMiddleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalledWith(
        expect.any(Error)
      );
      const calledError = (mockNext as jest.Mock).mock.calls[0][0];
      expect(calledError.name).toBe('InternalServerError');
      expect(calledError.message).toBe('Database not configured.');

      // Restore db
      (authConfig as any).db = originalDb;
    });

    it('should handle database errors', async () => {
      mockReq.cookies = { 'auth-token': 'valid-token' };
      mockVerifyToken.mockReturnValueOnce({ id: '1', email: 'test@example.com' });
      mockDb.findUserById.mockRejectedValueOnce(new Error('Database connection failed'));

      await authMiddleware(
        mockReq as AuthenticatedRequest,
        mockRes as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalledWith(
        expect.any(Error)
      );
      const calledError = (mockNext as jest.Mock).mock.calls[0][0];
      expect(calledError.message).toBe('Database connection failed');
    });
  });
});
