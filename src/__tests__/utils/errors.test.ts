import { describe, it, expect } from '@jest/globals';
import { 
  AuthrixError, 
  BadRequestError, 
  UnauthorizedError, 
  ForbiddenError, 
  NotFoundError 
} from '../../utils/errors';

describe('Error Utilities', () => {
  describe('AuthrixError', () => {
    it('should create AuthrixError with message and status code', () => {
      const message = 'Test error';
      const statusCode = 500;
      const error = new AuthrixError(message, statusCode);
      
      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(AuthrixError);
      expect(error.message).toBe(message);
      expect(error.statusCode).toBe(statusCode);
      expect(error.name).toBe('AuthrixError');
    });

    it('should be throwable', () => {
      expect(() => {
        throw new AuthrixError('Test error', 500);
      }).toThrow('Test error');
    });

    it('should have proper prototype chain', () => {
      const error = new AuthrixError('Test error', 500);
      
      expect(error instanceof Error).toBe(true);
      expect(error instanceof AuthrixError).toBe(true);
    });
  });

  describe('BadRequestError', () => {
    it('should create BadRequestError with default message', () => {
      const error = new BadRequestError();
      
      expect(error).toBeInstanceOf(AuthrixError);
      expect(error).toBeInstanceOf(BadRequestError);
      expect(error.message).toBe('Bad Request');
      expect(error.statusCode).toBe(400);
      expect(error.name).toBe('BadRequestError');
    });

    it('should create BadRequestError with custom message', () => {
      const customMessage = 'Custom bad request message';
      const error = new BadRequestError(customMessage);
      
      expect(error.message).toBe(customMessage);
      expect(error.statusCode).toBe(400);
    });
  });

  describe('UnauthorizedError', () => {
    it('should create UnauthorizedError with default message', () => {
      const error = new UnauthorizedError();
      
      expect(error).toBeInstanceOf(AuthrixError);
      expect(error).toBeInstanceOf(UnauthorizedError);
      expect(error.message).toBe('Authentication required');
      expect(error.statusCode).toBe(401);
      expect(error.name).toBe('UnauthorizedError');
    });

    it('should create UnauthorizedError with custom message', () => {
      const customMessage = 'Invalid credentials';
      const error = new UnauthorizedError(customMessage);
      
      expect(error.message).toBe(customMessage);
      expect(error.statusCode).toBe(401);
    });
  });

  describe('ForbiddenError', () => {
    it('should create ForbiddenError with default message', () => {
      const error = new ForbiddenError();
      
      expect(error).toBeInstanceOf(AuthrixError);
      expect(error).toBeInstanceOf(ForbiddenError);
      expect(error.message).toBe('Forbidden');
      expect(error.statusCode).toBe(403);
      expect(error.name).toBe('ForbiddenError');
    });

    it('should create ForbiddenError with custom message', () => {
      const customMessage = 'Access denied';
      const error = new ForbiddenError(customMessage);
      
      expect(error.message).toBe(customMessage);
      expect(error.statusCode).toBe(403);
    });
  });

  describe('NotFoundError', () => {
    it('should create NotFoundError with default message', () => {
      const error = new NotFoundError();
      
      expect(error).toBeInstanceOf(AuthrixError);
      expect(error).toBeInstanceOf(NotFoundError);
      expect(error.statusCode).toBe(404);
      expect(error.name).toBe('NotFoundError');
    });

    it('should create NotFoundError with custom message', () => {
      const customMessage = 'Resource not found';
      const error = new NotFoundError(customMessage);
      
      expect(error.message).toBe(customMessage);
      expect(error.statusCode).toBe(404);
    });
  });

  describe('Error Hierarchy', () => {
    it('should all extend AuthrixError', () => {
      const badRequestError = new BadRequestError();
      const unauthorizedError = new UnauthorizedError();
      const forbiddenError = new ForbiddenError();
      const notFoundError = new NotFoundError();
      
      expect(badRequestError).toBeInstanceOf(AuthrixError);
      expect(unauthorizedError).toBeInstanceOf(AuthrixError);
      expect(forbiddenError).toBeInstanceOf(AuthrixError);
      expect(notFoundError).toBeInstanceOf(AuthrixError);
    });

    it('should all extend base Error', () => {
      const authrixError = new AuthrixError('Test', 500);
      const badRequestError = new BadRequestError();
      const unauthorizedError = new UnauthorizedError();
      
      expect(authrixError).toBeInstanceOf(Error);
      expect(badRequestError).toBeInstanceOf(Error);
      expect(unauthorizedError).toBeInstanceOf(Error);
    });

    it('should have correct status codes', () => {
      expect(new BadRequestError().statusCode).toBe(400);
      expect(new UnauthorizedError().statusCode).toBe(401);
      expect(new ForbiddenError().statusCode).toBe(403);
      expect(new NotFoundError().statusCode).toBe(404);
    });
  });

  describe('Error Catching', () => {
    it('should be catchable as specific error types', () => {
      try {
        throw new UnauthorizedError('Custom auth error');
      } catch (error) {
        expect(error).toBeInstanceOf(UnauthorizedError);
        expect(error).toBeInstanceOf(AuthrixError);
        expect((error as UnauthorizedError).statusCode).toBe(401);
        expect((error as UnauthorizedError).message).toBe('Custom auth error');
      }
    });

    it('should preserve stack trace', () => {
      const error = new AuthrixError('Test error', 500);
      
      expect(error.stack).toBeDefined();
      expect(error.stack).toContain('AuthrixError');
    });
  });
});
