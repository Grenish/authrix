import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { postgresqlAdapter, resetPostgreSQLConnection } from '../../adapters/postgresql';

// Mock pg module
const mockPool = {
  query: jest.fn(),
  on: jest.fn(),
  end: jest.fn(),
};

const mockPg = {
  Pool: jest.fn().mockReturnValue(mockPool),
};

// Mock the dynamic import
const mockEval = jest.fn().mockResolvedValue(mockPg);
global.eval = mockEval as any;

describe('PostgreSQL Adapter', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    resetPostgreSQLConnection();
    
    // Set up environment variables
    process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/testdb';
  });

  afterEach(() => {
    resetPostgreSQLConnection();
    delete process.env.DATABASE_URL;
    delete process.env.POSTGRESQL_HOST;
    delete process.env.POSTGRESQL_DATABASE;
    delete process.env.POSTGRESQL_USER;
    delete process.env.POSTGRESQL_PASSWORD;
  });

  describe('findUserByEmail', () => {
    it('should find user by email successfully', async () => {
      const mockUser = {
        id: '123',
        email: 'test@example.com',
        password: 'hashedpassword',
        created_at: new Date(),
        email_verified: false,
        email_verified_at: null,
        two_factor_enabled: false,
      };

      mockPool.query.mockResolvedValueOnce({
        rows: [mockUser],
      });

      const result = await postgresqlAdapter.findUserByEmail('test@example.com');

      expect(result).toEqual({
        id: '123',
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: mockUser.created_at,
        emailVerified: false,
        emailVerifiedAt: null,
        twoFactorEnabled: false,
      });

      expect(mockPool.query).toHaveBeenCalledWith(
        'SELECT * FROM auth_users WHERE email = $1 LIMIT 1',
        ['test@example.com']
      );
    });

    it('should return null if user not found', async () => {
      mockPool.query.mockResolvedValueOnce({
        rows: [],
      });

      const result = await postgresqlAdapter.findUserByEmail('nonexistent@example.com');

      expect(result).toBeNull();
    });

    it('should handle database errors gracefully', async () => {
      mockPool.query.mockRejectedValueOnce(new Error('Database connection failed'));

      const result = await postgresqlAdapter.findUserByEmail('test@example.com');

      expect(result).toBeNull();
    });
  });

  describe('findUserById', () => {
    it('should find user by ID successfully', async () => {
      const mockUser = {
        id: '123',
        email: 'test@example.com',
        password: 'hashedpassword',
        created_at: new Date(),
        email_verified: true,
        email_verified_at: new Date(),
        two_factor_enabled: false,
      };

      mockPool.query.mockResolvedValueOnce({
        rows: [mockUser],
      });

      const result = await postgresqlAdapter.findUserById('123');

      expect(result).toEqual({
        id: '123',
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: mockUser.created_at,
        emailVerified: true,
        emailVerifiedAt: mockUser.email_verified_at,
        twoFactorEnabled: false,
      });
    });

    it('should return null if user not found', async () => {
      mockPool.query.mockResolvedValueOnce({
        rows: [],
      });

      const result = await postgresqlAdapter.findUserById('nonexistent');

      expect(result).toBeNull();
    });
  });

  describe('createUser', () => {
    it('should create user successfully', async () => {
      const mockUser = {
        id: '123',
        email: 'test@example.com',
        password: 'hashedpassword',
        created_at: new Date(),
        email_verified: false,
        email_verified_at: null,
        two_factor_enabled: false,
      };

      mockPool.query.mockResolvedValueOnce({
        rows: [mockUser],
      });

      const result = await postgresqlAdapter.createUser({
        email: 'Test@Example.com',
        password: 'hashedpassword',
      });

      expect(result).toEqual({
        id: '123',
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: mockUser.created_at,
        emailVerified: false,
        emailVerifiedAt: null,
        twoFactorEnabled: false,
      });

      expect(mockPool.query).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO auth_users (email, password)'),
        ['test@example.com', 'hashedpassword']
      );
    });

    it('should create user with username and name fields', async () => {
      const mockUser = {
        id: '123',
        email: 'test@example.com',
        password: 'hashedpassword',
        username: 'testuser',
        first_name: 'John',
        last_name: 'Doe',
        created_at: new Date(),
        email_verified: false,
        email_verified_at: null,
        two_factor_enabled: false,
      };

      mockPool.query.mockResolvedValueOnce({
        rows: [mockUser],
      });

      const result = await postgresqlAdapter.createUser({
        email: 'test@example.com',
        password: 'hashedpassword',
        username: 'testuser',
        firstName: 'John',
        lastName: 'Doe',
      });

      expect(result).toEqual({
        id: '123',
        email: 'test@example.com',
        password: 'hashedpassword',
        username: 'testuser',
        firstName: 'John',
        lastName: 'Doe',
        createdAt: mockUser.created_at,
        emailVerified: false,
        emailVerifiedAt: null,
        twoFactorEnabled: false,
      });

      expect(mockPool.query).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO auth_users (email, password, username, first_name, last_name)'),
        ['test@example.com', 'hashedpassword', 'testuser', 'John', 'Doe']
      );
    });

    it('should handle duplicate email error', async () => {
      const error = new Error('duplicate key value violates unique constraint email_idx');
      mockPool.query.mockRejectedValueOnce(error);

      await expect(
        postgresqlAdapter.createUser({
          email: 'test@example.com',
          password: 'hashedpassword',
        })
      ).rejects.toThrow('User with email test@example.com already exists');
    });

    it('should handle duplicate username error', async () => {
      const error = new Error('duplicate key value violates unique constraint username_idx');
      mockPool.query.mockRejectedValueOnce(error);

      await expect(
        postgresqlAdapter.createUser({
          email: 'test@example.com',
          password: 'hashedpassword',
          username: 'testuser',
        })
      ).rejects.toThrow('Username testuser is already taken');
    });
  });

  describe('updateUser', () => {
    it('should update user successfully', async () => {
      const mockUser = {
        id: '123',
        email: 'test@example.com',
        password: 'hashedpassword',
        created_at: new Date(),
        email_verified: true,
        email_verified_at: new Date(),
        two_factor_enabled: false,
      };

      mockPool.query.mockResolvedValueOnce({
        rows: [mockUser],
      });

      const result = await postgresqlAdapter.updateUser!('123', {
        emailVerified: true,
        emailVerifiedAt: mockUser.email_verified_at,
      });

      expect(result).toBeDefined();
      expect(result.emailVerified).toBe(true);
    });

    it('should update username, firstName, and lastName successfully', async () => {
      const mockUser = {
        id: '123',
        email: 'test@example.com',
        password: 'hashedpassword',
        username: 'newuser',
        first_name: 'Jane',
        last_name: 'Smith',
        created_at: new Date(),
        email_verified: false,
        email_verified_at: null,
        two_factor_enabled: false,
      };

      mockPool.query.mockResolvedValueOnce({
        rows: [mockUser],
      });

      const result = await postgresqlAdapter.updateUser!('123', {
        username: 'newuser',
        firstName: 'Jane',
        lastName: 'Smith',
      });

      expect(result).toEqual({
        id: '123',
        email: 'test@example.com',
        password: 'hashedpassword',
        username: 'newuser',
        firstName: 'Jane',
        lastName: 'Smith',
        createdAt: mockUser.created_at,
        emailVerified: false,
        emailVerifiedAt: null,
        twoFactorEnabled: false,
      });

      expect(mockPool.query).toHaveBeenCalledWith(
        expect.stringContaining('SET username = $1, first_name = $2, last_name = $3'),
        ['newuser', 'Jane', 'Smith', '123']
      );
    });

    it('should handle duplicate username error on update', async () => {
      const error = new Error('duplicate key value violates unique constraint username_idx');
      mockPool.query.mockRejectedValueOnce(error);

      await expect(
        postgresqlAdapter.updateUser!('123', { username: 'existinguser' })
      ).rejects.toThrow('Username existinguser is already taken');
    });

    it('should throw error if user not found', async () => {
      mockPool.query.mockResolvedValueOnce({
        rows: [],
      });

      await expect(
        postgresqlAdapter.updateUser!('nonexistent', { emailVerified: true })
      ).rejects.toThrow('User not found');
    });
  });

  describe('two factor code operations', () => {
    const mockCode = {
      id: 'code-123',
      userId: 'user-123',
      code: '123456',
      hashedCode: 'hashed-123456',
      type: 'email_verification' as const,
      expiresAt: new Date(),
      createdAt: new Date(),
      attempts: 0,
      isUsed: false,
      metadata: { email: 'test@example.com' },
    };

    it('should store two factor code successfully', async () => {
      mockPool.query.mockResolvedValueOnce({});

      await postgresqlAdapter.storeTwoFactorCode!(mockCode);

      expect(mockPool.query).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO auth_two_factor_codes'),
        [
          mockCode.id,
          mockCode.userId,
          mockCode.code,
          mockCode.hashedCode,
          mockCode.type,
          mockCode.expiresAt,
          mockCode.attempts,
          mockCode.isUsed,
          JSON.stringify(mockCode.metadata),
        ]
      );
    });

    it('should get two factor code successfully', async () => {
      const mockDbCode = {
        id: mockCode.id,
        user_id: mockCode.userId,
        code: mockCode.code,
        hashed_code: mockCode.hashedCode,
        type: mockCode.type,
        expires_at: mockCode.expiresAt,
        created_at: mockCode.createdAt,
        attempts: mockCode.attempts,
        is_used: mockCode.isUsed,
        metadata: mockCode.metadata,
      };

      mockPool.query.mockResolvedValueOnce({
        rows: [mockDbCode],
      });

      const result = await postgresqlAdapter.getTwoFactorCode!(mockCode.id);

      expect(result).toEqual(mockCode);
    });

    it('should return null if code not found', async () => {
      mockPool.query.mockResolvedValueOnce({
        rows: [],
      });

      const result = await postgresqlAdapter.getTwoFactorCode!('nonexistent');

      expect(result).toBeNull();
    });

    it('should update two factor code attempts', async () => {
      mockPool.query.mockResolvedValueOnce({});

      await postgresqlAdapter.updateTwoFactorCode!(mockCode.id, {
        attempts: 1,
      });

      expect(mockPool.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE auth_two_factor_codes'),
        [1, mockCode.id]
      );
    });

    it('should cleanup expired codes', async () => {
      mockPool.query.mockResolvedValueOnce({
        rowCount: 5,
      });

      const result = await postgresqlAdapter.cleanupExpiredTwoFactorCodes!();

      expect(result).toBe(5);
      expect(mockPool.query).toHaveBeenCalledWith(
        'DELETE FROM auth_two_factor_codes WHERE expires_at < NOW()'
      );
    });
  });

  describe('configuration', () => {
    it('should throw error if no configuration provided', async () => {
      delete process.env.DATABASE_URL;
      resetPostgreSQLConnection();

      await expect(
        postgresqlAdapter.findUserByEmail('test@example.com')
      ).rejects.toThrow('PostgreSQL configuration missing');
    });

    it('should work with individual environment variables', async () => {
      delete process.env.DATABASE_URL;
      process.env.POSTGRESQL_HOST = 'localhost';
      process.env.POSTGRESQL_PORT = '5432';
      process.env.POSTGRESQL_DATABASE = 'testdb';
      process.env.POSTGRESQL_USER = 'testuser';
      process.env.POSTGRESQL_PASSWORD = 'testpass';

      resetPostgreSQLConnection();

      mockPool.query.mockResolvedValueOnce({
        rows: [],
      });

      const result = await postgresqlAdapter.findUserByEmail('test@example.com');

      expect(result).toBeNull();
      expect(mockPg.Pool).toHaveBeenCalledWith({
        host: 'localhost',
        port: 5432,
        database: 'testdb',
        user: 'testuser',
        password: 'testpass',
        ssl: false,
      });
    });

    it('should use custom table names from environment', async () => {
      process.env.AUTH_USER_TABLE = 'custom_users';
      process.env.AUTH_2FA_TABLE = 'custom_codes';

      mockPool.query.mockResolvedValueOnce({
        rows: [],
      });

      await postgresqlAdapter.findUserByEmail('test@example.com');

      expect(mockPool.query).toHaveBeenCalledWith(
        'SELECT * FROM custom_users WHERE email = $1 LIMIT 1',
        ['test@example.com']
      );
    });
  });

  describe('findUserByUsername', () => {
    it('should find user by username successfully', async () => {
      const mockUser = {
        id: '123',
        email: 'test@example.com',
        password: 'hashedpassword',
        username: 'testuser',
        first_name: 'John',
        last_name: 'Doe',
        created_at: new Date(),
        email_verified: false,
        email_verified_at: null,
        two_factor_enabled: false,
      };

      mockPool.query.mockResolvedValueOnce({
        rows: [mockUser],
      });

      const result = await postgresqlAdapter.findUserByUsername('testuser');

      expect(result).toEqual({
        id: '123',
        email: 'test@example.com',
        password: 'hashedpassword',
        username: 'testuser',
        firstName: 'John',
        lastName: 'Doe',
        createdAt: mockUser.created_at,
        emailVerified: false,
        emailVerifiedAt: null,
        twoFactorEnabled: false,
      });

      expect(mockPool.query).toHaveBeenCalledWith(
        'SELECT * FROM custom_users WHERE LOWER(username) = $1 LIMIT 1',
        ['testuser']
      );
    });

    it('should return null if user not found by username', async () => {
      mockPool.query.mockResolvedValueOnce({
        rows: [],
      });

      const result = await postgresqlAdapter.findUserByUsername('nonexistent');

      expect(result).toBeNull();
    });

    it('should normalize username to lowercase', async () => {
      const mockUser = {
        id: '123',
        email: 'test@example.com',
        password: 'hashedpassword',
        username: 'testuser',
        first_name: 'John',
        last_name: 'Doe',
        created_at: new Date(),
        email_verified: false,
        email_verified_at: null,
        two_factor_enabled: false,
      };

      mockPool.query.mockResolvedValueOnce({
        rows: [mockUser],
      });

      await postgresqlAdapter.findUserByUsername('TestUser');

      expect(mockPool.query).toHaveBeenCalledWith(
        'SELECT * FROM custom_users WHERE LOWER(username) = $1 LIMIT 1',
        ['testuser']
      );
    });
  });
});
