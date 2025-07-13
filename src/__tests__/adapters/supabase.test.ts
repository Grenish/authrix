import { supabaseAdapter, resetSupabaseConnection } from '../../adapters/supabase';

// Mock Supabase client
const mockSupabaseClient = {
  from: jest.fn().mockReturnThis(),
  select: jest.fn().mockReturnThis(),
  eq: jest.fn().mockReturnThis(),
  single: jest.fn(),
  insert: jest.fn().mockReturnThis()
};

jest.mock('@supabase/supabase-js', () => ({
  createClient: jest.fn(() => mockSupabaseClient)
}));

import { createClient } from '@supabase/supabase-js';

const mockCreateClient = createClient as jest.MockedFunction<typeof createClient>;

// Mock environment variables
const originalEnv = process.env;

describe('Supabase Adapter', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env = {
      ...originalEnv,
      SUPABASE_URL: 'https://test.supabase.co',
      SUPABASE_ANON_KEY: 'test-anon-key',
      SUPABASE_AUTH_TABLE: 'users'
    };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('findUserByEmail', () => {
    it('should find user by email successfully', async () => {
      const mockData = {
        id: 123,
        email: 'test@example.com',
        password: 'hashedpassword',
        created_at: '2023-01-01T00:00:00.000Z'
      };

      mockSupabaseClient.single.mockResolvedValueOnce({
        data: mockData,
        error: null
      });

      const result = await supabaseAdapter.findUserByEmail('test@example.com');

      expect(mockSupabaseClient.from).toHaveBeenCalledWith('users');
      expect(mockSupabaseClient.select).toHaveBeenCalledWith('*');
      expect(mockSupabaseClient.eq).toHaveBeenCalledWith('email', 'test@example.com');
      expect(result).toEqual({
        id: '123',
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: new Date('2023-01-01T00:00:00.000Z')
      });
    });

    it('should return null if user not found', async () => {
      mockSupabaseClient.single.mockResolvedValueOnce({
        data: null,
        error: { message: 'No rows returned' }
      });

      const result = await supabaseAdapter.findUserByEmail('notfound@example.com');

      expect(result).toBeNull();
    });

    it('should normalize email to lowercase and trim', async () => {
      mockSupabaseClient.single.mockResolvedValueOnce({
        data: null,
        error: { message: 'No rows returned' }
      });

      await supabaseAdapter.findUserByEmail('  TEST@EXAMPLE.COM  ');

      expect(mockSupabaseClient.eq).toHaveBeenCalledWith('email', 'test@example.com');
    });
  });

  describe('findUserById', () => {
    it('should find user by ID successfully', async () => {
      const mockData = {
        id: 123,
        email: 'test@example.com',
        password: 'hashedpassword',
        created_at: '2023-01-01T00:00:00.000Z'
      };

      mockSupabaseClient.single.mockResolvedValueOnce({
        data: mockData,
        error: null
      });

      const result = await supabaseAdapter.findUserById('123');

      expect(mockSupabaseClient.from).toHaveBeenCalledWith('users');
      expect(mockSupabaseClient.select).toHaveBeenCalledWith('*');
      expect(mockSupabaseClient.eq).toHaveBeenCalledWith('id', '123');
      expect(result).toEqual({
        id: '123',
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: new Date('2023-01-01T00:00:00.000Z')
      });
    });

    it('should return null if user not found', async () => {
      mockSupabaseClient.single.mockResolvedValueOnce({
        data: null,
        error: { message: 'No rows returned' }
      });

      const result = await supabaseAdapter.findUserById('nonexistent');

      expect(result).toBeNull();
    });
  });

  describe('createUser', () => {
    it('should create user successfully', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'hashedpassword'
      };

      const mockData = {
        id: 123,
        email: 'test@example.com',
        password: 'hashedpassword',
        created_at: '2023-01-01T00:00:00.000Z'
      };

      mockSupabaseClient.single.mockResolvedValueOnce({
        data: mockData,
        error: null
      });

      const result = await supabaseAdapter.createUser(userData);

      expect(mockSupabaseClient.from).toHaveBeenCalledWith('users');
      expect(mockSupabaseClient.insert).toHaveBeenCalledWith({
        email: 'test@example.com',
        password: 'hashedpassword',
        created_at: expect.any(String)
      });
      expect(result).toEqual({
        id: '123',
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: new Date('2023-01-01T00:00:00.000Z')
      });
    });

    it('should normalize email when creating user', async () => {
      const userData = {
        email: '  TEST@EXAMPLE.COM  ',
        password: 'hashedpassword'
      };

      const mockData = {
        id: 123,
        email: 'test@example.com',
        password: 'hashedpassword',
        created_at: '2023-01-01T00:00:00.000Z'
      };

      mockSupabaseClient.single.mockResolvedValueOnce({
        data: mockData,
        error: null
      });

      const result = await supabaseAdapter.createUser(userData);

      expect(mockSupabaseClient.insert).toHaveBeenCalledWith({
        email: 'test@example.com',
        password: 'hashedpassword',
        created_at: expect.any(String)
      });
      expect(result.email).toBe('test@example.com');
    });

    it('should handle creation errors', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'hashedpassword'
      };

      mockSupabaseClient.single.mockResolvedValueOnce({
        data: null,
        error: { message: 'Unique constraint violation' }
      });

      await expect(supabaseAdapter.createUser(userData)).rejects.toThrow(
        'Failed to create user: Unique constraint violation'
      );
    });
  });

  describe('initialization', () => {
    it('should throw error if environment variables are missing', async () => {
      process.env = {};
      resetSupabaseConnection(); // Reset cached connection

      await expect(supabaseAdapter.findUserByEmail('test@example.com')).rejects.toThrow(
        'SUPABASE_URL and SUPABASE_ANON_KEY environment variables are required'
      );
    });

    it('should use default table name if not specified', async () => {
      delete process.env.SUPABASE_AUTH_TABLE;

      mockSupabaseClient.single.mockResolvedValueOnce({
        data: null,
        error: { message: 'No rows returned' }
      });

      await supabaseAdapter.findUserByEmail('test@example.com');

      expect(mockSupabaseClient.from).toHaveBeenCalledWith('users');
    });

    it('should create client with correct parameters', async () => {
      // Set environment variables
      process.env.SUPABASE_URL = 'https://test.supabase.co';
      process.env.SUPABASE_ANON_KEY = 'test-anon-key';
      
      resetSupabaseConnection(); // Reset to ensure fresh connection
      
      mockSupabaseClient.single.mockResolvedValueOnce({
        data: null,
        error: { message: 'No rows returned' }
      });

      await supabaseAdapter.findUserByEmail('test@example.com');

      expect(mockCreateClient).toHaveBeenCalledWith(
        'https://test.supabase.co',
        'test-anon-key'
      );
    });
  });
});
