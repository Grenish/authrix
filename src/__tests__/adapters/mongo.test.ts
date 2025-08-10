import { mongoAdapter, resetMongoConnection } from '../../adapters/mongo';

// Mock MongoDB before everything else
jest.mock('mongodb', () => {
  const mockObjectId = jest.fn().mockImplementation((id?: string) => ({ 
    toString: () => id || 'mock-object-id' 
  }));
  (mockObjectId as any).isValid = jest.fn().mockReturnValue(true);
  
  return {
    MongoClient: jest.fn(),
    ObjectId: mockObjectId
  };
});

const mockCollection = {
  findOne: jest.fn(),
  insertOne: jest.fn(),
  createIndex: jest.fn().mockResolvedValue(undefined)
};

const mockDb = {
  collection: jest.fn().mockReturnValue(mockCollection)
};

const mockClient = {
  connect: jest.fn(),
  db: jest.fn().mockReturnValue(mockDb)
};

import { MongoClient, ObjectId } from 'mongodb';

// Get the mocked classes
const MockMongoClient = MongoClient as jest.MockedClass<typeof MongoClient>;
const mockObjectId = ObjectId as jest.MockedClass<typeof ObjectId>;

// Mock environment variables
const originalEnv = process.env;

describe('Mongo Adapter', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    resetMongoConnection(); // Reset connection state
    process.env = {
      ...originalEnv,
      MONGO_URI: 'mongodb://localhost:27017',
      DB_NAME: 'test_db',
      AUTH_COLLECTION: 'users',
      TWO_FACTOR_COLLECTION: 'two_factor_codes'
    };
    
    // Mock the collection methods properly
    mockCollection.createIndex = jest.fn().mockResolvedValue(undefined);
    
    MockMongoClient.mockImplementation(() => mockClient as any);
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('findUserByEmail', () => {
    it('should find user by email successfully', async () => {
      const mockUser = {
        _id: { toString: () => '507f1f77bcf86cd799439011' },
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: new Date('2023-01-01')
      };

      mockCollection.findOne.mockResolvedValueOnce(mockUser);

      const result = await mongoAdapter.findUserByEmail('test@example.com');

      expect(mockCollection.findOne).toHaveBeenCalledWith({ 
        email: 'test@example.com' 
      });
      expect(result).toEqual({
        id: '507f1f77bcf86cd799439011',
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: new Date('2023-01-01')
      });
    });

    it('should return null if user not found', async () => {
      mockCollection.findOne.mockResolvedValueOnce(null);

      const result = await mongoAdapter.findUserByEmail('notfound@example.com');

      expect(result).toBeNull();
    });

    it('should normalize email to lowercase and trim', async () => {
      mockCollection.findOne.mockResolvedValueOnce(null);

      await mongoAdapter.findUserByEmail('  TEST@EXAMPLE.COM  ');

      expect(mockCollection.findOne).toHaveBeenCalledWith({ 
        email: 'test@example.com' 
      });
    });
  });

  describe('findUserById', () => {
    it('should find user by ID successfully', async () => {
      const userId = '507f1f77bcf86cd799439011';
      const mockUser = {
        _id: { toString: () => userId },
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: new Date('2023-01-01')
      };

      (mockObjectId as any).isValid.mockReturnValueOnce(true);
      mockCollection.findOne.mockResolvedValueOnce(mockUser);

      const result = await mongoAdapter.findUserById(userId);

      expect((mockObjectId as any).isValid).toHaveBeenCalledWith(userId);
      expect(result).toEqual({
        id: userId,
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: new Date('2023-01-01')
      });
    });

    it('should return null for invalid ObjectId', async () => {
      (mockObjectId as any).isValid.mockReturnValueOnce(false);

      const result = await mongoAdapter.findUserById('invalid-id');

      expect(result).toBeNull();
    });

    it('should return null if user not found', async () => {
      (mockObjectId as any).isValid.mockReturnValueOnce(true);
      mockCollection.findOne.mockResolvedValueOnce(null);

      const result = await mongoAdapter.findUserById('507f1f77bcf86cd799439011');

      expect(result).toBeNull();
    });
  });

  describe('createUser', () => {
    it('should create user successfully', async () => {
      const userId = '507f1f77bcf86cd799439011';
      const userData = {
        email: 'test@example.com',
        password: 'hashedpassword'
      };

      mockCollection.insertOne.mockResolvedValueOnce({
        insertedId: { toString: () => userId }
      });

      const result = await mongoAdapter.createUser(userData);

      expect(mockCollection.insertOne).toHaveBeenCalledWith({
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: expect.any(Date)
      });
      expect(result).toEqual({
        id: userId,
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: expect.any(Date)
      });
    });

    it('should normalize email when creating user', async () => {
      const userData = {
        email: '  TEST@EXAMPLE.COM  ',
        password: 'hashedpassword'
      };

      mockCollection.insertOne.mockResolvedValueOnce({
        insertedId: { toString: () => '507f1f77bcf86cd799439011' }
      });

      await mongoAdapter.createUser(userData);

      expect(mockCollection.insertOne).toHaveBeenCalledWith({
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: expect.any(Date)
      });
    });
  });

  describe('initialization', () => {
    it('should throw error if environment variables are missing', async () => {
      resetMongoConnection(); // Reset before clearing env vars
      process.env = {};

      await expect(mongoAdapter.findUserByEmail('test@example.com')).rejects.toThrow(
        'Missing required environment variables: MONGO_URI, DB_NAME, AUTH_COLLECTION'
      );
    });
  });
});
