import { firebaseAdapter, resetFirebaseConnection } from '../../adapters/firebase';

// Mock Firebase
jest.mock('firebase/app', () => ({
  initializeApp: jest.fn(),
  getApps: jest.fn()
}));

jest.mock('firebase/firestore', () => ({
  getFirestore: jest.fn(),
  collection: jest.fn(),
  doc: jest.fn(),
  getDoc: jest.fn(),
  setDoc: jest.fn(),
  query: jest.fn(),
  where: jest.fn(),
  getDocs: jest.fn()
}));

import { 
  initializeApp, 
  getApps 
} from 'firebase/app';
import { 
  getFirestore, 
  collection, 
  doc, 
  getDoc, 
  setDoc, 
  query, 
  where, 
  getDocs 
} from 'firebase/firestore';

const mockApp = { name: 'mock-app' };
const mockDb = { name: 'mock-db' };
const mockCollectionRef = { id: 'mock-collection' };
const mockDocRef = { id: 'mock-doc' };
const mockQueryRef = { id: 'mock-query' };

const mockInitializeApp = initializeApp as jest.MockedFunction<typeof initializeApp>;
const mockGetApps = getApps as jest.MockedFunction<typeof getApps>;
const mockGetFirestore = getFirestore as jest.MockedFunction<typeof getFirestore>;
const mockCollectionFn = collection as jest.MockedFunction<typeof collection>;
const mockDocFn = doc as jest.MockedFunction<typeof doc>;
const mockGetDoc = getDoc as jest.MockedFunction<typeof getDoc>;
const mockSetDoc = setDoc as jest.MockedFunction<typeof setDoc>;
const mockQueryFn = query as jest.MockedFunction<typeof query>;
const mockWhere = where as jest.MockedFunction<typeof where>;
const mockGetDocs = getDocs as jest.MockedFunction<typeof getDocs>;

// Mock environment variables
const originalEnv = process.env;

describe('Firebase Adapter', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env = {
      ...originalEnv,
      FIREBASE_API_KEY: 'test-api-key',
      FIREBASE_AUTH_DOMAIN: 'test.firebaseapp.com',
      FIREBASE_PROJECT_ID: 'test-project',
      FIREBASE_STORAGE_BUCKET: 'test.appspot.com',
      FIREBASE_MESSAGING_SENDER_ID: '123456789',
      FIREBASE_APP_ID: '1:123456789:web:abc123',
      FIREBASE_AUTH_COLLECTION: 'users'
    };

    mockGetApps.mockReturnValue([]);
    mockInitializeApp.mockReturnValue(mockApp as any);
    mockGetFirestore.mockReturnValue(mockDb as any);
    mockCollectionFn.mockReturnValue(mockCollectionRef as any);
    mockDocFn.mockReturnValue(mockDocRef as any);
    
    // Mock where to return a proper constraint object
    const mockWhereConstraint = { type: 'where', field: 'email' };
    mockWhere.mockReturnValue(mockWhereConstraint as any);
    
    // Mock query to return the query ref with the constraint
    mockQueryFn.mockReturnValue(mockQueryRef as any);
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('findUserByEmail', () => {
    it('should find user by email successfully', async () => {
      const mockUserData = {
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: { toDate: () => new Date('2023-01-01') }
      };

      const mockQuerySnapshot = {
        empty: false,
        docs: [{
          id: 'user123',
          data: () => mockUserData
        }]
      };

      mockGetDocs.mockResolvedValueOnce(mockQuerySnapshot as any);

      const result = await firebaseAdapter.findUserByEmail('test@example.com');

      expect(mockQueryFn).toHaveBeenCalledWith(mockCollectionRef, expect.anything());
      expect(mockWhere).toHaveBeenCalledWith('email', '==', 'test@example.com');
      expect(result).toEqual({
        id: 'user123',
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: new Date('2023-01-01')
      });
    });

    it('should return null if user not found', async () => {
      const mockQuerySnapshot = {
        empty: true,
        docs: []
      };

      mockGetDocs.mockResolvedValueOnce(mockQuerySnapshot as any);

      const result = await firebaseAdapter.findUserByEmail('notfound@example.com');

      expect(result).toBeNull();
    });

    it('should handle errors gracefully', async () => {
      mockGetDocs.mockRejectedValueOnce(new Error('Firebase error'));

      const result = await firebaseAdapter.findUserByEmail('test@example.com');

      expect(result).toBeNull();
    });

    it('should normalize email to lowercase and trim', async () => {
      const mockQuerySnapshot = { empty: true, docs: [] };
      mockGetDocs.mockResolvedValueOnce(mockQuerySnapshot as any);

      await firebaseAdapter.findUserByEmail('  TEST@EXAMPLE.COM  ');

      expect(mockWhere).toHaveBeenCalledWith('email', '==', 'test@example.com');
    });
  });

  describe('findUserById', () => {
    it('should find user by ID successfully', async () => {
      const mockUserData = {
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: { toDate: () => new Date('2023-01-01') }
      };

      const mockDocSnapshot = {
        exists: () => true,
        id: 'user123',
        data: () => mockUserData
      };

      mockGetDoc.mockResolvedValueOnce(mockDocSnapshot as any);

      const result = await firebaseAdapter.findUserById('user123');

      expect(mockDocFn).toHaveBeenCalledWith(mockDb, 'users', 'user123');
      expect(result).toEqual({
        id: 'user123',
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: new Date('2023-01-01')
      });
    });

    it('should return null if user not found', async () => {
      const mockDocSnapshot = {
        exists: () => false
      };

      mockGetDoc.mockResolvedValueOnce(mockDocSnapshot as any);

      const result = await firebaseAdapter.findUserById('nonexistent');

      expect(result).toBeNull();
    });

    it('should handle errors gracefully', async () => {
      mockGetDoc.mockRejectedValueOnce(new Error('Firebase error'));

      const result = await firebaseAdapter.findUserById('user123');

      expect(result).toBeNull();
    });
  });

  describe('createUser', () => {
    it('should create user successfully', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'hashedpassword'
      };

      const mockDocRef = { id: 'new-user-id' };
      mockDocFn.mockReturnValueOnce(mockDocRef as any);
      mockSetDoc.mockResolvedValueOnce(undefined);

      const result = await firebaseAdapter.createUser(userData);

      expect(mockSetDoc).toHaveBeenCalledWith(mockDocRef, {
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: expect.any(Date)
      });
      expect(result).toEqual({
        id: 'new-user-id',
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

      const mockDocRef = { id: 'new-user-id' };
      mockDocFn.mockReturnValueOnce(mockDocRef as any);
      mockSetDoc.mockResolvedValueOnce(undefined);

      const result = await firebaseAdapter.createUser(userData);

      expect(mockSetDoc).toHaveBeenCalledWith(mockDocRef, {
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: expect.any(Date)
      });
      expect(result.email).toBe('test@example.com');
    });

    it('should handle creation errors', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'hashedpassword'
      };

      mockSetDoc.mockRejectedValueOnce(new Error('Firebase write error'));

      await expect(firebaseAdapter.createUser(userData)).rejects.toThrow(
        'Failed to create user: Firebase write error'
      );
    });
  });

  describe('initialization', () => {
    it('should throw error if required environment variables are missing', async () => {
      process.env = {};
      resetFirebaseConnection(); // Reset cached connection

      await expect(firebaseAdapter.findUserByEmail('test@example.com')).rejects.toThrow(
        'Missing required Firebase environment variables'
      );
    });

    it('should use existing app if already initialized', async () => {
      mockGetApps.mockReturnValue([mockApp] as any);

      await firebaseAdapter.findUserByEmail('test@example.com');

      expect(mockInitializeApp).not.toHaveBeenCalled();
    });

    it('should use default collection name if not specified', async () => {
      delete process.env.FIREBASE_AUTH_COLLECTION;

      const mockQuerySnapshot = { empty: true, docs: [] };
      mockGetDocs.mockResolvedValueOnce(mockQuerySnapshot as any);

      await firebaseAdapter.findUserByEmail('test@example.com');

      expect(mockCollectionFn).toHaveBeenCalledWith(mockDb, 'users');
    });
  });
});
