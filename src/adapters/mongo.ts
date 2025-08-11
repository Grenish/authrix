import type { AuthDbAdapter, AuthUser, TwoFactorCode } from "../types/db";
import { MongoClient, ObjectId, Collection, Db, IndexSpecification, CreateIndexesOptions } from "mongodb";

// Types
interface MongoUser {
  _id?: ObjectId;
  email: string;
  password: string;
  createdAt: Date;
  emailVerified: boolean;
  emailVerifiedAt?: Date;
  twoFactorEnabled: boolean;
  username?: string;
  firstName?: string;
  lastName?: string;
  fullName?: string;
  profilePicture?: string;
  lastLoginAt?: Date;
  loginCount?: number;
}

interface ConnectionConfig {
  uri: string;
  dbName: string;
  authCollection: string;
  twoFactorCollection: string;
  options?: {
    maxPoolSize?: number;
    minPoolSize?: number;
    socketTimeoutMS?: number;
    serverSelectionTimeoutMS?: number;
  };
}

// Connection management with singleton pattern
class MongoConnection {
  private static instance: MongoConnection;
  private client: MongoClient | null = null;
  private db: Db | null = null;
  private usersCollection: Collection<MongoUser> | null = null;
  private twoFactorCollection: Collection<TwoFactorCode> | null = null;
  private config: ConnectionConfig | null = null;
  private connectionPromise: Promise<void> | null = null;
  private isConnected = false;

  private constructor() {}

  static getInstance(): MongoConnection {
    if (!this.instance) {
      this.instance = new MongoConnection();
    }
    return this.instance;
  }

  private loadConfig(): ConnectionConfig {
    if (this.config) return this.config;

    const uri = process.env.MONGO_URI;
    const dbName = process.env.DB_NAME;
    const authCollection = process.env.AUTH_COLLECTION || 'users';
    const twoFactorCollection = process.env.TWO_FACTOR_COLLECTION || 'two_factor_codes';

    if (!uri || !dbName) {
      throw new Error(
        'Missing required MongoDB environment variables:\n' +
        '- MONGO_URI: MongoDB connection string\n' +
        '- DB_NAME: Database name\n' +
        'Optional:\n' +
        '- AUTH_COLLECTION: Users collection name (default: "users")\n' +
        '- TWO_FACTOR_COLLECTION: 2FA codes collection name (default: "two_factor_codes")'
      );
    }

    this.config = {
      uri,
      dbName,
      authCollection,
      twoFactorCollection,
      options: {
        maxPoolSize: parseInt(process.env.MONGO_MAX_POOL_SIZE || '10'),
        minPoolSize: parseInt(process.env.MONGO_MIN_POOL_SIZE || '2'),
        socketTimeoutMS: parseInt(process.env.MONGO_SOCKET_TIMEOUT || '30000'),
        serverSelectionTimeoutMS: parseInt(process.env.MONGO_SERVER_SELECTION_TIMEOUT || '5000'),
      }
    };

    return this.config;
  }

  async connect(): Promise<void> {
    // Return existing connection promise if connecting
    if (this.connectionPromise) {
      return this.connectionPromise;
    }

    // Already connected
    if (this.isConnected && this.client) {
      return;
    }

    this.connectionPromise = this.performConnection();
    return this.connectionPromise;
  }

  private async performConnection(): Promise<void> {
    try {
      const config = this.loadConfig();

      // Create client with optimized settings
      this.client = new MongoClient(config.uri, {
        maxPoolSize: config.options?.maxPoolSize,
        minPoolSize: config.options?.minPoolSize,
        socketTimeoutMS: config.options?.socketTimeoutMS,
        serverSelectionTimeoutMS: config.options?.serverSelectionTimeoutMS,
      });

      await this.client.connect();
      this.db = this.client.db(config.dbName);
      this.usersCollection = this.db.collection<MongoUser>(config.authCollection);
      this.twoFactorCollection = this.db.collection<TwoFactorCode>(config.twoFactorCollection);

      // Create indexes
      await this.createIndexes();

      this.isConnected = true;
    } catch (error) {
      this.connectionPromise = null;
      throw new Error(`MongoDB connection failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async createIndexes(): Promise<void> {
    if (!this.usersCollection || !this.twoFactorCollection) return;

    // Define indexes with options
    const userIndexes: Array<[IndexSpecification, CreateIndexesOptions?]> = [
      [{ email: 1 }, { unique: true, background: true }],
      [{ username: 1 }, { unique: true, sparse: true, background: true }],
      [{ createdAt: -1 }, { background: true }],
      [{ emailVerified: 1, createdAt: -1 }, { background: true }],
    ];

    const twoFactorIndexes: Array<[IndexSpecification, CreateIndexesOptions?]> = [
      [{ id: 1 }, { unique: true, background: true }],
      [{ userId: 1, type: 1, isUsed: 1 }, { background: true }],
      [{ expiresAt: 1 }, { expireAfterSeconds: 0, background: true }],
      [{ createdAt: -1 }, { background: true }],
    ];

    // Create indexes in parallel
    await Promise.all([
      ...userIndexes.map(([spec, options]) => 
        this.usersCollection!.createIndex(spec, options).catch(() => {})
      ),
      ...twoFactorIndexes.map(([spec, options]) => 
        this.twoFactorCollection!.createIndex(spec, options).catch(() => {})
      ),
    ]);
  }

  async getUsers(): Promise<Collection<MongoUser>> {
    if (!this.usersCollection) {
      await this.connect();
    }
    return this.usersCollection!;
  }

  async getTwoFactorCodes(): Promise<Collection<TwoFactorCode>> {
    if (!this.twoFactorCollection) {
      await this.connect();
    }
    return this.twoFactorCollection!;
  }

  async disconnect(): Promise<void> {
    if (this.client) {
      await this.client.close();
      this.client = null;
      this.db = null;
      this.usersCollection = null;
      this.twoFactorCollection = null;
      this.isConnected = false;
      this.connectionPromise = null;
    }
  }

  reset(): void {
    this.disconnect();
    this.config = null;
  }
}

// Helper functions
function normalizeEmail(email: string): string {
  return email.toLowerCase().trim();
}

function normalizeUsername(username?: string): string | undefined {
  return username ? username.toLowerCase().trim() : undefined;
}

function mongoUserToAuthUser(user: MongoUser & { _id: ObjectId }): AuthUser {
  return {
    id: user._id.toString(),
    email: user.email,
    password: user.password,
    createdAt: user.createdAt,
    emailVerified: user.emailVerified || false,
    emailVerifiedAt: user.emailVerifiedAt,
    twoFactorEnabled: user.twoFactorEnabled || false,
    username: user.username,
    firstName: user.firstName,
  lastName: user.lastName,
  fullName: user.fullName,
  profilePicture: user.profilePicture,
  };
}

// Optimized adapter
export const mongoAdapter: AuthDbAdapter = {
  async findUserByEmail(email: string): Promise<AuthUser | null> {
    const conn = MongoConnection.getInstance();
    const users = await conn.getUsers();
    
    const user = await users.findOne(
      { email: normalizeEmail(email) },
    { 
        projection: {
          _id: 1,
          email: 1,
          password: 1,
          createdAt: 1,
          emailVerified: 1,
          emailVerifiedAt: 1,
          twoFactorEnabled: 1,
          username: 1,
          firstName: 1,
      lastName: 1,
      fullName: 1,
      profilePicture: 1,
        }
      }
    );

    return user && user._id ? mongoUserToAuthUser(user as MongoUser & { _id: ObjectId }) : null;
  },

  async findUserById(id: string): Promise<AuthUser | null> {
    if (!ObjectId.isValid(id)) return null;

    const conn = MongoConnection.getInstance();
    const users = await conn.getUsers();
    
    const user = await users.findOne(
      { _id: new ObjectId(id) },
    { 
        projection: {
          _id: 1,
          email: 1,
          password: 1,
          createdAt: 1,
          emailVerified: 1,
          emailVerifiedAt: 1,
          twoFactorEnabled: 1,
          username: 1,
          firstName: 1,
      lastName: 1,
      fullName: 1,
      profilePicture: 1,
        }
      }
    );

    return user && user._id ? mongoUserToAuthUser(user as MongoUser & { _id: ObjectId }) : null;
  },

  async createUser({ email, password, username, firstName, lastName, fullName, profilePicture }): Promise<AuthUser> {
    const conn = MongoConnection.getInstance();
    const users = await conn.getUsers();
    
    const normalizedEmail = normalizeEmail(email);
    const normalizedUsername = normalizeUsername(username);
    const now = new Date();

    const userData: MongoUser = {
      email: normalizedEmail,
      password,
      createdAt: now,
      emailVerified: false,
      twoFactorEnabled: false,
      loginCount: 0,
    };

  if (normalizedUsername) userData.username = normalizedUsername;
  if (firstName) userData.firstName = firstName.trim();
  if (lastName) userData.lastName = lastName.trim();
  if (fullName) userData.fullName = fullName.trim();
  if (profilePicture) userData.profilePicture = profilePicture;

    try {
      const result = await users.insertOne(userData);
      
      if (!result.insertedId) {
        throw new Error("Failed to create user: No ID generated");
      }

      return {
        id: result.insertedId.toString(),
        email: normalizedEmail,
        password,
        createdAt: now,
        emailVerified: false,
        twoFactorEnabled: false,
        username: normalizedUsername,
        firstName: firstName?.trim(),
        lastName: lastName?.trim(),
        fullName: fullName?.trim(),
        profilePicture,
      };
    } catch (error: any) {
      if (error.code === 11000) {
        const field = error.keyPattern?.email ? 'email' : 
                     error.keyPattern?.username ? 'username' : 'field';
        const value = field === 'email' ? email : username;
        throw new Error(`${field.charAt(0).toUpperCase() + field.slice(1)} "${value}" is already in use`);
      }
      throw new Error(`Failed to create user: ${error.message}`);
    }
  },

  async updateUser(id: string, data: Partial<AuthUser>): Promise<AuthUser> {
    if (!ObjectId.isValid(id)) {
      throw new Error("Invalid user ID");
    }

    const conn = MongoConnection.getInstance();
    const users = await conn.getUsers();

    // Prepare update data
    const updateData: Partial<MongoUser> = {};
    
    if (data.email !== undefined) updateData.email = normalizeEmail(data.email);
    if (data.password !== undefined) updateData.password = data.password;
    if (data.emailVerified !== undefined) updateData.emailVerified = data.emailVerified;
    if (data.emailVerifiedAt !== undefined) updateData.emailVerifiedAt = data.emailVerifiedAt;
    if (data.twoFactorEnabled !== undefined) updateData.twoFactorEnabled = data.twoFactorEnabled;
    if (data.username !== undefined) updateData.username = normalizeUsername(data.username);
  if (data.firstName !== undefined) updateData.firstName = data.firstName?.trim();
  if (data.lastName !== undefined) updateData.lastName = data.lastName?.trim();
  if (data.fullName !== undefined) updateData.fullName = data.fullName?.trim();
  if (data.profilePicture !== undefined) updateData.profilePicture = data.profilePicture;

    try {
      const result = await users.findOneAndUpdate(
        { _id: new ObjectId(id) },
        { $set: updateData },
        { 
          returnDocument: 'after',
          projection: {
            _id: 1,
            email: 1,
            password: 1,
            createdAt: 1,
            emailVerified: 1,
            emailVerifiedAt: 1,
            twoFactorEnabled: 1,
            username: 1,
            firstName: 1,
            lastName: 1,
            fullName: 1,
            profilePicture: 1,
          }
        }
      );

      if (!result || !result._id) {
        throw new Error("User not found");
      }

      return mongoUserToAuthUser(result as MongoUser & { _id: ObjectId });
    } catch (error: any) {
      if (error.code === 11000) {
        const field = error.keyPattern?.email ? 'email' : 
                     error.keyPattern?.username ? 'username' : 'field';
        const value = field === 'email' ? data.email : data.username;
        throw new Error(`${field.charAt(0).toUpperCase() + field.slice(1)} "${value}" is already in use`);
      }
      throw error;
    }
  },

  async findUserByUsername(username: string): Promise<AuthUser | null> {
    const conn = MongoConnection.getInstance();
    const users = await conn.getUsers();
    
    const user = await users.findOne(
      { username: normalizeUsername(username) },
      { 
        projection: {
          _id: 1,
          email: 1,
          password: 1,
          createdAt: 1,
          emailVerified: 1,
          emailVerifiedAt: 1,
          twoFactorEnabled: 1,
          username: 1,
          firstName: 1,
          lastName: 1,
          fullName: 1,
          profilePicture: 1,
        }
      }
    );

    return user && user._id ? mongoUserToAuthUser(user as MongoUser & { _id: ObjectId }) : null;
  },

  // 2FA methods with optimizations
  async storeTwoFactorCode(code: TwoFactorCode): Promise<void> {
    const conn = MongoConnection.getInstance();
    const codes = await conn.getTwoFactorCodes();
    await codes.insertOne(code);
  },

  async getTwoFactorCode(codeId: string): Promise<TwoFactorCode | null> {
    const conn = MongoConnection.getInstance();
    const codes = await conn.getTwoFactorCodes();
    return await codes.findOne({ id: codeId }) as TwoFactorCode | null;
  },

  async updateTwoFactorCode(codeId: string, updates: Partial<TwoFactorCode>): Promise<void> {
    const conn = MongoConnection.getInstance();
    const codes = await conn.getTwoFactorCodes();
    await codes.updateOne({ id: codeId }, { $set: updates });
  },

  async getUserTwoFactorCodes(userId: string, type?: string): Promise<TwoFactorCode[]> {
    const conn = MongoConnection.getInstance();
    const codes = await conn.getTwoFactorCodes();
    
    const query: any = { 
      userId, 
      isUsed: false,
      expiresAt: { $gt: new Date() } // Only get non-expired codes
    };
    
    if (type) query.type = type;
    
    return await codes
      .find(query)
      .sort({ createdAt: -1 })
      .limit(10) // Limit results for performance
      .toArray() as TwoFactorCode[];
  },

  async cleanupExpiredTwoFactorCodes(): Promise<number> {
    const conn = MongoConnection.getInstance();
    const codes = await conn.getTwoFactorCodes();
    
    const result = await codes.deleteMany({
      $or: [
        { expiresAt: { $lt: new Date() } },
        { isUsed: true, createdAt: { $lt: new Date(Date.now() - 24 * 60 * 60 * 1000) } } // Clean used codes after 24h
      ]
    });
    
    return result.deletedCount || 0;
  },
};

// Export utilities for testing and management
export const mongoUtils = {
  async disconnect(): Promise<void> {
    await MongoConnection.getInstance().disconnect();
  },
  
  reset(): void {
    MongoConnection.getInstance().reset();
  },
  
  async healthCheck(): Promise<boolean> {
    try {
      const conn = MongoConnection.getInstance();
      const users = await conn.getUsers();
      await users.findOne({}, { projection: { _id: 1 } });
      return true;
    } catch {
      return false;
    }
  },
};