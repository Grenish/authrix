import type { AuthDbAdapter, AuthUser, TwoFactorCode } from "../types/db";
import { MongoClient, ObjectId, Collection } from "mongodb";

let client: MongoClient;
let users: Collection;
let twoFactorCodes: Collection;
let isInitialized = false;

// Reset function for testing
export function resetMongoConnection() {
  isInitialized = false;
  client = null as any;
  users = null as any;
  twoFactorCodes = null as any;
}

async function initMongoConnection() {
  if (!isInitialized) {
    // Read environment variables dynamically
    const MONGO_URI = process.env.MONGO_URI;
    const DB_NAME = process.env.DB_NAME;
    const COLLECTION_NAME = process.env.AUTH_COLLECTION;
    const TWO_FACTOR_COLLECTION = process.env.TWO_FACTOR_COLLECTION || 'two_factor_codes';
    
    if (!MONGO_URI || !DB_NAME || !COLLECTION_NAME) {
      throw new Error('Missing required environment variables: MONGO_URI, DB_NAME, AUTH_COLLECTION');
    }
    client = new MongoClient(MONGO_URI);
    await client.connect();
    const db = client.db(DB_NAME);
    users = db.collection(COLLECTION_NAME);
    twoFactorCodes = db.collection(TWO_FACTOR_COLLECTION);
    
    // Create indexes for better performance
    await users.createIndex({ email: 1 }, { unique: true });
    await users.createIndex({ username: 1 }, { unique: true, sparse: true }); // sparse allows null values
    await twoFactorCodes.createIndex({ id: 1 }, { unique: true });
    await twoFactorCodes.createIndex({ userId: 1 });
    await twoFactorCodes.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
    await twoFactorCodes.createIndex({ type: 1 });
    
    isInitialized = true;
  }
}

async function ensureConnection() {
  if (!isInitialized) {
    await initMongoConnection();
  }
}

export const mongoAdapter: AuthDbAdapter = {
  async findUserByEmail(email: string): Promise<AuthUser | null> {
    await ensureConnection();
    const user = await users.findOne({ email: email.toLowerCase().trim() });
    if (!user) return null;

    return {
      id: user._id.toString(),
      email: user.email,
      password: user.password,
      createdAt: user.createdAt,
      emailVerified: user.emailVerified || false,
      emailVerifiedAt: user.emailVerifiedAt,
      twoFactorEnabled: user.twoFactorEnabled || false,
      username: user.username || undefined,
      firstName: user.firstName || undefined,
      lastName: user.lastName || undefined,
    };
  },

  async findUserById(id: string): Promise<AuthUser | null> {
    await ensureConnection();
    if (!ObjectId.isValid(id)) return null;

    const user = await users.findOne({ _id: new ObjectId(id) });
    if (!user) return null;

    return {
      id: user._id.toString(),
      email: user.email,
      password: user.password,
      createdAt: user.createdAt,
      emailVerified: user.emailVerified || false,
      emailVerifiedAt: user.emailVerifiedAt,
      twoFactorEnabled: user.twoFactorEnabled || false,
      username: user.username || undefined,
      firstName: user.firstName || undefined,
      lastName: user.lastName || undefined,
    };
  },

  async createUser({ email, password, username, firstName, lastName }): Promise<AuthUser> {
    await ensureConnection();
    const normalizedEmail = email.toLowerCase().trim();
    const normalizedUsername = username ? username.toLowerCase().trim() : undefined;
    const now = new Date();

    try {
      const insertData: any = {
        email: normalizedEmail,
        password,
        createdAt: now,
        emailVerified: false,
        emailVerifiedAt: undefined,
        twoFactorEnabled: false,
      };

      if (normalizedUsername) {
        insertData.username = normalizedUsername;
      }
      if (firstName) {
        insertData.firstName = firstName.trim();
      }
      if (lastName) {
        insertData.lastName = lastName.trim();
      }

      const result = await users.insertOne(insertData);

      return {
        id: result.insertedId.toString(),
        email: normalizedEmail,
        password,
        createdAt: now,
        emailVerified: false,
        emailVerifiedAt: undefined,
        twoFactorEnabled: false,
        username: normalizedUsername,
        firstName: firstName ? firstName.trim() : undefined,
        lastName: lastName ? lastName.trim() : undefined,
      };
    } catch (error: any) {
      if (error.code === 11000) { // MongoDB duplicate key error
        if (error.message.includes('email')) {
          throw new Error(`User with email ${email} already exists`);
        }
        if (error.message.includes('username')) {
          throw new Error(`Username ${username} is already taken`);
        }
      }
      throw new Error(`Failed to create user: ${error.message}`);
    }
  },

  async updateUser(id: string, data: Partial<AuthUser>): Promise<AuthUser> {
    await ensureConnection();
    if (!ObjectId.isValid(id)) {
      throw new Error("Invalid user ID");
    }

    const updateData = { ...data };
    delete updateData.id; // Remove id from update data
    delete updateData.createdAt; // Don't allow updating createdAt

    // Normalize fields
    if (updateData.email) {
      updateData.email = updateData.email.toLowerCase().trim();
    }
    if (updateData.username !== undefined) {
      updateData.username = updateData.username ? updateData.username.toLowerCase().trim() : undefined;
    }
    if (updateData.firstName !== undefined) {
      updateData.firstName = updateData.firstName ? updateData.firstName.trim() : undefined;
    }
    if (updateData.lastName !== undefined) {
      updateData.lastName = updateData.lastName ? updateData.lastName.trim() : undefined;
    }

    try {
      const result = await users.findOneAndUpdate(
        { _id: new ObjectId(id) },
        { $set: updateData },
        { returnDocument: 'after' }
      );

      if (!result || !result.value) {
        throw new Error("User not found");
      }

      return {
        id: result.value._id.toString(),
        email: result.value.email,
        password: result.value.password,
        createdAt: result.value.createdAt,
        emailVerified: result.value.emailVerified || false,
        emailVerifiedAt: result.value.emailVerifiedAt,
        twoFactorEnabled: result.value.twoFactorEnabled || false,
        username: result.value.username || undefined,
        firstName: result.value.firstName || undefined,
        lastName: result.value.lastName || undefined,
      };
    } catch (error: any) {
      if (error.code === 11000) { // MongoDB duplicate key error
        if (error.message.includes('email')) {
          throw new Error(`Email ${data.email} is already in use`);
        }
        if (error.message.includes('username')) {
          throw new Error(`Username ${data.username} is already taken`);
        }
      }
      throw error;
    }
  },

  async findUserByUsername(username: string): Promise<AuthUser | null> {
    await ensureConnection();
    const normalizedUsername = username.toLowerCase().trim();
    const user = await users.findOne({ username: normalizedUsername });
    if (!user) return null;

    return {
      id: user._id.toString(),
      email: user.email,
      password: user.password,
      createdAt: user.createdAt,
      emailVerified: user.emailVerified || false,
      emailVerifiedAt: user.emailVerifiedAt,
      twoFactorEnabled: user.twoFactorEnabled || false,
      username: user.username || undefined,
      firstName: user.firstName || undefined,
      lastName: user.lastName || undefined,
    };
  },

  async storeTwoFactorCode(code: TwoFactorCode): Promise<void> {
    await ensureConnection();
    await twoFactorCodes.insertOne(code);
  },

  async getTwoFactorCode(codeId: string): Promise<TwoFactorCode | null> {
    await ensureConnection();
    const code = await twoFactorCodes.findOne({ id: codeId });
    return code ? (code as unknown as TwoFactorCode) : null;
  },

  async updateTwoFactorCode(codeId: string, updates: Partial<TwoFactorCode>): Promise<void> {
    await ensureConnection();
    await twoFactorCodes.updateOne(
      { id: codeId },
      { $set: updates }
    );
  },

  async getUserTwoFactorCodes(userId: string, type?: string): Promise<TwoFactorCode[]> {
    await ensureConnection();
    const query: any = { userId, isUsed: false };
    if (type) {
      query.type = type;
    }
    
    const codes = await twoFactorCodes.find(query).toArray();
    return codes as unknown as TwoFactorCode[];
  },

  async cleanupExpiredTwoFactorCodes(): Promise<number> {
    await ensureConnection();
    const result = await twoFactorCodes.deleteMany({
      expiresAt: { $lt: new Date() }
    });
    return result.deletedCount || 0;
  },
};
