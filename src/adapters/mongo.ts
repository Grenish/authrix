import type { AuthDbAdapter, AuthUser } from "../types/db";
import { MongoClient, ObjectId, Collection } from "mongodb";

// Read from environment
const MONGO_URI = process.env.MONGO_URI;
const DB_NAME = process.env.DB_NAME;
const COLLECTION_NAME = process.env.AUTH_COLLECTION;

let client: MongoClient;
let users: Collection;
let isInitialized = false;

async function initMongoConnection() {
  if (!isInitialized) {
    if (!MONGO_URI || !DB_NAME || !COLLECTION_NAME) {
      throw new Error('Missing required environment variables: MONGO_URI, DB_NAME, AUTH_COLLECTION');
    }
    client = new MongoClient(MONGO_URI);
    await client.connect();
    users = client.db(DB_NAME).collection(COLLECTION_NAME);
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
    };
  },

  async createUser({ email, password }) {
    await ensureConnection();
    const normalizedEmail = email.toLowerCase().trim();
    const now = new Date();

    const result = await users.insertOne({
      email: normalizedEmail,
      password,
      createdAt: now,
    });

    return {
      id: result.insertedId.toString(),
      email: normalizedEmail,
      password,
      createdAt: now,
    };
  },
};
