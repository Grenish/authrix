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
  authMethod?: 'password' | 'sso';
  authProvider?: string;
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
  retryConnect?: boolean;
  retryAttempts?: number;
  };
}

// Runtime configuration override (takes precedence over env when set)
type ConnectionOverride = Partial<ConnectionConfig>;
let mongoConfigOverride: ConnectionOverride | null = null;
let warnedMongoDbAlias = false;

/**
 * Parse a MongoDB URI to extract dbName if present.
 * Supports mongodb:// and mongodb+srv:// forms.
 */
export function parseMongoUri(uri: string): { dbName?: string } {
  try {
    // Use URL for simple extraction; fallback to regex when needed
    const u = new URL(uri);
    const path = u.pathname || "";
    if (path && path !== "/") {
      const name = path.replace(/^\//, "");
      if (name) return { dbName: decodeURIComponent(name) };
    }
  } catch {
    // Fallback regex extraction
    const m = uri.match(/^mongodb(?:\+srv)?:\/\/[^/]+\/([^?]+)/i);
    if (m && m[1]) return { dbName: decodeURIComponent(m[1]) };
  }
  return {};
}

/**
 * Configure a global adapter override without mutating process.env.
 * The env-driven mongoAdapter will honor this when present.
 */
export function configureMongoAdapter(opts: ConnectionOverride): void {
  mongoConfigOverride = { ...(mongoConfigOverride || {}), ...opts };
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
  private static indexSignatureCreated = new Set<string>();

  private constructor() {}

  static getInstance(): MongoConnection {
    if (!this.instance) {
      this.instance = new MongoConnection();
    }
    return this.instance;
  }

  private loadConfig(): ConnectionConfig {
    if (this.config) return this.config;

    // Prefer override if provided, else env
    let uri = mongoConfigOverride?.uri || process.env.MONGO_URI;
    let dbName = mongoConfigOverride?.dbName || process.env.DB_NAME;
    const legacyDb = process.env.MONGO_DB;
    const authCollection = mongoConfigOverride?.authCollection || process.env.AUTH_COLLECTION || 'users';
    const twoFactorCollection = mongoConfigOverride?.twoFactorCollection || process.env.TWO_FACTOR_COLLECTION || 'two_factor_codes';

    // Accept legacy alias MONGO_DB with one-time warning
    if (!dbName && legacyDb) {
      dbName = legacyDb;
      if (!warnedMongoDbAlias) {
        try { console.warn('[Authrix][Mongo] MONGO_DB is deprecated. Use DB_NAME instead.'); } catch {}
        warnedMongoDbAlias = true;
      }
    }

    // If dbName missing but URI contains a path, infer it
    if (!dbName && uri) {
      const parsed = parseMongoUri(uri);
      if (parsed.dbName) dbName = parsed.dbName;
    }

    if (!uri || !dbName) {
      const missing = [!uri && 'MONGO_URI', !dbName && 'DB_NAME'].filter(Boolean).join(', ');
      const envPresence = {
        MONGO_URI: typeof process?.env?.MONGO_URI !== 'undefined',
        DB_NAME: typeof process?.env?.DB_NAME !== 'undefined',
        NEXT_RUNTIME: process?.env?.NEXT_RUNTIME || undefined
      } as const;
      const nextHint = 'Next.js tip: If using App Router, add `export const runtime = "nodejs"` to route files or include the database in the URI path (mongodb://host:port/mydb).';
      throw new Error(
        'Missing required MongoDB configuration: ' + missing + '\n' +
        'Provide via environment (MONGO_URI, DB_NAME) or configure at runtime.\n' +
        'Example (env): MONGO_URI=mongodb://127.0.0.1:27017, DB_NAME=authrix_next\n' +
        'Example (factory): createMongoAdapter({ uri: "mongodb://127.0.0.1:27017/mydb" })\n' +
        `[Env presence] MONGO_URI: ${envPresence.MONGO_URI}, DB_NAME: ${envPresence.DB_NAME}, NEXT_RUNTIME: ${envPresence.NEXT_RUNTIME || 'n/a'}\n` +
        nextHint
      );
    }

    // Auto-tune Atlas / TLS friendly defaults when using mongodb+srv unless user overrides
    const isSrv = uri.startsWith('mongodb+srv://');
    if (isSrv) {
      process.env.MONGO_MAX_POOL_SIZE = process.env.MONGO_MAX_POOL_SIZE || '10';
      process.env.MONGO_MIN_POOL_SIZE = process.env.MONGO_MIN_POOL_SIZE || '2';
      process.env.MONGO_SOCKET_TIMEOUT = process.env.MONGO_SOCKET_TIMEOUT || '30000';
      process.env.MONGO_SERVER_SELECTION_TIMEOUT = process.env.MONGO_SERVER_SELECTION_TIMEOUT || '5000';
    }

    this.config = {
      uri,
      dbName,
      authCollection,
      twoFactorCollection,
      options: {
        maxPoolSize: mongoConfigOverride?.options?.maxPoolSize ?? parseInt(process.env.MONGO_MAX_POOL_SIZE || '10'),
        minPoolSize: mongoConfigOverride?.options?.minPoolSize ?? parseInt(process.env.MONGO_MIN_POOL_SIZE || '2'),
        socketTimeoutMS: mongoConfigOverride?.options?.socketTimeoutMS ?? parseInt(process.env.MONGO_SOCKET_TIMEOUT || '30000'),
        serverSelectionTimeoutMS: mongoConfigOverride?.options?.serverSelectionTimeoutMS ?? parseInt(process.env.MONGO_SERVER_SELECTION_TIMEOUT || '5000'),
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
      const tlsOptions: any = {};
      if (config.uri.startsWith('mongodb+srv://')) {
        // Let driver manage SRV records; optionally enable retryable writes if not set
        tlsOptions.retryWrites = true;
      }
      this.client = new MongoClient(config.uri, {
        maxPoolSize: config.options?.maxPoolSize,
        minPoolSize: config.options?.minPoolSize,
        socketTimeoutMS: config.options?.socketTimeoutMS,
        serverSelectionTimeoutMS: config.options?.serverSelectionTimeoutMS,
        ...tlsOptions
      });
      // Optional retry with simple backoff
      const attempts = config.options?.retryConnect ? (config.options?.retryAttempts || 3) : 1;
      let connectErr: any = null;
      for (let i = 1; i <= attempts; i++) {
        try {
          await this.client.connect();
          connectErr = null;
          break;
        } catch (e) {
          connectErr = e;
          if (i < attempts) {
            await new Promise(r => setTimeout(r, 200 * i));
          }
        }
      }
      if (connectErr) {
        const msg = connectErr instanceof Error ? connectErr.message : String(connectErr);
        const srvHint = config.uri.startsWith('mongodb+srv://') ? ' Hint: For mongodb+srv, verify DNS/TLS and IP allowlist.' : '';
        throw new Error(`Connect failed after ${attempts} attempt(s): ${msg}.${srvHint}`);
      }
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
  // Prevent duplicate index creation work across reloads
  const cfg = this.loadConfig();
  const signature = `${cfg.dbName}|${cfg.authCollection}|${cfg.twoFactorCollection}`;
  if (MongoConnection.indexSignatureCreated.has(signature)) return;
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
  MongoConnection.indexSignatureCreated.add(signature);
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
  authMethod: user.authMethod,
  authProvider: user.authProvider,
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
          authMethod: 1,
          authProvider: 1,
        }
      }
    );

    return user && user._id ? mongoUserToAuthUser(user as MongoUser & { _id: ObjectId }) : null;
  },
  // Alias method for docs compatibility
  async getUserByEmail(email: string): Promise<AuthUser | null> {
    return this.findUserByEmail(email);
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
          authMethod: 1,
          authProvider: 1,
        }
      }
    );

    return user && user._id ? mongoUserToAuthUser(user as MongoUser & { _id: ObjectId }) : null;
  },

  async createUser({ email, password, username, firstName, lastName, fullName, profilePicture, authMethod, authProvider }): Promise<AuthUser> {
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
  authMethod,
  authProvider,
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
  authMethod,
  authProvider,
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

/**
 * Create a Mongo adapter with explicit options (no env required).
 * If dbName is omitted but present in the URI path, it will be inferred.
 */
export function createMongoAdapter(options: Partial<ConnectionConfig> & { uri?: string; dbName?: string }): AuthDbAdapter {
  // Prefer explicit options; fallback to env when omitted
  const envUri = process.env.MONGO_URI;
  const uri = options.uri || envUri;
  if (!uri) {
    throw new Error(
      "createMongoAdapter called without uri and MONGO_URI not set. " +
      "Next.js tip: ensure route handlers run on Node (export const runtime = 'nodejs') and .env.local is at the project root."
    );
  }

  // Resolve dbName: explicit > inferred from URI path > env DB_NAME
  const inferred = !options.dbName ? parseMongoUri(uri) : {};
  const dbName = options.dbName || inferred.dbName || process.env.DB_NAME;

  // Build override without undefineds
  const override: ConnectionOverride = { uri };
  if (dbName) override.dbName = dbName;
  if (options.authCollection) override.authCollection = options.authCollection;
  if (options.twoFactorCollection) override.twoFactorCollection = options.twoFactorCollection;
  if (options.options) override.options = options.options;

  // Set a scoped override and return the same adapter object;
  // MongoConnection is a singleton so subsequent calls reuse it.
  configureMongoAdapter(override);
  return mongoAdapter;
}

/** Small wrapper returning richer health info */
export async function healthCheckMongo(): Promise<{ ok: boolean; message?: string }> {
  try {
    const ok = await mongoUtils.healthCheck();
    return ok ? { ok: true } : { ok: false, message: 'Query failed' };
  } catch (e: any) {
    return { ok: false, message: e?.message || 'Unknown error' };
  }
}