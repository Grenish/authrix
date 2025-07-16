import type { AuthDbAdapter, AuthUser, TwoFactorCode } from "../types/db";

// Dynamic import for pg to avoid build errors when pg is not installed
let Pool: any = null;

async function loadPgPool() {
  if (!Pool) {
    try {
      // Use dynamic import without eval for better bundler compatibility
      const pgModule = await import("pg");
      Pool = pgModule.Pool;
    } catch (error) {
      throw new Error(
        "PostgreSQL adapter requires 'pg' package. Install it with: npm install pg @types/pg"
      );
    }
  }
  return Pool;
}

// Lazy-load pool to avoid connection errors when adapter is not used
let pool: any = null;

// Reset function for testing
export function resetPostgreSQLConnection() {
  if (pool) {
    pool.end();
    pool = null;
  }
}

async function getPool(): Promise<any> {
  if (!pool) {
    const PoolClass = await loadPgPool();
    const connectionString = process.env.DATABASE_URL || process.env.POSTGRESQL_URL;
    
    if (connectionString) {
      // Use connection string
      pool = new PoolClass({
        connectionString,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
      });
    } else {
      // Use individual environment variables
      const config = {
        host: process.env.POSTGRESQL_HOST || process.env.PGHOST || 'localhost',
        port: parseInt(process.env.POSTGRESQL_PORT || process.env.PGPORT || '5432'),
        database: process.env.POSTGRESQL_DATABASE || process.env.PGDATABASE,
        user: process.env.POSTGRESQL_USER || process.env.PGUSER,
        password: process.env.POSTGRESQL_PASSWORD || process.env.PGPASSWORD,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
      };

      if (!config.database || !config.user || !config.password) {
        throw new Error(
          "PostgreSQL configuration missing. Either set DATABASE_URL/POSTGRESQL_URL or provide individual environment variables: " +
          "POSTGRESQL_HOST, POSTGRESQL_PORT, POSTGRESQL_DATABASE, POSTGRESQL_USER, POSTGRESQL_PASSWORD"
        );
      }

      pool = new PoolClass(config);
    }

    // Handle pool errors
    pool.on('error', (err: Error) => {
      console.error('PostgreSQL pool error:', err);
    });
  }
  
  return pool;
}

function getUserTableName(): string {
  return process.env.POSTGRESQL_USER_TABLE || process.env.AUTH_USER_TABLE || "auth_users";
}

function getTwoFactorTableName(): string {
  return process.env.POSTGRESQL_2FA_TABLE || process.env.AUTH_2FA_TABLE || "auth_two_factor_codes";
}

// Initialize database tables
export async function initializePostgreSQLTables() {
  const pool = await getPool();
  const userTable = getUserTableName();
  const twoFactorTable = getTwoFactorTableName();

  try {
    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ${userTable} (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        username VARCHAR(100) UNIQUE,
        first_name VARCHAR(100),
        last_name VARCHAR(100),
        password TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        email_verified BOOLEAN DEFAULT FALSE,
        email_verified_at TIMESTAMP WITH TIME ZONE,
        two_factor_enabled BOOLEAN DEFAULT FALSE,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );
    `);

    // Create indexes for users table
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_${userTable}_email ON ${userTable}(email);
      CREATE INDEX IF NOT EXISTS idx_${userTable}_username ON ${userTable}(username);
      CREATE INDEX IF NOT EXISTS idx_${userTable}_created_at ON ${userTable}(created_at);
    `);

    // Create two-factor codes table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ${twoFactorTable} (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES ${userTable}(id) ON DELETE CASCADE,
        code TEXT NOT NULL,
        hashed_code TEXT NOT NULL,
        type VARCHAR(50) NOT NULL,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        attempts INTEGER DEFAULT 0,
        is_used BOOLEAN DEFAULT FALSE,
        metadata JSONB DEFAULT '{}'::jsonb
      );
    `);

    // Create indexes for two-factor codes table
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_${twoFactorTable}_id ON ${twoFactorTable}(id);
      CREATE INDEX IF NOT EXISTS idx_${twoFactorTable}_user_id ON ${twoFactorTable}(user_id);
      CREATE INDEX IF NOT EXISTS idx_${twoFactorTable}_type ON ${twoFactorTable}(type);
      CREATE INDEX IF NOT EXISTS idx_${twoFactorTable}_expires_at ON ${twoFactorTable}(expires_at);
      CREATE INDEX IF NOT EXISTS idx_${twoFactorTable}_created_at ON ${twoFactorTable}(created_at);
    `);

    console.log('PostgreSQL tables initialized successfully');
  } catch (error) {
    console.error('Error initializing PostgreSQL tables:', error);
    throw error;
  }
}

// Helper function to convert database row to AuthUser
function rowToUser(row: any): AuthUser {
  return {
    id: row.id,
    email: row.email,
    username: row.username,
    firstName: row.first_name,
    lastName: row.last_name,
    password: row.password,
    createdAt: row.created_at,
    emailVerified: row.email_verified,
    emailVerifiedAt: row.email_verified_at,
    twoFactorEnabled: row.two_factor_enabled,
  };
}

// Helper function to convert database row to TwoFactorCode
function rowToTwoFactorCode(row: any): TwoFactorCode {
  return {
    id: row.id,
    userId: row.user_id,
    code: row.code,
    hashedCode: row.hashed_code,
    type: row.type,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
    attempts: row.attempts,
    isUsed: row.is_used,
    metadata: row.metadata || {},
  };
}

export const postgresqlAdapter: AuthDbAdapter = {
  async findUserByEmail(email: string): Promise<AuthUser | null> {
    try {
      const pool = await getPool();
      const tableName = getUserTableName();
      const normalizedEmail = email.toLowerCase().trim();
      
      const result = await pool.query(
        `SELECT * FROM ${tableName} WHERE email = $1 LIMIT 1`,
        [normalizedEmail]
      );

      if (result.rows.length === 0) return null;

      return rowToUser(result.rows[0]);
    } catch (error) {
      // Let configuration errors bubble up
      if (error instanceof Error && error.message.includes('PostgreSQL configuration missing')) {
        throw error;
      }
      console.error("Error finding user by email:", error);
      return null;
    }
  },

  async findUserById(id: string): Promise<AuthUser | null> {
    try {
      const pool = await getPool();
      const tableName = getUserTableName();
      
      const result = await pool.query(
        `SELECT * FROM ${tableName} WHERE id = $1 LIMIT 1`,
        [id]
      );

      if (result.rows.length === 0) return null;

      return rowToUser(result.rows[0]);
    } catch (error) {
      console.error("Error finding user by ID:", error);
      return null;
    }
  },

  async findUserByUsername(username: string): Promise<AuthUser | null> {
    try {
      const pool = await getPool();
      const tableName = getUserTableName();
      const normalizedUsername = username.toLowerCase().trim();
      
      const result = await pool.query(
        `SELECT * FROM ${tableName} WHERE LOWER(username) = $1 LIMIT 1`,
        [normalizedUsername]
      );

      if (result.rows.length === 0) return null;

      return rowToUser(result.rows[0]);
    } catch (error) {
      console.error("Error finding user by username:", error);
      return null;
    }
  },

  async createUser({ email, password, username, firstName, lastName }): Promise<AuthUser> {
    try {
      const pool = await getPool();
      const tableName = getUserTableName();
      const normalizedEmail = email.toLowerCase().trim();
      const normalizedUsername = username ? username.toLowerCase().trim() : null;
      
      // Build dynamic insert query
      const fields = ['email', 'password'];
      const values = [normalizedEmail, password];
      const placeholders = ['$1', '$2'];
      let paramCount = 3;

      if (normalizedUsername) {
        fields.push('username');
        values.push(normalizedUsername);
        placeholders.push(`$${paramCount++}`);
      }

      if (firstName) {
        fields.push('first_name');
        values.push(firstName.trim());
        placeholders.push(`$${paramCount++}`);
      }

      if (lastName) {
        fields.push('last_name');
        values.push(lastName.trim());
        placeholders.push(`$${paramCount++}`);
      }

      const query = `
        INSERT INTO ${tableName} (${fields.join(', ')}) 
        VALUES (${placeholders.join(', ')}) 
        RETURNING *
      `;

      const result = await pool.query(query, values);

      return rowToUser(result.rows[0]);
    } catch (error) {
      console.error("Error creating user:", error);
      if (error instanceof Error) {
        if (error.message.includes('duplicate key') && error.message.includes('email')) {
          throw new Error(`User with email ${email} already exists`);
        }
        if (error.message.includes('duplicate key') && error.message.includes('username')) {
          throw new Error(`Username ${username} is already taken`);
        }
      }
      throw new Error(`Failed to create user: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  },

  async updateUser(id: string, data: Partial<AuthUser>): Promise<AuthUser> {
    try {
      const pool = await getPool();
      const tableName = getUserTableName();
      
      // Build dynamic update query
      const updates: string[] = [];
      const values: any[] = [];
      let paramCount = 1;

      if (data.email !== undefined) {
        updates.push(`email = $${paramCount++}`);
        values.push(data.email.toLowerCase().trim());
      }
      if (data.password !== undefined) {
        updates.push(`password = $${paramCount++}`);
        values.push(data.password);
      }
      if (data.emailVerified !== undefined) {
        updates.push(`email_verified = $${paramCount++}`);
        values.push(data.emailVerified);
      }
      if (data.emailVerifiedAt !== undefined) {
        updates.push(`email_verified_at = $${paramCount++}`);
        values.push(data.emailVerifiedAt);
      }
      if (data.twoFactorEnabled !== undefined) {
        updates.push(`two_factor_enabled = $${paramCount++}`);
        values.push(data.twoFactorEnabled);
      }
      if (data.username !== undefined) {
        updates.push(`username = $${paramCount++}`);
        values.push(data.username ? data.username.toLowerCase().trim() : null);
      }
      if (data.firstName !== undefined) {
        updates.push(`first_name = $${paramCount++}`);
        values.push(data.firstName ? data.firstName.trim() : null);
      }
      if (data.lastName !== undefined) {
        updates.push(`last_name = $${paramCount++}`);
        values.push(data.lastName ? data.lastName.trim() : null);
      }

      if (updates.length === 0) {
        throw new Error('No valid fields to update');
      }

      updates.push(`updated_at = NOW()`);
      values.push(id);

      const query = `
        UPDATE ${tableName} 
        SET ${updates.join(', ')} 
        WHERE id = $${paramCount} 
        RETURNING *
      `;

      const result = await pool.query(query, values);

      if (result.rows.length === 0) {
        throw new Error('User not found');
      }

      return rowToUser(result.rows[0]);
    } catch (error) {
      console.error("Error updating user:", error);
      if (error instanceof Error) {
        if (error.message.includes('duplicate key') && error.message.includes('email')) {
          throw new Error(`Email ${data.email} is already in use`);
        }
        if (error.message.includes('duplicate key') && error.message.includes('username')) {
          throw new Error(`Username ${data.username} is already taken`);
        }
      }
      throw new Error(`Failed to update user: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  },

  async storeTwoFactorCode(code: TwoFactorCode): Promise<void> {
    try {
      const pool = await getPool();
      const tableName = getTwoFactorTableName();
      
      await pool.query(
        `INSERT INTO ${tableName} (id, user_id, code, hashed_code, type, expires_at, attempts, is_used, metadata) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          code.id,
          code.userId,
          code.code,
          code.hashedCode,
          code.type,
          code.expiresAt,
          code.attempts,
          code.isUsed,
          JSON.stringify(code.metadata || {})
        ]
      );
    } catch (error) {
      console.error("Error storing two-factor code:", error);
      throw new Error(`Failed to store two-factor code: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  },

  async getTwoFactorCode(codeId: string): Promise<TwoFactorCode | null> {
    try {
      const pool = await getPool();
      const tableName = getTwoFactorTableName();
      
      const result = await pool.query(
        `SELECT * FROM ${tableName} WHERE id = $1 LIMIT 1`,
        [codeId]
      );

      if (result.rows.length === 0) return null;

      return rowToTwoFactorCode(result.rows[0]);
    } catch (error) {
      console.error("Error getting two-factor code:", error);
      return null;
    }
  },

  async updateTwoFactorCode(codeId: string, updates: Partial<TwoFactorCode>): Promise<void> {
    try {
      const pool = await getPool();
      const tableName = getTwoFactorTableName();
      
      // Build dynamic update query
      const updateFields: string[] = [];
      const values: any[] = [];
      let paramCount = 1;

      if (updates.attempts !== undefined) {
        updateFields.push(`attempts = $${paramCount++}`);
        values.push(updates.attempts);
      }
      if (updates.isUsed !== undefined) {
        updateFields.push(`is_used = $${paramCount++}`);
        values.push(updates.isUsed);
      }
      if (updates.metadata !== undefined) {
        updateFields.push(`metadata = $${paramCount++}`);
        values.push(JSON.stringify(updates.metadata));
      }

      if (updateFields.length === 0) return;

      values.push(codeId);

      const query = `
        UPDATE ${tableName} 
        SET ${updateFields.join(', ')} 
        WHERE id = $${paramCount}
      `;

      await pool.query(query, values);
    } catch (error) {
      console.error("Error updating two-factor code:", error);
      throw new Error(`Failed to update two-factor code: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  },

  async getUserTwoFactorCodes(userId: string, type?: string): Promise<TwoFactorCode[]> {
    try {
      const pool = await getPool();
      const tableName = getTwoFactorTableName();
      
      let query = `SELECT * FROM ${tableName} WHERE user_id = $1`;
      const values: any[] = [userId];

      if (type) {
        query += ` AND type = $2`;
        values.push(type);
      }

      query += ` ORDER BY created_at DESC`;

      const result = await pool.query(query, values);

      return result.rows.map(rowToTwoFactorCode);
    } catch (error) {
      console.error("Error getting user two-factor codes:", error);
      return [];
    }
  },

  async cleanupExpiredTwoFactorCodes(): Promise<number> {
    try {
      const pool = await getPool();
      const tableName = getTwoFactorTableName();
      
      const result = await pool.query(
        `DELETE FROM ${tableName} WHERE expires_at < NOW()`
      );

      return result.rowCount || 0;
    } catch (error) {
      console.error("Error cleaning up expired two-factor codes:", error);
      return 0;
    }
  },
};
