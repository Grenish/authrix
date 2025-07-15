# PostgreSQL Adapter for Authrix

The PostgreSQL adapter provides a robust database backend for Authrix authentication system with full support for user management and 2FA email verification.

## Installation

```bash
npm install pg @types/pg
```

## Configuration

### Environment Variables

You can configure PostgreSQL connection using either a connection string or individual parameters:

#### Option 1: Connection String (Recommended)
```env
DATABASE_URL=postgresql://username:password@host:port/database
# OR
POSTGRESQL_URL=postgresql://username:password@host:port/database
```

#### Option 2: Individual Parameters
```env
POSTGRESQL_HOST=localhost
POSTGRESQL_PORT=5432
POSTGRESQL_DATABASE=your_database
POSTGRESQL_USER=your_username
POSTGRESQL_PASSWORD=your_password

# Standard PostgreSQL environment variables are also supported:
PGHOST=localhost
PGPORT=5432
PGDATABASE=your_database
PGUSER=your_username
PGPASSWORD=your_password
```

#### Optional Configuration
```env
# Custom table names (optional)
POSTGRESQL_USER_TABLE=auth_users
POSTGRESQL_2FA_TABLE=auth_two_factor_codes
# OR
AUTH_USER_TABLE=auth_users
AUTH_2FA_TABLE=auth_two_factor_codes
```

### SSL Configuration

- **Development**: SSL is disabled by default
- **Production**: SSL is enabled with `{ rejectUnauthorized: false }` for cloud databases

## Setup

### 1. Initialize Database Tables

```typescript
import { initializePostgreSQLTables } from 'authrix/adapters';

// Initialize tables before using the adapter
await initializePostgreSQLTables();
```

### 2. Use the Adapter

```typescript
import { postgresqlAdapter } from 'authrix/adapters';

// For basic auth
const auth = new AuthService({
  adapter: postgresqlAdapter,
  // ...other config
});

// For 2FA with email verification
import { TwoFactorService } from 'authrix/core/twoFactor';
import { getEmailService } from './email-service';

const twoFactorService = new TwoFactorService(getEmailService(), {
  adapter: postgresqlAdapter
});
```

## Database Schema

The adapter automatically creates these tables:

### Users Table (`auth_users`)

```sql
CREATE TABLE auth_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  email_verified BOOLEAN DEFAULT FALSE,
  email_verified_at TIMESTAMP WITH TIME ZONE,
  two_factor_enabled BOOLEAN DEFAULT FALSE,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_auth_users_email ON auth_users(email);
CREATE INDEX idx_auth_users_created_at ON auth_users(created_at);
```

### Two-Factor Codes Table (`auth_two_factor_codes`)

```sql
CREATE TABLE auth_two_factor_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth_users(id) ON DELETE CASCADE,
  code TEXT NOT NULL,
  hashed_code TEXT NOT NULL,
  type VARCHAR(50) NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  attempts INTEGER DEFAULT 0,
  is_used BOOLEAN DEFAULT FALSE,
  metadata JSONB DEFAULT '{}'::jsonb
);

-- Indexes
CREATE INDEX idx_auth_two_factor_codes_id ON auth_two_factor_codes(id);
CREATE INDEX idx_auth_two_factor_codes_user_id ON auth_two_factor_codes(user_id);
CREATE INDEX idx_auth_two_factor_codes_type ON auth_two_factor_codes(type);
CREATE INDEX idx_auth_two_factor_codes_expires_at ON auth_two_factor_codes(expires_at);
CREATE INDEX idx_auth_two_factor_codes_created_at ON auth_two_factor_codes(created_at);
```

## Features

### ✅ Core Authentication
- User registration and login
- Email uniqueness enforcement
- Password storage
- User lookup by email and ID

### ✅ Email Verification & 2FA
- Store and verify 2FA codes
- Code expiration handling
- Attempt limiting (security)
- Metadata storage (IP, user agent, etc.)
- Automatic cleanup of expired codes

### ✅ User Management
- Update user information
- Email verification status
- Two-factor authentication enablement
- Timestamps for audit trails

### ✅ Production Ready
- Connection pooling
- SSL support for production
- Comprehensive error handling
- SQL injection prevention
- Proper indexing for performance

## Complete Setup Example

### 1. Environment Configuration

```env
# .env.local
DATABASE_URL=postgresql://username:password@localhost:5432/authrix_db

# Optional custom table names
AUTH_USER_TABLE=users
AUTH_2FA_TABLE=verification_codes
```

### 2. Database Initialization

```typescript
// lib/database.ts
import { initializePostgreSQLTables } from 'authrix/adapters';

export async function initializeDatabase() {
  try {
    await initializePostgreSQLTables();
    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Database initialization failed:', error);
    throw error;
  }
}
```

### 3. Authentication Service Setup

```typescript
// lib/auth.ts
import { AuthService } from 'authrix';
import { postgresqlAdapter } from 'authrix/adapters';

export const authService = new AuthService({
  adapter: postgresqlAdapter,
  jwtSecret: process.env.JWT_SECRET!,
  // ...other config
});
```

### 4. Next.js API Route Example

```typescript
// app/api/auth/signup/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { postgresqlAdapter } from 'authrix/adapters';
import { TwoFactorService } from 'authrix/core/twoFactor';
import { getEmailService } from '@/lib/email-service';
import bcrypt from 'bcryptjs';

export async function POST(request: NextRequest) {
  try {
    const { email, password, name } = await request.json();

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = await postgresqlAdapter.createUser({
      email,
      password: hashedPassword
    });

    // Send verification email
    const twoFactorService = new TwoFactorService(getEmailService(), {
      adapter: postgresqlAdapter
    });
    
    await twoFactorService.sendVerificationCode(email, 'email_verification');

    return NextResponse.json({
      success: true,
      message: 'Account created. Please check your email for verification.'
    });

  } catch (error) {
    console.error('Signup error:', error);
    return NextResponse.json(
      { error: 'Failed to create account' },
      { status: 500 }
    );
  }
}
```

## Connection Management

### Connection Pooling
The adapter uses PostgreSQL connection pooling for optimal performance:

```typescript
// Automatic connection management
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Pool automatically manages connections
});
```

### Cleanup (Testing)
For testing environments, you can reset connections:

```typescript
import { resetPostgreSQLConnection } from 'authrix/adapters';

// Reset connection (useful for testing)
resetPostgreSQLConnection();
```

## Error Handling

The adapter provides comprehensive error handling:

- **Configuration errors**: Thrown immediately if required environment variables are missing
- **Connection errors**: Logged and handled gracefully
- **Query errors**: Detailed error messages with context
- **Constraint violations**: Proper error messages for duplicate emails, etc.

## Performance Considerations

1. **Indexes**: All frequently queried fields are indexed
2. **Connection Pooling**: Efficient connection reuse
3. **Prepared Statements**: Protection against SQL injection
4. **Cleanup Jobs**: Automatic cleanup of expired 2FA codes
5. **UUID Primary Keys**: Better performance for distributed systems

## Migration from Other Adapters

### From Firebase/Supabase
1. Export your existing user data
2. Transform the data to match PostgreSQL schema
3. Import using standard PostgreSQL tools
4. Update your application configuration

### Data Transformation Example
```sql
-- Transform existing data to PostgreSQL format
INSERT INTO auth_users (email, password, created_at, email_verified)
SELECT 
  email,
  password,
  created_at,
  email_verified
FROM your_existing_users_table;
```

## Troubleshooting

### Common Issues

1. **"PostgreSQL adapter requires 'pg' package"**
   ```bash
   npm install pg @types/pg
   ```

2. **"PostgreSQL configuration missing"**
   - Set `DATABASE_URL` or individual connection parameters
   - Verify database exists and credentials are correct

3. **SSL Connection Issues**
   - For local development, SSL is disabled automatically
   - For production, ensure your database supports SSL

4. **Permission Errors**
   - Ensure database user has CREATE, SELECT, INSERT, UPDATE, DELETE permissions
   - For table creation, user needs CREATE permissions

### Debug Mode

Enable PostgreSQL query logging:

```env
NODE_ENV=development
DEBUG=true
```

This will log all SQL queries for debugging purposes.

## Security Features

1. **SQL Injection Prevention**: Parameterized queries
2. **Password Security**: Never logs or exposes passwords
3. **Connection Security**: SSL enforcement in production
4. **Rate Limiting Ready**: Database queries optimized for rate limiting
5. **Audit Trail**: Comprehensive timestamps and metadata
6. **Automatic Cleanup**: Expired codes are automatically removed

## Production Deployment

### Cloud Database Recommendations

1. **AWS RDS PostgreSQL**
2. **Google Cloud SQL for PostgreSQL**
3. **Azure Database for PostgreSQL**
4. **Heroku Postgres**
5. **DigitalOcean Managed Databases**

### Production Configuration

```env
# Production example
DATABASE_URL=postgresql://user:pass@prod-db.amazonaws.com:5432/authrix
NODE_ENV=production

# Table names for production
AUTH_USER_TABLE=users
AUTH_2FA_TABLE=verification_codes
```

The PostgreSQL adapter is production-ready and provides enterprise-grade features for authentication and user management.
