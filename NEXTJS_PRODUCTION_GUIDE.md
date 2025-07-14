# Next.js Production Guide

> Comprehensive guide for deploying Authrix-powered Next.js applications to production with best practices, security considerations, and platform-specific configurations.

## Table of Contents

- [Pre-Production Checklist](#pre-production-checklist)
- [Environment Configuration](#environment-configuration)
- [Security Hardening](#security-hardening)
- [Performance Optimization](#performance-optimization)
- [Database Configuration](#database-configuration)
- [Deployment Platforms](#deployment-platforms)
- [Monitoring and Logging](#monitoring-and-logging)
- [Troubleshooting](#troubleshooting)
- [Maintenance](#maintenance)

## Pre-Production Checklist

### ✅ Security Checklist

- [ ] Strong JWT secret (32+ characters, random)
- [ ] HTTPS enabled in production
- [ ] Secure cookie settings configured
- [ ] Environment variables properly secured
- [ ] Rate limiting implemented
- [ ] Input validation on all endpoints
- [ ] OAuth redirect URIs verified
- [ ] Database credentials secured
- [ ] Error handling doesn't expose sensitive data
- [ ] Content Security Policy configured

### ✅ Performance Checklist

- [ ] Database connections optimized
- [ ] Caching strategy implemented
- [ ] Bundle size analyzed and optimized
- [ ] Edge Runtime used where appropriate
- [ ] Static generation enabled for public pages
- [ ] Image optimization configured
- [ ] Database queries optimized
- [ ] CDN configured for assets

### ✅ Functionality Checklist

- [ ] All authentication flows tested
- [ ] OAuth providers working correctly
- [ ] Password reset functionality tested
- [ ] Session management verified
- [ ] Error pages customized
- [ ] Email notifications configured
- [ ] Database migrations completed
- [ ] Backup strategy implemented

## Environment Configuration

### Production Environment Variables

Create a comprehensive `.env.production` file:

```env
# Application
NODE_ENV=production
NEXTAUTH_URL=https://yourdomain.com
NEXTAUTH_SECRET=your-32-char-random-secret-here

# Authrix Configuration
JWT_SECRET=your-super-secure-jwt-secret-key-minimum-32-characters
AUTH_COOKIE_NAME=secure_auth_token
JWT_EXPIRES_IN=24h

# Database (choose one)
# MongoDB
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/production_db?retryWrites=true&w=majority

# Supabase
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-production-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key

# Firebase
FIREBASE_PROJECT_ID=your-production-project-id
FIREBASE_CLIENT_EMAIL=your-service-account-email
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nYour private key here\n-----END PRIVATE KEY-----"

# OAuth Providers (if using)
GOOGLE_CLIENT_ID=your-production-google-client-id
GOOGLE_CLIENT_SECRET=your-production-google-client-secret
GITHUB_CLIENT_ID=your-production-github-client-id
GITHUB_CLIENT_SECRET=your-production-github-client-secret

# Email Configuration
SMTP_HOST=smtp.yourdomain.com
SMTP_PORT=587
SMTP_USER=noreply@yourdomain.com
SMTP_PASS=your-email-password
FROM_EMAIL=noreply@yourdomain.com

# External APIs
EXTERNAL_API_KEY=your-production-api-key

# Monitoring
SENTRY_DSN=https://your-sentry-dsn
ANALYTICS_ID=your-analytics-id

# Rate Limiting
REDIS_URL=redis://username:password@redis-host:6379
```

### Environment Variable Validation

```typescript
// lib/env.ts
import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']),
  NEXTAUTH_URL: z.string().url(),
  JWT_SECRET: z.string().min(32),
  
  // Database (at least one required)
  MONGODB_URI: z.string().optional(),
  SUPABASE_URL: z.string().url().optional(),
  FIREBASE_PROJECT_ID: z.string().optional(),
  
  // OAuth (optional)
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  GITHUB_CLIENT_ID: z.string().optional(),
  GITHUB_CLIENT_SECRET: z.string().optional(),
}).refine(
  (data) => data.MONGODB_URI || data.SUPABASE_URL || data.FIREBASE_PROJECT_ID,
  {
    message: "At least one database configuration is required",
    path: ["database"]
  }
);

export const env = envSchema.parse(process.env);
```

### Next.js Configuration

```javascript
// next.config.js
/** @type {import('next').NextConfig} */
const nextConfig = {
  // Enable experimental features for production
  experimental: {
    serverComponentsExternalPackages: ['authrix'],
  },
  
  // Security headers
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'X-Frame-Options',
            value: 'DENY'
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff'
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin'
          },
          {
            key: 'X-XSS-Protection',
            value: '1; mode=block'
          },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains'
          }
        ]
      }
    ];
  },
  
  // Redirect HTTP to HTTPS in production
  async redirects() {
    if (process.env.NODE_ENV === 'production') {
      return [
        {
          source: '/(.*)',
          has: [
            {
              type: 'header',
              key: 'x-forwarded-proto',
              value: 'http'
            }
          ],
          destination: 'https://yourdomain.com/:path*',
          permanent: true
        }
      ];
    }
    return [];
  },
  
  // Optimize images
  images: {
    domains: ['yourdomain.com', 'cdn.yourdomain.com'],
    formats: ['image/webp', 'image/avif'],
  },
  
  // Optimize bundle
  webpack: (config, { isServer }) => {
    if (!isServer) {
      // Reduce client bundle size
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false,
        net: false,
        tls: false,
      };
    }
    return config;
  },
  
  // Enable static optimization
  output: 'standalone',
  
  // Configure runtime for different routes
  experimental: {
    runtime: 'nodejs',
  }
};

module.exports = nextConfig;
```

## Security Hardening

### Authentication Configuration

```typescript
// lib/auth-config.ts
import { initAuth } from 'authrix';
import { mongoAdapter } from 'authrix/adapters/mongo';

const isProduction = process.env.NODE_ENV === 'production';

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter,
  cookieName: process.env.AUTH_COOKIE_NAME || 'auth_token',
  jwtOptions: {
    expiresIn: process.env.JWT_EXPIRES_IN || '24h',
    issuer: process.env.NEXTAUTH_URL,
    audience: process.env.NEXTAUTH_URL,
  },
  cookieOptions: {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    path: '/',
    domain: isProduction ? '.yourdomain.com' : undefined,
  },
  passwordRequirements: {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
  }
});
```

### Rate Limiting

```typescript
// lib/rate-limit.ts
import { NextRequest } from 'next/server';

interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  keyGenerator?: (req: NextRequest) => string;
}

class RateLimiter {
  private store = new Map<string, { count: number; resetTime: number }>();
  
  constructor(private config: RateLimitConfig) {}
  
  async check(req: NextRequest): Promise<{ allowed: boolean; remaining: number }> {
    const key = this.config.keyGenerator 
      ? this.config.keyGenerator(req)
      : this.getDefaultKey(req);
    
    const now = Date.now();
    const record = this.store.get(key);
    
    if (!record || now > record.resetTime) {
      this.store.set(key, {
        count: 1,
        resetTime: now + this.config.windowMs
      });
      return { allowed: true, remaining: this.config.maxRequests - 1 };
    }
    
    if (record.count >= this.config.maxRequests) {
      return { allowed: false, remaining: 0 };
    }
    
    record.count++;
    return { 
      allowed: true, 
      remaining: this.config.maxRequests - record.count 
    };
  }
  
  private getDefaultKey(req: NextRequest): string {
    return req.ip || req.headers.get('x-forwarded-for') || 'unknown';
  }
}

// Different rate limits for different endpoints
export const authRateLimit = new RateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 5, // 5 login attempts per 15 minutes
  keyGenerator: (req) => `auth:${req.ip}:${req.nextUrl.pathname}`
});

export const apiRateLimit = new RateLimiter({
  windowMs: 60 * 1000, // 1 minute
  maxRequests: 100, // 100 requests per minute
});

export const strictRateLimit = new RateLimiter({
  windowMs: 60 * 1000, // 1 minute
  maxRequests: 10, // 10 requests per minute for sensitive endpoints
});
```

### Input Validation and Sanitization

```typescript
// lib/validation.ts
import { z } from 'zod';
import validator from 'validator';

export const authSchemas = {
  signup: z.object({
    email: z.string()
      .email('Invalid email format')
      .max(254, 'Email too long')
      .transform(email => validator.normalizeEmail(email) || email),
    password: z.string()
      .min(8, 'Password must be at least 8 characters')
      .max(128, 'Password too long')
      .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, 
        'Password must contain uppercase, lowercase, number, and special character'),
    name: z.string()
      .min(1, 'Name is required')
      .max(100, 'Name too long')
      .transform(name => validator.escape(name))
      .optional(),
  }),
  
  signin: z.object({
    email: z.string()
      .email('Invalid email format')
      .transform(email => validator.normalizeEmail(email) || email),
    password: z.string()
      .min(1, 'Password is required')
      .max(128, 'Password too long'),
  }),
  
  updateProfile: z.object({
    name: z.string()
      .max(100, 'Name too long')
      .transform(name => validator.escape(name))
      .optional(),
    bio: z.string()
      .max(500, 'Bio too long')
      .transform(bio => validator.escape(bio))
      .optional(),
  })
};

export function validateRequest<T>(
  data: unknown, 
  schema: z.ZodSchema<T>
): { success: true; data: T } | { success: false; errors: string[] } {
  try {
    const validData = schema.parse(data);
    return { success: true, data: validData };
  } catch (error) {
    if (error instanceof z.ZodError) {
      return { 
        success: false, 
        errors: error.errors.map(e => e.message) 
      };
    }
    return { 
      success: false, 
      errors: ['Validation failed'] 
    };
  }
}
```

### Security Middleware

```typescript
// middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import { checkAuthMiddleware } from 'authrix/nextjs';
import { authRateLimit, apiRateLimit } from './lib/rate-limit';

export async function middleware(request: NextRequest) {
  const response = NextResponse.next();
  
  // Security headers
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-XSS-Protection', '1; mode=block');
  
  // Rate limiting
  if (request.nextUrl.pathname.startsWith('/api/auth/')) {
    const rateLimitResult = await authRateLimit.check(request);
    if (!rateLimitResult.allowed) {
      return NextResponse.json(
        { error: 'Too many requests' },
        { status: 429 }
      );
    }
    response.headers.set('X-RateLimit-Remaining', rateLimitResult.remaining.toString());
  } else if (request.nextUrl.pathname.startsWith('/api/')) {
    const rateLimitResult = await apiRateLimit.check(request);
    if (!rateLimitResult.allowed) {
      return NextResponse.json(
        { error: 'Too many requests' },
        { status: 429 }
      );
    }
  }
  
  // Authentication for protected routes
  if (request.nextUrl.pathname.startsWith('/dashboard') ||
      request.nextUrl.pathname.startsWith('/profile') ||
      request.nextUrl.pathname.startsWith('/admin')) {
    
    const auth = await checkAuthMiddleware(request);
    
    if (!auth.isAuthenticated) {
      const loginUrl = new URL('/signin', request.url);
      loginUrl.searchParams.set('redirect', request.nextUrl.pathname);
      return NextResponse.redirect(loginUrl);
    }
    
    // Add user context to headers
    if (auth.user) {
      response.headers.set('X-User-ID', auth.user.id);
      response.headers.set('X-User-Email', auth.user.email);
    }
  }
  
  // CSRF protection for state-changing operations
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    const origin = request.headers.get('origin');
    const host = request.headers.get('host');
    
    if (!origin || new URL(origin).host !== host) {
      return NextResponse.json(
        { error: 'CSRF protection: Origin mismatch' },
        { status: 403 }
      );
    }
  }
  
  return response;
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ]
};
```

## Performance Optimization

### Database Connection Pooling

```typescript
// lib/database.ts
import { MongoClient } from 'mongodb';

let client: MongoClient;
let clientPromise: Promise<MongoClient>;

if (process.env.NODE_ENV === 'production') {
  // In production, use a global variable to ensure connection reuse
  client = new MongoClient(process.env.MONGODB_URI!, {
    maxPoolSize: 50,
    minPoolSize: 5,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    family: 4,
    retryWrites: true,
    retryReads: true,
    connectTimeoutMS: 10000,
  });
  clientPromise = client.connect();
} else {
  // In development, use a global variable to preserve connection across HMR
  if (!(global as any)._mongoClientPromise) {
    client = new MongoClient(process.env.MONGODB_URI!);
    (global as any)._mongoClientPromise = client.connect();
  }
  clientPromise = (global as any)._mongoClientPromise;
}

export default clientPromise;
```

### Caching Strategy

```typescript
// lib/cache.ts
import { Redis } from 'ioredis';

const redis = new Redis(process.env.REDIS_URL!);

export class CacheManager {
  static async get<T>(key: string): Promise<T | null> {
    try {
      const cached = await redis.get(key);
      return cached ? JSON.parse(cached) : null;
    } catch (error) {
      console.error('Cache get error:', error);
      return null;
    }
  }
  
  static async set(key: string, value: any, ttl: number = 300): Promise<void> {
    try {
      await redis.setex(key, ttl, JSON.stringify(value));
    } catch (error) {
      console.error('Cache set error:', error);
    }
  }
  
  static async del(key: string): Promise<void> {
    try {
      await redis.del(key);
    } catch (error) {
      console.error('Cache delete error:', error);
    }
  }
  
  static async invalidatePattern(pattern: string): Promise<void> {
    try {
      const keys = await redis.keys(pattern);
      if (keys.length > 0) {
        await redis.del(...keys);
      }
    } catch (error) {
      console.error('Cache invalidation error:', error);
    }
  }
}

// Usage in API routes
export async function getCachedUser(userId: string) {
  const cacheKey = `user:${userId}`;
  let user = await CacheManager.get(cacheKey);
  
  if (!user) {
    user = await fetchUserFromDatabase(userId);
    await CacheManager.set(cacheKey, user, 600); // 10 minutes
  }
  
  return user;
}
```

### Image Optimization

```typescript
// components/OptimizedImage.tsx
import Image from 'next/image';

interface OptimizedImageProps {
  src: string;
  alt: string;
  width?: number;
  height?: number;
  className?: string;
  priority?: boolean;
}

export function OptimizedImage({ 
  src, 
  alt, 
  width = 400, 
  height = 300, 
  className,
  priority = false 
}: OptimizedImageProps) {
  return (
    <Image
      src={src}
      alt={alt}
      width={width}
      height={height}
      className={className}
      priority={priority}
      quality={85}
      placeholder="blur"
      blurDataURL="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAYEBQYFBAYGBQYHBwYIChAKCgkJChQODwwQFxQYGBcUFhYaHSUfGhsjHBYWICwgIyYnKSopGR8tMC0oMCUoKSj/2wBDAQcHBwoIChMKChMoGhYaKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCj/wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAv/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFQEBAQAAAAAAAAAAAAAAAAAAAAX/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwCdABmX/9k="
      sizes="(max-width: 768px) 100vw, (max-width: 1200px) 50vw, 33vw"
    />
  );
}
```

### Bundle Analysis

```bash
# Install bundle analyzer
npm install @next/bundle-analyzer

# Update next.config.js
const withBundleAnalyzer = require('@next/bundle-analyzer')({
  enabled: process.env.ANALYZE === 'true'
});

module.exports = withBundleAnalyzer(nextConfig);

# Analyze bundle
ANALYZE=true npm run build
```

## Database Configuration

### MongoDB Production Setup

```typescript
// lib/adapters/mongo-production.ts
import { MongoClient, Db } from 'mongodb';
import type { AuthDbAdapter } from 'authrix';

class MongoProductionAdapter implements AuthDbAdapter {
  private client: MongoClient;
  private db: Db;
  
  constructor() {
    this.client = new MongoClient(process.env.MONGODB_URI!, {
      maxPoolSize: 50,
      minPoolSize: 5,
      maxIdleTimeMS: 30000,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      retryWrites: true,
      retryReads: true,
      readPreference: 'primaryPreferred',
      writeConcern: { w: 'majority', j: true },
    });
    
    this.db = this.client.db('production');
    
    // Create indexes
    this.createIndexes();
  }
  
  private async createIndexes() {
    try {
      const users = this.db.collection('users');
      
      // Email index (unique)
      await users.createIndex({ email: 1 }, { unique: true });
      
      // Created at index for queries
      await users.createIndex({ createdAt: -1 });
      
      // OAuth provider indexes
      await users.createIndex({ 'oauth.provider': 1, 'oauth.id': 1 });
      
      console.log('Database indexes created successfully');
    } catch (error) {
      console.error('Error creating indexes:', error);
    }
  }
  
  async findUserByEmail(email: string) {
    try {
      const user = await this.db.collection('users').findOne({ email });
      return user ? this.transformUser(user) : null;
    } catch (error) {
      console.error('Find user by email error:', error);
      throw new Error('Database query failed');
    }
  }
  
  async findUserById(id: string) {
    try {
      const user = await this.db.collection('users').findOne({ _id: id });
      return user ? this.transformUser(user) : null;
    } catch (error) {
      console.error('Find user by ID error:', error);
      throw new Error('Database query failed');
    }
  }
  
  async createUser(data: { email: string; password: string; [key: string]: any }) {
    try {
      const now = new Date();
      const userData = {
        ...data,
        createdAt: now,
        updatedAt: now,
        emailVerified: false,
        lastLogin: null,
      };
      
      const result = await this.db.collection('users').insertOne(userData);
      
      return this.transformUser({
        _id: result.insertedId,
        ...userData
      });
    } catch (error) {
      if (error.code === 11000) {
        throw new Error('Email already exists');
      }
      console.error('Create user error:', error);
      throw new Error('Failed to create user');
    }
  }
  
  private transformUser(user: any) {
    return {
      id: user._id.toString(),
      email: user.email,
      password: user.password,
      name: user.name,
      avatar: user.avatar,
      emailVerified: user.emailVerified,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
      lastLogin: user.lastLogin,
    };
  }
}

export const mongoProductionAdapter = new MongoProductionAdapter();
```

### Supabase Production Setup

```typescript
// lib/adapters/supabase-production.ts
import { createClient } from '@supabase/supabase-js';
import type { AuthDbAdapter } from 'authrix';

const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    },
    db: {
      schema: 'public'
    },
    global: {
      headers: {
        'X-Client-Info': 'authrix-production'
      }
    }
  }
);

export const supabaseProductionAdapter: AuthDbAdapter = {
  async findUserByEmail(email: string) {
    try {
      const { data, error } = await supabase
        .from('users')
        .select('*')
        .eq('email', email)
        .single();
      
      if (error && error.code !== 'PGRST116') {
        throw error;
      }
      
      return data;
    } catch (error) {
      console.error('Find user by email error:', error);
      throw new Error('Database query failed');
    }
  },
  
  async findUserById(id: string) {
    try {
      const { data, error } = await supabase
        .from('users')
        .select('*')
        .eq('id', id)
        .single();
      
      if (error && error.code !== 'PGRST116') {
        throw error;
      }
      
      return data;
    } catch (error) {
      console.error('Find user by ID error:', error);
      throw new Error('Database query failed');
    }
  },
  
  async createUser(userData: { email: string; password: string; [key: string]: any }) {
    try {
      const { data, error } = await supabase
        .from('users')
        .insert([{
          ...userData,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          email_verified: false,
        }])
        .select()
        .single();
      
      if (error) {
        if (error.code === '23505') {
          throw new Error('Email already exists');
        }
        throw error;
      }
      
      return data;
    } catch (error) {
      console.error('Create user error:', error);
      throw new Error('Failed to create user');
    }
  }
};
```

## Deployment Platforms

### Vercel

```javascript
// vercel.json
{
  "version": 2,
  "regions": ["iad1", "sfo1"],
  "env": {
    "NODE_ENV": "production"
  },
  "build": {
    "env": {
      "NODE_ENV": "production"
    }
  },
  "functions": {
    "app/api/**/*.js": {
      "maxDuration": 30
    }
  },
  "headers": [
    {
      "source": "/api/(.*)",
      "headers": [
        {
          "key": "Access-Control-Allow-Origin",
          "value": "https://yourdomain.com"
        },
        {
          "key": "Access-Control-Allow-Methods",
          "value": "GET, POST, PUT, DELETE, OPTIONS"
        }
      ]
    }
  ]
}
```

Deploy script:
```bash
#!/bin/bash
# deploy.sh

echo "Building and deploying to Vercel..."

# Install dependencies
npm ci

# Build application
npm run build

# Deploy to Vercel
vercel --prod

echo "Deployment complete!"
```

### Docker

```dockerfile
# Dockerfile
FROM node:18-alpine AS base

# Install dependencies only when needed
FROM base AS deps
RUN apk add --no-cache libc6-compat
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci

# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Disable telemetry
ENV NEXT_TELEMETRY_DISABLED 1

RUN npm run build

# Production image
FROM base AS runner
WORKDIR /app

ENV NODE_ENV production
ENV NEXT_TELEMETRY_DISABLED 1

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public

# Automatically leverage output traces to reduce image size
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

ENV PORT 3000
ENV HOSTNAME "0.0.0.0"

CMD ["node", "server.js"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - JWT_SECRET=${JWT_SECRET}
      - MONGODB_URI=${MONGODB_URI}
    depends_on:
      - mongodb
      - redis
    restart: unless-stopped
    
  mongodb:
    image: mongo:6
    ports:
      - "27017:27017"
    environment:
      - MONGO_INITDB_ROOT_USERNAME=${MONGO_USERNAME}
      - MONGO_INITDB_ROOT_PASSWORD=${MONGO_PASSWORD}
    volumes:
      - mongodb_data:/data/db
    restart: unless-stopped
    
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped
    
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - app
    restart: unless-stopped

volumes:
  mongodb_data:
  redis_data:
```

### AWS ECS

```yaml
# ecs-task-definition.json
{
  "family": "authrix-app",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "authrix-app",
      "image": "your-account.dkr.ecr.region.amazonaws.com/authrix-app:latest",
      "portMappings": [
        {
          "containerPort": 3000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "NODE_ENV",
          "value": "production"
        }
      ],
      "secrets": [
        {
          "name": "JWT_SECRET",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:jwt-secret"
        },
        {
          "name": "MONGODB_URI",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:mongodb-uri"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/authrix-app",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:3000/api/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ]
}
```

## Monitoring and Logging

### Error Tracking with Sentry

```typescript
// lib/sentry.ts
import * as Sentry from '@sentry/nextjs';

if (process.env.NODE_ENV === 'production') {
  Sentry.init({
    dsn: process.env.SENTRY_DSN,
    environment: process.env.NODE_ENV,
    integrations: [
      new Sentry.Integrations.Http({ tracing: true }),
    ],
    tracesSampleRate: 0.1,
    beforeSend(event) {
      // Filter out sensitive data
      if (event.exception) {
        const error = event.exception.values?.[0];
        if (error?.stacktrace?.frames) {
          error.stacktrace.frames = error.stacktrace.frames.map(frame => ({
            ...frame,
            vars: undefined // Remove variable data
          }));
        }
      }
      return event;
    }
  });
}

export function captureAuthError(error: Error, context: Record<string, any>) {
  Sentry.withScope(scope => {
    scope.setTag('category', 'authentication');
    scope.setContext('auth_context', context);
    Sentry.captureException(error);
  });
}
```

### Application Metrics

```typescript
// lib/metrics.ts
import { performance } from 'perf_hooks';

class MetricsCollector {
  private static instance: MetricsCollector;
  private metrics: Map<string, number[]> = new Map();
  
  static getInstance(): MetricsCollector {
    if (!MetricsCollector.instance) {
      MetricsCollector.instance = new MetricsCollector();
    }
    return MetricsCollector.instance;
  }
  
  recordTiming(name: string, duration: number) {
    if (!this.metrics.has(name)) {
      this.metrics.set(name, []);
    }
    this.metrics.get(name)!.push(duration);
  }
  
  recordAuthEvent(event: string, success: boolean, duration?: number) {
    const eventName = `auth_${event}_${success ? 'success' : 'failure'}`;
    
    if (duration) {
      this.recordTiming(eventName, duration);
    }
    
    // Send to your metrics service
    this.sendToMetricsService({
      event: eventName,
      timestamp: Date.now(),
      duration,
      success
    });
  }
  
  private async sendToMetricsService(metric: any) {
    try {
      await fetch(process.env.METRICS_ENDPOINT!, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(metric)
      });
    } catch (error) {
      console.error('Failed to send metrics:', error);
    }
  }
  
  getStats(name: string) {
    const values = this.metrics.get(name) || [];
    if (values.length === 0) return null;
    
    const sorted = values.sort((a, b) => a - b);
    return {
      count: values.length,
      min: sorted[0],
      max: sorted[sorted.length - 1],
      avg: values.reduce((a, b) => a + b, 0) / values.length,
      p50: sorted[Math.floor(sorted.length * 0.5)],
      p95: sorted[Math.floor(sorted.length * 0.95)],
      p99: sorted[Math.floor(sorted.length * 0.99)]
    };
  }
}

export const metrics = MetricsCollector.getInstance();

// Usage wrapper
export function withMetrics<T extends any[], R>(
  name: string,
  fn: (...args: T) => Promise<R>
) {
  return async (...args: T): Promise<R> => {
    const start = performance.now();
    try {
      const result = await fn(...args);
      metrics.recordTiming(name, performance.now() - start);
      return result;
    } catch (error) {
      metrics.recordTiming(`${name}_error`, performance.now() - start);
      throw error;
    }
  };
}
```

### Health Check Endpoint

```typescript
// app/api/health/route.ts
import { NextRequest } from 'next/server';
import { mongoAdapter } from 'authrix/adapters/mongo';

export async function GET(request: NextRequest) {
  const checks = {
    timestamp: new Date().toISOString(),
    status: 'healthy',
    version: process.env.npm_package_version || '1.0.0',
    environment: process.env.NODE_ENV,
    checks: {
      database: false,
      redis: false,
      external_apis: false
    }
  };
  
  try {
    // Database check
    await mongoAdapter.findUserByEmail('health@check.com');
    checks.checks.database = true;
  } catch (error) {
    checks.status = 'degraded';
  }
  
  try {
    // Redis check (if using)
    const redis = require('ioredis');
    const client = new redis(process.env.REDIS_URL);
    await client.ping();
    checks.checks.redis = true;
    client.disconnect();
  } catch (error) {
    checks.status = 'degraded';
  }
  
  try {
    // External API check
    const response = await fetch(process.env.EXTERNAL_API_HEALTH_URL!, {
      timeout: 5000
    });
    checks.checks.external_apis = response.ok;
  } catch (error) {
    checks.status = 'degraded';
  }
  
  const statusCode = checks.status === 'healthy' ? 200 : 503;
  
  return Response.json(checks, { status: statusCode });
}
```

## Troubleshooting

### Common Production Issues

#### 1. Database Connection Timeouts

**Symptoms:** Intermittent 500 errors, slow response times

**Solutions:**
```typescript
// Increase connection pool settings
const client = new MongoClient(uri, {
  maxPoolSize: 100,
  minPoolSize: 10,
  maxIdleTimeMS: 30000,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
});

// Add connection retry logic
async function withRetry<T>(operation: () => Promise<T>, retries = 3): Promise<T> {
  for (let i = 0; i < retries; i++) {
    try {
      return await operation();
    } catch (error) {
      if (i === retries - 1) throw error;
      await new Promise(resolve => setTimeout(resolve, 1000 * Math.pow(2, i)));
    }
  }
  throw new Error('Max retries exceeded');
}
```

#### 2. Memory Leaks

**Symptoms:** Increasing memory usage, eventual crashes

**Solutions:**
```typescript
// Monitor memory usage
setInterval(() => {
  const memUsage = process.memoryUsage();
  console.log('Memory usage:', {
    rss: Math.round(memUsage.rss / 1024 / 1024) + 'MB',
    heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024) + 'MB',
    heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024) + 'MB',
  });
}, 60000);

// Cleanup database connections
process.on('SIGTERM', async () => {
  await client.close();
  process.exit(0);
});
```

#### 3. JWT Token Issues

**Symptoms:** Users getting logged out unexpectedly

**Solutions:**
```typescript
// Add token refresh mechanism
export async function refreshTokenIfNeeded(token: string) {
  try {
    const decoded = jwt.decode(token) as any;
    const now = Date.now() / 1000;
    
    // Refresh if token expires in less than 5 minutes
    if (decoded.exp - now < 300) {
      return await generateNewToken(decoded.id);
    }
    
    return token;
  } catch (error) {
    throw new Error('Invalid token');
  }
}

// Add graceful token expiry handling
export function createTokenWithGracePeriod(payload: any) {
  return jwt.sign(payload, process.env.JWT_SECRET!, {
    expiresIn: '24h',
    issuer: process.env.NEXTAUTH_URL,
    audience: process.env.NEXTAUTH_URL,
    notBefore: 0,
    // Add 5 minute grace period
    clockTolerance: 300
  });
}
```

### Performance Debugging

```typescript
// Add performance monitoring
export async function monitoredAuthOperation<T>(
  operation: () => Promise<T>,
  operationName: string
): Promise<T> {
  const start = Date.now();
  const startMemory = process.memoryUsage();
  
  try {
    const result = await operation();
    const duration = Date.now() - start;
    const endMemory = process.memoryUsage();
    
    console.log(`Auth operation ${operationName}:`, {
      duration: `${duration}ms`,
      memoryDelta: `${Math.round((endMemory.heapUsed - startMemory.heapUsed) / 1024)}KB`
    });
    
    return result;
  } catch (error) {
    const duration = Date.now() - start;
    console.error(`Auth operation ${operationName} failed after ${duration}ms:`, error);
    throw error;
  }
}
```

## Maintenance

### Database Maintenance

```typescript
// scripts/maintenance.ts
async function runDatabaseMaintenance() {
  console.log('Starting database maintenance...');
  
  // Clean up expired sessions
  await db.collection('sessions').deleteMany({
    expiresAt: { $lt: new Date() }
  });
  
  // Clean up unverified users older than 7 days
  const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  await db.collection('users').deleteMany({
    emailVerified: false,
    createdAt: { $lt: weekAgo }
  });
  
  // Update user statistics
  await updateUserStatistics();
  
  console.log('Database maintenance completed');
}

// Run daily via cron or cloud scheduler
```

### Security Audits

```bash
#!/bin/bash
# security-audit.sh

echo "Running security audit..."

# Check for vulnerable dependencies
npm audit --audit-level high

# Check for secrets in code
npx secret-scan

# Update dependencies
npm update

# Run security tests
npm run test:security

echo "Security audit completed"
```

### Backup Strategy

```typescript
// scripts/backup.ts
import { spawn } from 'child_process';
import { S3 } from 'aws-sdk';

async function backupDatabase() {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `backup-${timestamp}.gz`;
  
  // Create MongoDB dump
  const mongodump = spawn('mongodump', [
    '--uri', process.env.MONGODB_URI!,
    '--gzip',
    '--archive', `/tmp/${filename}`
  ]);
  
  await new Promise((resolve, reject) => {
    mongodump.on('close', resolve);
    mongodump.on('error', reject);
  });
  
  // Upload to S3
  const s3 = new S3();
  const fileStream = require('fs').createReadStream(`/tmp/${filename}`);
  
  await s3.upload({
    Bucket: process.env.BACKUP_BUCKET!,
    Key: `database-backups/${filename}`,
    Body: fileStream
  }).promise();
  
  console.log(`Backup completed: ${filename}`);
}

// Schedule daily backups
```

This comprehensive production guide ensures your Authrix-powered Next.js application is ready for production deployment with proper security, performance, and monitoring in place.
