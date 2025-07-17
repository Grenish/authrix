# Bundle Optimization Guide

> Comprehensive guide to minimize bundle size and optimize performance when using Authrix in your applications.

## Table of Contents

- [Overview](#overview)
- [Bundle Analysis](#bundle-analysis)
- [Modular Imports](#modular-imports)
- [Tree Shaking](#tree-shaking)
- [Code Splitting](#code-splitting)
- [Framework-Specific Optimizations](#framework-specific-optimizations)
- [Production Optimizations](#production-optimizations)
- [Performance Monitoring](#performance-monitoring)
- [Best Practices](#best-practices)

## Overview

Authrix is designed with bundle optimization in mind, offering modular imports and tree-shaking support to ensure you only include the code you actually use.

### Bundle Size Comparison

| Import Strategy | Bundle Size | Features Included |
|----------------|-------------|-------------------|
| Full import | ~45kB | All features |
| Core only | ~12kB | Basic auth functions |
| Framework-specific | ~18kB | Core + framework helpers |
| Minimal selective | ~8kB | Only specific functions |

### Key Optimization Features

- ✅ **Modular Architecture**: Import only what you need
- ✅ **Tree Shaking**: Dead code elimination
- ✅ **Zero Dependencies**: Core functions have minimal dependencies
- ✅ **Framework Separation**: Framework-specific code is separate
- ✅ **Conditional Loading**: Dynamic imports for optional features

## Bundle Analysis

### Analyzing Your Bundle

#### Next.js Bundle Analyzer

```bash
# Install bundle analyzer
npm install @next/bundle-analyzer

# Add to next.config.js
const withBundleAnalyzer = require('@next/bundle-analyzer')({
  enabled: process.env.ANALYZE === 'true'
});

module.exports = withBundleAnalyzer({
  // your next config
});

# Analyze bundle
ANALYZE=true npm run build
```

#### Webpack Bundle Analyzer

```bash
# For other frameworks
npm install webpack-bundle-analyzer

# Add to webpack config
const BundleAnalyzerPlugin = require('webpack-bundle-analyzer').BundleAnalyzerPlugin;

module.exports = {
  plugins: [
    new BundleAnalyzerPlugin({
      analyzerMode: 'static',
      openAnalyzer: false,
    })
  ]
};
```

#### Bundle Size Tracking

```javascript
// scripts/bundle-size.js
const fs = require('fs');
const path = require('path');
const gzipSize = require('gzip-size');

async function analyzeBundleSize() {
  const bundlePath = path.join(__dirname, '../dist');
  const files = fs.readdirSync(bundlePath);
  
  const sizes = await Promise.all(
    files
      .filter(file => file.endsWith('.js'))
      .map(async file => {
        const filePath = path.join(bundlePath, file);
        const content = fs.readFileSync(filePath);
        const originalSize = content.length;
        const gzipped = await gzipSize(content);
        
        return {
          file,
          original: `${(originalSize / 1024).toFixed(2)}KB`,
          gzipped: `${(gzipped / 1024).toFixed(2)}KB`
        };
      })
  );
  
  console.table(sizes);
}

analyzeBundleSize();
```

## Modular Imports

### Import Strategies

#### ❌ Avoid: Full Package Import

```typescript
// Don't do this - imports everything
import * as authrix from 'authrix';
import { everything } from 'authrix';
```

#### ✅ Recommended: Specific Imports

```typescript
// Core authentication only (smallest bundle)
import { initAuth, signup, signin } from 'authrix';

// Framework-specific imports
import { signupNextApp, getCurrentUserNextApp } from 'authrix/nextjs';
import { signupReact, getCurrentUserReact } from 'authrix/react';

// Adapter imports
import { mongoAdapter } from 'authrix/adapters/mongo';
import { supabaseAdapter } from 'authrix/adapters/supabase';

// OAuth imports (only when needed)
import { getGoogleOAuthURL, handleGoogleCallback } from 'authrix/oauth';

// Utility imports
import { createToken, verifyToken } from 'authrix/tokens';
import { AuthrixError } from 'authrix/utils';
```

### Module Breakdown

```typescript
// authrix (core) - ~12kB
export {
  initAuth,
  signup,
  signin,
  logout,
  getCurrentUser,
  authMiddleware
} from 'authrix';

// authrix/nextjs - +6kB
export {
  signupNextApp,
  signinNextApp,
  getCurrentUserNextApp,
  checkAuthMiddleware
} from 'authrix/nextjs';

// authrix/react - +4kB
export {
  signupReact,
  signinReact,
  getCurrentUserReact,
  useAuth
} from 'authrix/react';

// authrix/oauth - +8kB
export {
  getGoogleOAuthURL,
  handleGoogleCallback,
  getGitHubOAuthURL,
  handleGitHubCallback
} from 'authrix/oauth';

// authrix/adapters/mongo - +3kB
export { mongoAdapter } from 'authrix/adapters/mongo';

// authrix/adapters/supabase - +5kB
export { supabaseAdapter } from 'authrix/adapters/supabase';

// authrix/adapters/firebase - +7kB
export { firebaseAdapter } from 'authrix/adapters/firebase';
```

## Tree Shaking

### Ensuring Proper Tree Shaking

#### Package.json Configuration

```json
{
  "name": "authrix",
  "sideEffects": false,
  "main": "./dist/index.cjs",
  "module": "./dist/index.mjs",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "require": "./dist/index.cjs",
      "import": "./dist/index.mjs"
    },
    "./nextjs": {
      "types": "./dist/nextjs.d.ts",
      "require": "./dist/nextjs.cjs",
      "import": "./dist/nextjs.mjs"
    }
  }
}
```

#### Webpack Configuration

```javascript
// webpack.config.js
module.exports = {
  mode: 'production',
  optimization: {
    usedExports: true,
    sideEffects: false,
    concatenateModules: true,
    minimize: true,
  },
  resolve: {
    mainFields: ['module', 'main'],
  }
};
```

#### Rollup Configuration

```javascript
// rollup.config.js
import { terser } from 'rollup-plugin-terser';

export default {
  input: 'src/index.ts',
  output: {
    file: 'dist/index.mjs',
    format: 'es'
  },
  plugins: [
    terser({
      mangle: {
        properties: {
          regex: /^_/
        }
      }
    })
  ],
  treeshake: {
    moduleSideEffects: false,
    propertyReadSideEffects: false,
    unknownGlobalSideEffects: false
  }
};
```

### Tree Shaking Verification

```javascript
// scripts/verify-tree-shaking.js
const rollup = require('rollup');
const { terser } = require('rollup-plugin-terser');

async function testTreeShaking() {
  const tests = [
    {
      name: 'Core only',
      input: `
        import { signup, signin } from 'authrix';
        console.log(signup, signin);
      `
    },
    {
      name: 'Next.js only',
      input: `
        import { signupNextApp } from 'authrix/nextjs';
        console.log(signupNextApp);
      `
    },
    {
      name: 'OAuth only',
      input: `
        import { getGoogleOAuthURL } from 'authrix/oauth';
        console.log(getGoogleOAuthURL);
      `
    }
  ];

  for (const test of tests) {
    const bundle = await rollup.rollup({
      input: 'virtual:test',
      plugins: [
        {
          name: 'virtual',
          resolveId(id) {
            if (id === 'virtual:test') return id;
            return null;
          },
          load(id) {
            if (id === 'virtual:test') return test.input;
            return null;
          }
        },
        terser()
      ]
    });

    const { output } = await bundle.generate({ format: 'es' });
    const size = output[0].code.length;
    
    console.log(`${test.name}: ${(size / 1024).toFixed(2)}KB`);
  }
}

testTreeShaking();
```

## Code Splitting

### Dynamic Imports

#### Lazy Loading OAuth

```typescript
// components/OAuth.tsx
import { useState } from 'react';

export function OAuthButtons() {
  const [loading, setLoading] = useState(false);

  const handleGoogleOAuth = async () => {
    setLoading(true);
    
    // Dynamically import OAuth functionality only when needed
    const { getGoogleOAuthURL } = await import('authrix/oauth');
    
    try {
      const url = getGoogleOAuthURL(crypto.randomUUID());
      window.location.href = url;
    } catch (error) {
      console.error('OAuth error:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <button onClick={handleGoogleOAuth} disabled={loading}>
      {loading ? 'Loading...' : 'Sign in with Google'}
    </button>
  );
}
```

#### Conditional Database Adapters

```typescript
// lib/database.ts
let adapter: any = null;

export async function getDbAdapter() {
  if (adapter) return adapter;

  // Load adapter based on environment
  if (process.env.MONGODB_URI) {
    const { mongoAdapter } = await import('authrix/adapters/mongo');
    adapter = mongoAdapter;
  } else if (process.env.SUPABASE_URL) {
    const { supabaseAdapter } = await import('authrix/adapters/supabase');
    adapter = supabaseAdapter;
  } else if (process.env.FIREBASE_PROJECT_ID) {
    const { firebaseAdapter } = await import('authrix/adapters/firebase');
    adapter = firebaseAdapter;
  } else {
    throw new Error('No database adapter configured');
  }

  return adapter;
}

// Usage
export async function initializeAuth() {
  const { initAuth } = await import('authrix');
  const adapter = await getDbAdapter();
  
  initAuth({
    jwtSecret: process.env.JWT_SECRET!,
    db: adapter
  });
}
```

#### Route-Based Code Splitting

```typescript
// Next.js with dynamic imports
import dynamic from 'next/dynamic';

// Only load admin components when needed
const AdminPanel = dynamic(() => import('../components/AdminPanel'), {
  loading: () => <p>Loading admin panel...</p>,
});

// Only load OAuth components when needed
const OAuthButtons = dynamic(() => import('../components/OAuthButtons'), {
  loading: () => <p>Loading OAuth options...</p>,
});

export default function LoginPage() {
  const [showAdmin, setShowAdmin] = useState(false);
  const [showOAuth, setShowOAuth] = useState(false);

  return (
    <div>
      <h1>Login</h1>
      
      {showOAuth && <OAuthButtons />}
      {showAdmin && <AdminPanel />}
      
      <button onClick={() => setShowOAuth(true)}>
        Show OAuth Options
      </button>
    </div>
  );
}
```

### Webpack Code Splitting

```javascript
// webpack.config.js
module.exports = {
  optimization: {
    splitChunks: {
      chunks: 'all',
      cacheGroups: {
        authrix: {
          test: /[\\/]node_modules[\\/]authrix[\\/]/,
          name: 'authrix',
          chunks: 'all',
        },
        authrixOAuth: {
          test: /[\\/]node_modules[\\/]authrix[\\/].*oauth/,
          name: 'authrix-oauth',
          chunks: 'all',
        },
        adapters: {
          test: /[\\/]node_modules[\\/]authrix[\\/].*adapters/,
          name: 'authrix-adapters',
          chunks: 'all',
        }
      }
    }
  }
};
```

## Framework-Specific Optimizations

### Next.js Optimizations

#### App Router Optimization

```typescript
// app/auth/layout.tsx
import { Suspense } from 'react';

export default function AuthLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <Suspense fallback={<div>Loading authentication...</div>}>
      {children}
    </Suspense>
  );
}
```

#### Pages Router Optimization

```typescript
// pages/auth/signin.tsx
import dynamic from 'next/dynamic';
import { GetStaticProps } from 'next';

// Pre-load core auth functions at build time
export const getStaticProps: GetStaticProps = async () => {
  // Pre-import to ensure it's included in the initial bundle
  await import('authrix');
  
  return {
    props: {},
    revalidate: 86400 // 24 hours
  };
};

// Dynamically load OAuth components
const OAuthSection = dynamic(() => import('../../components/OAuthSection'), {
  ssr: false,
  loading: () => <div>Loading OAuth options...</div>
});

export default function SignIn() {
  return (
    <div>
      <h1>Sign In</h1>
      <OAuthSection />
    </div>
  );
}
```

#### Edge Runtime Optimization

```typescript
// middleware.ts
import { NextRequest, NextResponse } from 'next/server';

// Only import what's needed for Edge Runtime
export async function middleware(request: NextRequest) {
  if (request.nextUrl.pathname.startsWith('/protected')) {
    // Dynamic import to keep middleware bundle small
    const { checkAuthMiddleware } = await import('authrix/nextjs');
    
    const auth = await checkAuthMiddleware(request);
    
    if (!auth.isAuthenticated) {
      return NextResponse.redirect(new URL('/signin', request.url));
    }
  }
  
  return NextResponse.next();
}
```

### React Optimizations

#### Context Optimization

```typescript
// contexts/AuthContext.tsx
import React, { createContext, useContext, lazy, Suspense } from 'react';

// Lazy load auth functions
const authFunctions = lazy(() => import('../lib/auth-functions'));

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  return (
    <Suspense fallback={<div>Loading authentication...</div>}>
      <AuthProviderInner>{children}</AuthProviderInner>
    </Suspense>
  );
}

function AuthProviderInner({ children }) {
  // Implementation with lazy-loaded functions
  return (
    <AuthContext.Provider value={{}}>
      {children}
    </AuthContext.Provider>
  );
}
```

#### Component Optimization

```typescript
// components/AuthButton.tsx
import { memo, lazy, Suspense } from 'react';

// Lazy load the actual auth logic
const AuthLogic = lazy(() => import('./AuthLogic'));

export const AuthButton = memo(function AuthButton({ 
  type 
}: { 
  type: 'signin' | 'signup' 
}) {
  return (
    <Suspense fallback={<button disabled>Loading...</button>}>
      <AuthLogic type={type} />
    </Suspense>
  );
});
```

### Express.js Optimizations

```typescript
// routes/auth.ts
import { Router } from 'express';

const router = Router();

// Lazy load auth functions
router.post('/signup', async (req, res) => {
  const { signup } = await import('authrix');
  
  try {
    const user = await signup(req.body.email, req.body.password, res);
    res.json({ success: true, user });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Lazy load OAuth when needed
router.get('/oauth/:provider', async (req, res) => {
  const { provider } = req.params;
  
  if (provider === 'google') {
    const { getGoogleOAuthURL } = await import('authrix/oauth');
    const url = getGoogleOAuthURL(crypto.randomUUID());
    res.redirect(url);
  } else {
    res.status(400).json({ error: 'Unsupported provider' });
  }
});

export default router;
```

## Production Optimizations

### Build Configuration

#### tsup Configuration (for Authrix)

```typescript
// tsup.config.ts
import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    nextjs: 'src/nextjs.ts',
    react: 'src/react.ts',
    oauth: 'src/oauth.ts',
    'adapters/mongo': 'src/adapters/mongo.ts',
    'adapters/supabase': 'src/adapters/supabase.ts',
    'adapters/firebase': 'src/adapters/firebase.ts',
  },
  format: ['cjs', 'esm'],
  dts: true,
  splitting: true,
  clean: true,
  minify: true,
  treeshake: true,
  external: [
    'mongodb',
    '@supabase/supabase-js',
    'firebase',
    'firebase-admin',
    'next',
    'react',
    'express'
  ],
  esbuildOptions(options) {
    options.drop = ['console', 'debugger'];
    options.legalComments = 'none';
  }
});
```

#### Vite Configuration

```typescript
// vite.config.ts
import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      name: 'Authrix',
      formats: ['es', 'cjs']
    },
    rollupOptions: {
      external: ['mongodb', '@supabase/supabase-js', 'firebase'],
      output: {
        manualChunks: {
          'oauth': ['src/oauth.ts'],
          'adapters': ['src/adapters/index.ts'],
          'nextjs': ['src/nextjs.ts'],
          'react': ['src/react.ts']
        }
      }
    },
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: true,
        drop_debugger: true
      }
    }
  }
});
```

### Runtime Optimizations

#### Preloading Critical Modules

```typescript
// lib/preload.ts
export function preloadAuthModules() {
  if (typeof window !== 'undefined') {
    // Preload critical modules in the browser
    import('authrix').catch(() => {});
    
    // Preload framework-specific modules based on detection
    if (window.location.pathname.includes('auth')) {
      import('authrix/react').catch(() => {});
    }
  }
}

// Call during app initialization
preloadAuthModules();
```

#### Service Worker Caching

```javascript
// sw.js
const CACHE_NAME = 'authrix-v1';
const AUTHRIX_MODULES = [
  '/node_modules/authrix/dist/index.mjs',
  '/node_modules/authrix/dist/react.mjs',
  '/node_modules/authrix/dist/oauth.mjs'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(AUTHRIX_MODULES))
  );
});

self.addEventListener('fetch', event => {
  if (AUTHRIX_MODULES.some(module => event.request.url.includes(module))) {
    event.respondWith(
      caches.match(event.request)
        .then(response => response || fetch(event.request))
    );
  }
});
```

## Performance Monitoring

### Bundle Size Monitoring

```typescript
// scripts/monitor-bundle-size.ts
import { execSync } from 'child_process';
import { readFileSync } from 'fs';

interface BundleSizeReport {
  timestamp: string;
  sizes: Record<string, number>;
  totalSize: number;
}

function getBundleSizes(): BundleSizeReport {
  execSync('npm run build', { stdio: 'inherit' });
  
  const distFiles = execSync('find dist -name "*.js" -o -name "*.mjs"', { encoding: 'utf8' })
    .split('\n')
    .filter(Boolean);
  
  const sizes: Record<string, number> = {};
  let totalSize = 0;
  
  for (const file of distFiles) {
    const content = readFileSync(file);
    const size = content.length;
    sizes[file] = size;
    totalSize += size;
  }
  
  return {
    timestamp: new Date().toISOString(),
    sizes,
    totalSize
  };
}

function compareBundleSizes(current: BundleSizeReport, previous: BundleSizeReport) {
  const diff = current.totalSize - previous.totalSize;
  const percentChange = (diff / previous.totalSize) * 100;
  
  console.log(`Bundle size change: ${diff > 0 ? '+' : ''}${diff} bytes (${percentChange.toFixed(2)}%)`);
  
  if (Math.abs(percentChange) > 10) {
    console.warn('⚠️  Significant bundle size change detected!');
  }
}

// Usage in CI/CD
const current = getBundleSizes();
console.log('Current bundle sizes:', current);
```

### Runtime Performance Monitoring

```typescript
// lib/performance.ts
class BundlePerformanceMonitor {
  private loadTimes: Map<string, number> = new Map();
  
  startLoad(moduleName: string) {
    this.loadTimes.set(moduleName, performance.now());
  }
  
  endLoad(moduleName: string) {
    const startTime = this.loadTimes.get(moduleName);
    if (startTime) {
      const loadTime = performance.now() - startTime;
      console.log(`Module ${moduleName} loaded in ${loadTime.toFixed(2)}ms`);
      
      // Send to analytics
      this.sendToAnalytics({
        event: 'module_load',
        module: moduleName,
        loadTime
      });
    }
  }
  
  private sendToAnalytics(data: any) {
    if (typeof window !== 'undefined' && window.gtag) {
      window.gtag('event', 'performance', {
        custom_parameter_1: data.module,
        custom_parameter_2: data.loadTime
      });
    }
  }
}

export const performanceMonitor = new BundlePerformanceMonitor();

// Usage
export async function loadAuthModule() {
  performanceMonitor.startLoad('authrix');
  const authrix = await import('authrix');
  performanceMonitor.endLoad('authrix');
  return authrix;
}
```

## Best Practices

### Import Guidelines

```typescript
// ✅ Good: Specific imports
import { signup, signin } from 'authrix';
import { mongoAdapter } from 'authrix/adapters/mongo';

// ✅ Good: Dynamic imports for optional features
const loadOAuth = () => import('authrix/oauth');

// ✅ Good: Conditional imports
const adapter = process.env.DATABASE_TYPE === 'mongo' 
  ? await import('authrix/adapters/mongo')
  : await import('authrix/adapters/supabase');

// ❌ Bad: Importing everything
import * as authrix from 'authrix';

// ❌ Bad: Importing unused features
import { signup, signin, getGoogleOAuthURL } from 'authrix'; // OAuth not used
```

### Code Organization

```typescript
// lib/auth/index.ts - Core auth functions
export { signup, signin, logout } from 'authrix';

// lib/auth/oauth.ts - OAuth functions (loaded separately)
export const loadOAuth = () => import('authrix/oauth');

// lib/auth/adapters.ts - Database adapters
export const getAdapter = async () => {
  if (process.env.MONGODB_URI) {
    return (await import('authrix/adapters/mongo')).mongoAdapter;
  }
  // ... other adapters
};

// components/Auth.tsx - Use lazy loading
import { lazy, Suspense } from 'react';

const OAuthButtons = lazy(() => import('./OAuthButtons'));

export function AuthForm() {
  return (
    <div>
      <Suspense fallback={<div>Loading...</div>}>
        <OAuthButtons />
      </Suspense>
    </div>
  );
}
```

### Environment-Based Loading

```typescript
// lib/auth-config.ts
export async function configureAuth() {
  const { initAuth } = await import('authrix');
  
  // Load adapter based on environment
  let adapter;
  if (process.env.NODE_ENV === 'development') {
    // Smaller adapter for development
    adapter = (await import('authrix/adapters/memory')).memoryAdapter;
  } else if (process.env.MONGODB_URI) {
    adapter = (await import('authrix/adapters/mongo')).mongoAdapter;
  } else {
    adapter = (await import('authrix/adapters/supabase')).supabaseAdapter;
  }
  
  initAuth({
    jwtSecret: process.env.JWT_SECRET!,
    db: adapter
  });
}
```

### Build Scripts

```json
{
  "scripts": {
    "build": "npm run clean && npm run build:analyze",
    "build:analyze": "cross-env ANALYZE=true next build",
    "build:profile": "cross-env PROFILE=true next build",
    "bundle:size": "node scripts/bundle-size.js",
    "bundle:report": "npm run build && npm run bundle:size",
    "optimize": "npm run bundle:report && npm run test:bundle-size"
  }
}
```

### Continuous Integration

```yaml
# .github/workflows/bundle-size.yml
name: Bundle Size Check

on:
  pull_request:
    branches: [main]

jobs:
  bundle-size:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Build and analyze bundle
        run: npm run bundle:report
      
      - name: Check bundle size
        run: |
          if [ -f bundle-size-report.json ]; then
            node scripts/check-bundle-size.js
          fi
      
      - name: Comment PR
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            if (fs.existsSync('bundle-size-report.json')) {
              const report = JSON.parse(fs.readFileSync('bundle-size-report.json', 'utf8'));
              github.rest.issues.createComment({
                issue_number: context.issue.number,
                owner: context.repo.owner,
                repo: context.repo.repo,
                body: `## Bundle Size Report\n\n${report.summary}`
              });
            }
```

By following this bundle optimization guide, you can ensure that Authrix adds minimal overhead to your application while providing all the authentication features you need. The modular architecture and tree-shaking support make it easy to include only the code you actually use, resulting in smaller bundles and better performance.
