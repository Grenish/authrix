# Authrix Bundle Optimization Guide

## 🎯 Optimized Architecture

Authrix has been restructured into a modular architecture to achieve a **significantly smaller bundle size** while maintaining full functionality. The library now uses tree-shaking-friendly exports that allow you to import only what you need.

## 📊 Bundle Size Comparison

- **Before Optimization**: 285.5 kB
- **After Optimization**: 110.2 kB total (but you only load what you use!)
- **Core Bundle Only**: ~7.8 kB (main index.ts)

## 🎯 Import Strategy

### Core Authentication (Minimal Bundle)
```typescript
// Import only essential authentication functions (~7.8 kB)
import { initAuth, signup, signin, logout, authMiddleware } from 'authrix';
import { mongoAdapter } from 'authrix/adapters/mongo'; // ~2.4 kB when needed
```

### Framework-Specific Modules
```typescript
// Next.js App Router (~9.8 kB only when used)
import { signupNextApp, getCurrentUserNextApp } from 'authrix/nextjs';

// React SPA (~3.6 kB only when used)
import { signupReact, withAuthReact } from 'authrix/react';

// Universal/Framework-agnostic (~6.1 kB only when used)
import { signupUniversal, validateAuth } from 'authrix/universal';
```

### Optional Features
```typescript
// OAuth providers (~7.8 kB only when used)
import { getGoogleOAuthURL, handleGoogleCallback } from 'authrix/oauth';

// Advanced middleware (~4.5 kB only when used)
import { createAuthMiddleware, optionalAuthMiddleware } from 'authrix/middleware';

// Error handling utilities (~2.7 kB only when used)
import { AuthrixError, sendSuccess } from 'authrix/utils';
```

## 🚀 Usage Examples

### Minimal Express.js Setup (~10 kB total)
```typescript
import express from "express";
import { initAuth, signup, signin, authMiddleware } from "authrix";
import { mongoAdapter } from "authrix/adapters/mongo";

// Only loads core authentication + MongoDB adapter
initAuth({ jwtSecret: process.env.JWT_SECRET!, db: mongoAdapter });

const app = express();
app.post("/signup", async (req, res) => {
  const user = await signup(req.body.email, req.body.password, res);
  res.json({ user });
});
```

### Minimal Next.js Setup (~17 kB total)
```typescript
// app/auth/signup/route.ts
import { initAuth, signupNextApp } from "authrix/nextjs";
import { mongoAdapter } from "authrix/adapters/mongo";

// Only loads Next.js helpers + core + adapter
initAuth({ jwtSecret: process.env.JWT_SECRET!, db: mongoAdapter });

export async function POST(request: Request) {
  const { email, password } = await request.json();
  const user = await signupNextApp(email, password);
  return Response.json({ user });
}
```

### Minimal React SPA Setup (~13 kB total)
```typescript
// Only loads React helpers + core functionality
import { signupReact, getCurrentUserReact } from "authrix/react";

export function useAuth() {
  const [user, setUser] = useState(null);
  
  const signup = async (email: string, password: string) => {
    const result = await signupReact(email, password);
    setUser(result.user);
    return result;
  };
  
  return { user, signup };
}
```

## 📦 Bundle Size Breakdown

| Module | CJS Size | ESM Size | Purpose |
|--------|----------|----------|---------|
| `authrix` (core) | 4.3 kB | 3.5 kB | Essential auth functions |
| `authrix/nextjs` | 5.0 kB | 4.3 kB | Next.js specific helpers |
| `authrix/react` | 2.4 kB | 1.8 kB | React SPA helpers |
| `authrix/universal` | 4.0 kB | 3.1 kB | Framework-agnostic helpers |
| `authrix/oauth` | 4.2 kB | 3.6 kB | OAuth providers (Google, GitHub) |
| `authrix/adapters/mongo` | 1.4 kB | 1.0 kB | MongoDB adapter |
| `authrix/adapters/supabase` | 1.7 kB | 1.2 kB | Supabase adapter |
| `authrix/adapters/firebase` | 2.3 kB | 1.8 kB | Firebase adapter |
| `authrix/utils` | 1.7 kB | 1.0 kB | Error handling & utilities |
| `authrix/middleware` | 2.6 kB | 1.9 kB | Advanced middleware |

## 🎯 Migration Guide

### Before (Heavy Bundle)
```typescript
// This would load everything (~110 kB)
import { 
  signup, 
  signupReact, 
  signupNextApp, 
  getGoogleOAuthURL,
  mongoAdapter,
  AuthrixError 
} from 'authrix';
```

### After (Optimized)
```typescript
// Core only (~7.8 kB)
import { signup, signin, authMiddleware } from 'authrix';

// Framework-specific (only when needed)
import { signupReact } from 'authrix/react'; // +3.6 kB
import { signupNextApp } from 'authrix/nextjs'; // +9.8 kB

// OAuth (only when needed)
import { getGoogleOAuthURL } from 'authrix/oauth'; // +7.8 kB

// Adapter (only when needed)
import { mongoAdapter } from 'authrix/adapters/mongo'; // +2.4 kB

// Utils (only when needed)
import { AuthrixError } from 'authrix/utils'; // +2.7 kB
```

## 🔥 Benefits

1. **🪶 Ultra-lightweight**: Core bundle is only 7.8 kB
2. **🌳 Tree-shakable**: Import only what you use
3. **📱 Framework-agnostic**: Separate modules for each framework
4. **⚡ Fast loading**: Smaller bundles = faster page loads
5. **🔄 Backward compatible**: Existing code still works
6. **📦 Modular**: Clear separation of concerns

## 💡 Best Practices

1. **Start small**: Import from `authrix` core first
2. **Add as needed**: Import framework-specific modules only when required
3. **Lazy load**: Import OAuth and utilities modules only when using those features
4. **Choose your adapter**: Import only the database adapter you're using
5. **Bundle analysis**: Use tools like `webpack-bundle-analyzer` to verify your bundle size

This optimization reduces the library size by **~65%** while maintaining full functionality and improving developer experience through better modularity.
