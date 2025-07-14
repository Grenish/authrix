# Authrix

> A lightweight, framework-agnostic authentication library for Node.js and TypeScript

[![npm version](https://img.shields.io/npm/v/authrix.svg)](https://www.npmjs.com/package/authrix)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/Tests-Jest-green.svg)](https://jestjs.io/)

**Authrix** is a production-ready, database-agnostic authentication library designed for developers who want full control over their authentication logic. No UI, no opinions, just flexible auth that works with any framework.

> **⚠️ Development Notice**
> 
> Authrix is currently under active development. While the core functionality is stable and tested, some features and use cases are still being refined. We recommend:
> - Testing thoroughly in your development environment
> - Checking the [issues page](https://github.com/Grenish/authrix/issues) for known limitations
> - Contributing feedback and bug reports to help us improve
> - Using caution in production environments until v1.0.0 stable release
> 
> We appreciate your patience and contributions as we work towards a stable release! 🚀

## ✨ Features

- 🔐 **Secure JWT Authentication** - Signup, signin, and session management
- 🍪 **HttpOnly Cookie Support** - Secure, automatic cookie handling
- 🔌 **Database Agnostic** - MongoDB, Firebase, Supabase, or custom adapters
- 🌐 **Framework Agnostic** - Express.js, Next.js, React, or any JavaScript framework
- 🚀 **OAuth Providers** - Built-in GitHub and Google OAuth support
- 🛡️ **Flexible Middleware** - Route protection with customizable options
- 📝 **TypeScript First** - Full type safety and IntelliSense support
- 🪶 **Minimal Bundle** - Modular imports, only load what you need
- 🔄 **Edge Runtime Compatible** - Works in Next.js Edge Runtime
- ⚡ **Production Ready** - Thoroughly tested with comprehensive error handling

## 📦 Installation

Choose your preferred package manager:

```bash
# npm
npm install authrix

# yarn
yarn add authrix

# pnpm
pnpm add authrix

# bun
bun add authrix
```

## 🚀 Quick Start

### Express.js

```typescript
import express from "express";
import cookieParser from "cookie-parser";
import { initAuth, signup, signin, authMiddleware } from "authrix";
import { mongoAdapter } from "authrix/adapters/mongo";

// Initialize Authrix
initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter,
});

const app = express();
app.use(express.json());
app.use(cookieParser());

// Registration
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await signup(email, password, res);
    res.status(201).json({ success: true, user });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await signin(email, password, res);
    res.json({ success: true, user });
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

// Protected route
app.get("/profile", authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000);
```

### Next.js App Router

```typescript
// app/api/auth/register/route.ts
import { initAuth, signupNextApp } from "authrix/nextjs";
import { mongoAdapter } from "authrix/adapters/mongo";

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter,
});

export async function POST(request: Request) {
  try {
    const { email, password } = await request.json();
    const user = await signupNextApp(email, password);
    return Response.json({ user }, { status: 201 });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 400 });
  }
}
```

### React SPA

```typescript
import { signupReact, getCurrentUserReact } from "authrix/react";

function AuthComponent() {
  const [user, setUser] = useState(null);

  const handleSignup = async (email, password) => {
    try {
      const result = await signupReact(email, password);
      setUser(result.user);
    } catch (error) {
      console.error("Signup failed:", error.message);
    }
  };

  useEffect(() => {
    getCurrentUserReact().then(setUser);
  }, []);

  return (
    <div>
      {user ? (
        <p>Welcome, {user.email}!</p>
      ) : (
        <button onClick={() => handleSignup("user@example.com", "password123")}>
          Sign Up
        </button>
      )}
    </div>
  );
}
```

## 🏗️ Architecture

### Database Adapters

Authrix uses a simple adapter pattern for database integration:

```typescript
interface AuthDbAdapter {
  findUserByEmail(email: string): Promise<AuthUser | null>;
  findUserById(id: string): Promise<AuthUser | null>;
  createUser(data: { email: string; password: string }): Promise<AuthUser>;
}

interface AuthUser {
  id: string;
  email: string;
  password: string;
  createdAt?: Date;
  [key: string]: any; // Additional user fields
}
```

### Available Adapters

```typescript
// MongoDB
import { mongoAdapter } from "authrix/adapters/mongo";

// Supabase
import { supabaseAdapter } from "authrix/adapters/supabase";

// Firebase
import { firebaseAdapter } from "authrix/adapters/firebase";

// Custom adapter
const customAdapter: AuthDbAdapter = {
  async findUserByEmail(email) { /* your implementation */ },
  async findUserById(id) { /* your implementation */ },
  async createUser(data) { /* your implementation */ },
};
```

## 🔐 Security Features

### Password Hashing
- **bcryptjs** for secure password hashing
- Configurable salt rounds (default: 12)
- Automatic password validation

### JWT Tokens
- **jsonwebtoken** for secure token generation
- Configurable expiration (default: 7 days)
- Automatic signature verification

### Cookie Security
- **HttpOnly** flags prevent XSS attacks
- **Secure** flag in production
- **SameSite** protection against CSRF
- Automatic cookie clearing on logout

### Input Validation
- Email format validation
- Password strength requirements  
- Automatic sanitization

## 🛠️ Framework Support

### Modular Imports

```typescript
// Core (7.8 kB) - Essential authentication
import { initAuth, signup, signin } from "authrix";

// Next.js support (+9.8 kB)
import { signupNextApp, getCurrentUserNextApp } from "authrix/nextjs";

// React support (+3.6 kB)
import { signupReact, getCurrentUserReact } from "authrix/react";

// OAuth providers (+7.8 kB)
import { getGoogleOAuthURL, handleGoogleCallback } from "authrix/oauth";

// Universal/Framework-agnostic
import { signupUniversal, validateAuth } from "authrix/universal";
```

### Next.js Edge Runtime

```typescript
// middleware.ts - Edge Runtime Compatible
import { checkAuthMiddleware } from 'authrix/nextjs';

export async function middleware(request: NextRequest) {
  const auth = await checkAuthMiddleware(request);
  
  if (!auth.isAuthenticated && request.nextUrl.pathname.startsWith('/dashboard')) {
    return NextResponse.redirect(new URL('/login', request.url));
  }
}
```

## 🔑 OAuth Integration

### Google OAuth

```typescript
import { getGoogleOAuthURL, handleGoogleCallback } from "authrix/oauth";

// Generate OAuth URL
const authUrl = getGoogleOAuthURL("random-state-string");

// Handle callback
app.get("/auth/google/callback", async (req, res) => {
  try {
    const { code } = req.query;
    const oauthUser = await handleGoogleCallback(code);
    
    // Create or find user in your database
    // Generate JWT and set cookie
    // Redirect to dashboard
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
```

### GitHub OAuth

```typescript
import { getGitHubOAuthURL, handleGitHubCallback } from "authrix/oauth";

// Similar API to Google OAuth
const authUrl = getGitHubOAuthURL("random-state-string");
const oauthUser = await handleGitHubCallback(code);
```

## 📚 API Reference

### Core Functions

#### `initAuth(config)`
Initialize Authrix with your configuration.

```typescript
initAuth({
  jwtSecret: string;      // Required: JWT signing secret
  db: AuthDbAdapter;      // Required: Database adapter
  cookieName?: string;    // Optional: Cookie name (default: "auth_token")
});
```

#### `signup(email, password, res?)`
Register a new user.

```typescript
const user = await signup("user@example.com", "password123", res);
// Returns: { id: string, email: string }
```

#### `signin(email, password, res?)`
Authenticate an existing user.

```typescript
const user = await signin("user@example.com", "password123", res);
// Returns: { id: string, email: string }
```

#### `getCurrentUser(req)`
Get the current authenticated user from request.

```typescript
const user = await getCurrentUser(req);
// Returns: { id: string, email: string, createdAt?: Date } | null
```

### Middleware

#### `authMiddleware`
Express.js middleware for route protection.

```typescript
app.get("/protected", authMiddleware, (req, res) => {
  // req.user is automatically available
  res.json({ user: req.user });
});
```

#### `createAuthMiddleware(options)`
Flexible middleware for any framework.

```typescript
const middleware = createAuthMiddleware({
  required: true,                    // Throw error if not authenticated
  tokenExtractor: (req) => string,   // Custom token extraction
  errorHandler: (error, req, res) => void  // Custom error handling
});
```

### Framework-Specific Functions

#### Next.js App Router
- `signupNextApp(email, password)`
- `signinNextApp(email, password)`
- `getCurrentUserNextApp()`
- `checkAuthMiddleware(request)`

#### Next.js Pages Router
- `signupNextPages(email, password, res)`
- `signinNextPages(email, password, res)`
- `getCurrentUserNextPages(req)`
- `withAuth(handler)` - HOC for API routes

#### React
- `signupReact(email, password)`
- `signinReact(email, password)`
- `getCurrentUserReact()`
- `logoutReact()`

## 🧪 Testing

Authrix includes comprehensive test coverage:

```bash
# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

## 📖 Documentation

- [Framework Usage Examples](./FRAMEWORK_USAGE.md)
- [OAuth Usage Guide](./OAUTH_USAGE.md)
- [Edge Runtime Guide](./EDGE_RUNTIME_GUIDE.md)
- [Next.js Production Guide](./NEXTJS_PRODUCTION_GUIDE.md)
- [Bundle Optimization](./BUNDLE_OPTIMIZATION.md)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](./CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/Grenish/authrix.git
cd authrix

# Install dependencies
npm install

# Run tests
npm test

# Build the project
npm run build
```

### Adapter Development

Need support for a new database? Create a custom adapter:

```typescript
import type { AuthDbAdapter } from "authrix";

export const yourDbAdapter: AuthDbAdapter = {
  async findUserByEmail(email: string) {
    // Implementation for your database
  },
  async findUserById(id: string) {
    // Implementation for your database
  },
  async createUser(data: { email: string; password: string }) {
    // Implementation for your database
  },
};
```

## 🐛 Issues & Support

- 🐛 [Report bugs](https://github.com/Grenish/authrix/issues/new?template=bug_report.md)
- 💡 [Request features](https://github.com/Grenish/authrix/issues/new?template=feature_request.md)
- ❓ [Ask questions](https://github.com/Grenish/authrix/discussions)

## 📄 License

MIT License - see [LICENSE](./LICENSE) for details.

Copyright (c) 2025 [Grenish Rai](https://github.com/Grenish)

---

**Authrix** - Simple, secure, and flexible authentication for modern applications.