# Framework Usage Examples

> **Note:** OAuth providers are now exported separately to prevent environment variable errors. Import them from `authrix/oauth` or individual provider files. See [OAUTH_USAGE.md](./OAUTH_USAGE.md) for details.

## Table of Contents

- [Express.js](#expressjs)
- [Next.js App Router](#nextjs-app-router)
- [Next.js Pages Router](#nextjs-pages-router)
- [React SPA](#react-spa-client-side)
- [Universal/Framework-Agnostic](#universalframework-agnostic-usage)
- [Middleware Examples](#middleware-examples)
- [Database Adapters](#database-adapters)

## Express.js

### Basic Setup

```typescript
import express from "express";
import cookieParser from "cookie-parser";
import { initAuth, signup, signin, logout, authMiddleware } from "authrix";
import { mongoAdapter } from "authrix/adapters/mongo";

const app = express();
app.use(express.json());
app.use(cookieParser());

// Initialize Authrix
initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter,
  cookieName: "auth_token"
});

// Authentication routes
app.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await signup(email, password, res);
    res.status(201).json({ success: true, user });
  } catch (error) {
    res.status(400).json({ success: false, error: { message: error.message } });
  }
});

app.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await signin(email, password, res);
    res.json({ success: true, user });
  } catch (error) {
    res.status(400).json({ success: false, error: { message: error.message } });
  }
});

app.post("/logout", async (req, res) => {
  try {
    await logout(res);
    res.json({ success: true, message: "Logged out successfully" });
  } catch (error) {
    res.status(400).json({ success: false, error: { message: error.message } });
  }
});

// Protected route
app.get("/profile", authMiddleware, (req, res) => {
  res.json({ success: true, user: req.user });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
```

### Advanced Express.js Setup

```typescript
import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import helmet from "helmet";
import { initAuth, createAuthMiddleware } from "authrix";
import { supabaseAdapter } from "authrix/adapters/supabase";

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// Initialize Authrix with custom configuration
initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: supabaseAdapter,
  cookieName: "secure_auth",
  jwtOptions: {
    expiresIn: "24h"
  }
});

// Custom middleware with error handling
const customAuthMiddleware = createAuthMiddleware({
  required: true,
  errorHandler: (error, req, res, next) => {
    console.error("Auth error:", error);
    res.status(401).json({ 
      error: "Authentication required",
      code: "AUTH_REQUIRED"
    });
  }
});

// API routes with different protection levels
app.use("/api/auth", require("./routes/auth"));
app.use("/api/user", customAuthMiddleware, require("./routes/user"));
app.use("/api/admin", customAuthMiddleware, require("./routes/admin"));

module.exports = app;
```

## Next.js App Router

### API Routes

```typescript
// app/api/auth/signup/route.ts
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
    
    return Response.json({ success: true, user }, { status: 201 });
  } catch (error) {
    return Response.json(
      { success: false, error: { message: error.message } },
      { status: 400 }
    );
  }
}
```

```typescript
// app/api/auth/signin/route.ts
import { signinNextApp } from "authrix/nextjs";

export async function POST(request: Request) {
  try {
    const { email, password } = await request.json();
    const user = await signinNextApp(email, password);
    
    return Response.json({ success: true, user });
  } catch (error) {
    return Response.json(
      { success: false, error: { message: error.message } },
      { status: 400 }
    );
  }
}
```

```typescript
// app/api/auth/logout/route.ts
import { logoutNextApp } from "authrix/nextjs";

export async function POST() {
  try {
    const response = logoutNextApp();
    return Response.json({ success: true }, response);
  } catch (error) {
    return Response.json(
      { success: false, error: { message: error.message } },
      { status: 400 }
    );
  }
}
```

### Server Components

```typescript
// app/profile/page.tsx
import { getCurrentUserNextApp } from "authrix/nextjs";
import { redirect } from "next/navigation";

export default async function ProfilePage() {
  const user = await getCurrentUserNextApp();
  
  if (!user) {
    redirect("/signin");
  }
  
  return (
    <div className="max-w-md mx-auto mt-8 p-6 bg-white rounded-lg shadow-md">
      <h1 className="text-2xl font-bold mb-4">Welcome, {user.email}!</h1>
      <div className="space-y-2">
        <p><strong>User ID:</strong> {user.id}</p>
        <p><strong>Email:</strong> {user.email}</p>
        {user.createdAt && (
          <p><strong>Member since:</strong> {user.createdAt.toDateString()}</p>
        )}
      </div>
    </div>
  );
}
```

### Server Actions

```typescript
// app/actions/auth.ts
"use server";

import { signupNextApp, signinNextApp } from "authrix/nextjs";
import { redirect } from "next/navigation";

export async function signupAction(formData: FormData) {
  const email = formData.get("email") as string;
  const password = formData.get("password") as string;
  
  try {
    await signupNextApp(email, password);
    redirect("/dashboard");
  } catch (error) {
    return { error: error.message };
  }
}

export async function signinAction(formData: FormData) {
  const email = formData.get("email") as string;
  const password = formData.get("password") as string;
  
  try {
    await signinNextApp(email, password);
    redirect("/dashboard");
  } catch (error) {
    return { error: error.message };
  }
}
```

### Client Components

```typescript
// app/components/AuthForm.tsx
"use client";

import { useState } from "react";
import { signupAction, signinAction } from "../actions/auth";

export default function AuthForm() {
  const [isSignup, setIsSignup] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(formData: FormData) {
    setError("");
    const result = isSignup 
      ? await signupAction(formData) 
      : await signinAction(formData);
    
    if (result?.error) {
      setError(result.error);
    }
  }

  return (
    <form action={handleSubmit} className="max-w-md mx-auto mt-8 space-y-4">
      <div>
        <label htmlFor="email" className="block text-sm font-medium">
          Email
        </label>
        <input
          type="email"
          name="email"
          required
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm"
        />
      </div>
      
      <div>
        <label htmlFor="password" className="block text-sm font-medium">
          Password
        </label>
        <input
          type="password"
          name="password"
          required
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm"
        />
      </div>
      
      {error && (
        <div className="text-red-600 text-sm">{error}</div>
      )}
      
      <button
        type="submit"
        className="w-full bg-blue-600 text-white rounded-md py-2 hover:bg-blue-700"
      >
        {isSignup ? "Sign Up" : "Sign In"}
      </button>
      
      <button
        type="button"
        onClick={() => setIsSignup(!isSignup)}
        className="w-full text-blue-600 hover:underline"
      >
        {isSignup ? "Already have an account? Sign in" : "Need an account? Sign up"}
      </button>
    </form>
  );
}
```

### Middleware

```typescript
// middleware.ts
import { NextRequest, NextResponse } from "next/server";
import { checkAuthMiddleware } from "authrix/nextjs";

export async function middleware(request: NextRequest) {
  // Check authentication for protected routes
  if (request.nextUrl.pathname.startsWith('/dashboard') ||
      request.nextUrl.pathname.startsWith('/profile') ||
      request.nextUrl.pathname.startsWith('/admin')) {
    
    const auth = await checkAuthMiddleware(request);
    
    if (!auth.isAuthenticated) {
      return NextResponse.redirect(new URL('/signin', request.url));
    }
  }
  
  // Redirect authenticated users away from auth pages
  if (request.nextUrl.pathname.startsWith('/signin') ||
      request.nextUrl.pathname.startsWith('/signup')) {
    
    const auth = await checkAuthMiddleware(request);
    
    if (auth.isAuthenticated) {
      return NextResponse.redirect(new URL('/dashboard', request.url));
    }
  }
  
  return NextResponse.next();
}

export const config = {
  matcher: ['/dashboard/:path*', '/profile/:path*', '/admin/:path*', '/signin', '/signup']
};
```

## Next.js Pages Router

### API Routes

```typescript
// pages/api/auth/signup.ts
import type { NextApiRequest, NextApiResponse } from "next";
import { initAuth, signupNextPages } from "authrix/nextjs";
import { firebaseAdapter } from "authrix/adapters/firebase";

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: firebaseAdapter,
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }
  
  try {
    const { email, password } = req.body;
    const user = await signupNextPages(email, password, res);
    
    res.status(201).json({ success: true, user });
  } catch (error) {
    res.status(400).json({ success: false, error: { message: error.message } });
  }
}
```

### Protected API Routes with HOC

```typescript
// pages/api/user/profile.ts
import { withAuth } from "authrix/nextjs";

export default withAuth(async function handler(req, res) {
  // req.user is automatically available here
  if (req.method === "GET") {
    res.json({ success: true, user: req.user });
  } else if (req.method === "PUT") {
    // Update user logic here
    res.json({ success: true, message: "Profile updated" });
  } else {
    res.status(405).json({ error: "Method not allowed" });
  }
});
```

### Pages with Authentication

```typescript
// pages/profile.tsx
import { useEffect, useState } from "react";
import { getCurrentUserReact } from "authrix/react";
import { useRouter } from "next/router";

export default function Profile() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();
  
  useEffect(() => {
    getCurrentUserReact().then(userData => {
      if (!userData) {
        router.push("/signin");
      } else {
        setUser(userData);
      }
      setLoading(false);
    });
  }, [router]);
  
  if (loading) return <div>Loading...</div>;
  if (!user) return null;
  
  return (
    <div>
      <h1>Welcome, {user.email}!</h1>
      <p>User ID: {user.id}</p>
    </div>
  );
}
```

## React SPA (Client-Side)

### Auth Context Provider

```typescript
// contexts/AuthContext.tsx
import React, { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { getCurrentUserReact, signupReact, signinReact, logoutReact } from "authrix/react";

interface User {
  id: string;
  email: string;
  createdAt?: Date;
}

interface AuthContextType {
  user: User | null;
  loading: boolean;
  signup: (email: string, password: string) => Promise<void>;
  signin: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    getCurrentUserReact().then(userData => {
      setUser(userData);
      setLoading(false);
    }).catch(() => {
      setLoading(false);
    });
  }, []);
  
  const signup = async (email: string, password: string) => {
    const result = await signupReact(email, password);
    setUser(result.user);
  };
  
  const signin = async (email: string, password: string) => {
    const result = await signinReact(email, password);
    setUser(result.user);
  };
  
  const logout = async () => {
    await logoutReact();
    setUser(null);
  };
  
  return (
    <AuthContext.Provider value={{ user, loading, signup, signin, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
```

### Protected Route Component

```typescript
// components/ProtectedRoute.tsx
import React, { ReactNode } from "react";
import { useAuth } from "../contexts/AuthContext";

interface ProtectedRouteProps {
  children: ReactNode;
  fallback?: ReactNode;
}

export function ProtectedRoute({ children, fallback }: ProtectedRouteProps) {
  const { user, loading } = useAuth();
  
  if (loading) {
    return <div className="flex justify-center p-8">Loading...</div>;
  }
  
  if (!user) {
    return fallback || <div>Please log in to access this page.</div>;
  }
  
  return <>{children}</>;
}
```

### Auth Forms

```typescript
// components/AuthForms.tsx
import React, { useState } from "react";
import { useAuth } from "../contexts/AuthContext";

export function AuthForms() {
  const [isSignup, setIsSignup] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const { signup, signin } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    
    try {
      if (isSignup) {
        await signup(email, password);
      } else {
        await signin(email, password);
      }
    } catch (error) {
      setError(error.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-md mx-auto mt-8">
      <form onSubmit={handleSubmit} className="space-y-4">
        <h2 className="text-2xl font-bold text-center">
          {isSignup ? "Sign Up" : "Sign In"}
        </h2>
        
        <div>
          <label htmlFor="email" className="block text-sm font-medium">
            Email
          </label>
          <input
            type="email"
            id="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm"
          />
        </div>
        
        <div>
          <label htmlFor="password" className="block text-sm font-medium">
            Password
          </label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm"
          />
        </div>
        
        {error && (
          <div className="text-red-600 text-sm">{error}</div>
        )}
        
        <button
          type="submit"
          disabled={loading}
          className="w-full bg-blue-600 text-white rounded-md py-2 hover:bg-blue-700 disabled:opacity-50"
        >
          {loading ? "Loading..." : (isSignup ? "Sign Up" : "Sign In")}
        </button>
        
        <button
          type="button"
          onClick={() => setIsSignup(!isSignup)}
          className="w-full text-blue-600 hover:underline"
        >
          {isSignup ? "Already have an account? Sign in" : "Need an account? Sign up"}
        </button>
      </form>
    </div>
  );
}
```

### Dashboard Component

```typescript
// components/Dashboard.tsx
import React from "react";
import { useAuth } from "../contexts/AuthContext";

export function Dashboard() {
  const { user, logout } = useAuth();

  const handleLogout = async () => {
    try {
      await logout();
    } catch (error) {
      console.error("Logout failed:", error);
    }
  };

  return (
    <div className="max-w-4xl mx-auto mt-8 p-6">
      <div className="bg-white rounded-lg shadow-md p-6">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">Dashboard</h1>
          <button
            onClick={handleLogout}
            className="bg-red-600 text-white px-4 py-2 rounded hover:bg-red-700"
          >
            Logout
          </button>
        </div>
        
        <div className="grid md:grid-cols-2 gap-6">
          <div className="bg-gray-50 p-4 rounded">
            <h2 className="text-xl font-semibold mb-2">Profile Information</h2>
            <p><strong>Email:</strong> {user?.email}</p>
            <p><strong>User ID:</strong> {user?.id}</p>
            {user?.createdAt && (
              <p><strong>Member since:</strong> {new Date(user.createdAt).toDateString()}</p>
            )}
          </div>
          
          <div className="bg-gray-50 p-4 rounded">
            <h2 className="text-xl font-semibold mb-2">Quick Actions</h2>
            <div className="space-y-2">
              <button className="block w-full text-left p-2 hover:bg-gray-100 rounded">
                Update Profile
              </button>
              <button className="block w-full text-left p-2 hover:bg-gray-100 rounded">
                Change Password
              </button>
              <button className="block w-full text-left p-2 hover:bg-gray-100 rounded">
                Privacy Settings
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
```

## Universal/Framework-Agnostic Usage

```typescript
// For custom frameworks or manual cookie handling
import { 
  initAuth, 
  signupUniversal, 
  signinUniversal, 
  validateAuth,
  createCookieString,
  parseCookies 
} from "authrix/universal";

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: yourCustomAdapter,
});

// In your custom framework handler
async function handleSignup(request: any, response: any) {
  try {
    const { email, password } = await parseRequestBody(request);
    const result = await signupUniversal(email, password);
    
    // Manually set cookie
    const cookieString = createCookieString(
      "auth_token", 
      result.token, 
      result.cookieOptions
    );
    response.setHeader("Set-Cookie", cookieString);
    
    return { success: true, user: result.user };
  } catch (error) {
    return { success: false, error: { message: error.message } };
  }
}

// Validate authentication
async function protectedHandler(request: any, response: any) {
  const cookies = parseCookies(request.headers.cookie || "");
  const token = cookies["auth_token"];
  
  const authResult = await validateAuth(token);
  
  if (!authResult.isValid) {
    return { status: 401, error: "Authentication required" };
  }
  
  // Use authResult.user for authenticated operations
  return { user: authResult.user };
}
```

## Middleware Examples

### Custom Express Middleware

```typescript
import { createAuthMiddleware } from "authrix";

// Flexible middleware for different routes
const optionalAuth = createAuthMiddleware({
  required: false,
  errorHandler: (error, req, res, next) => {
    req.user = null;
    next();
  }
});

const strictAuth = createAuthMiddleware({
  required: true,
  errorHandler: (error, req, res, next) => {
    res.status(401).json({ error: "Authentication required" });
  }
});

// Use in routes
app.get("/public", optionalAuth, (req, res) => {
  // req.user might be null
  res.json({ user: req.user, public: true });
});

app.get("/private", strictAuth, (req, res) => {
  // req.user is guaranteed to exist
  res.json({ user: req.user });
});
```

### Role-based Middleware

```typescript
import { createAuthMiddleware } from "authrix";

function createRoleMiddleware(requiredRole: string) {
  return createAuthMiddleware({
    required: true,
    customValidator: async (user) => {
      // Fetch user roles from database
      const userWithRoles = await db.findUserWithRoles(user.id);
      return userWithRoles.roles.includes(requiredRole);
    },
    errorHandler: (error, req, res, next) => {
      res.status(403).json({ error: "Insufficient permissions" });
    }
  });
}

const adminOnly = createRoleMiddleware("admin");
const moderatorOnly = createRoleMiddleware("moderator");

app.get("/admin", adminOnly, (req, res) => {
  res.json({ message: "Admin panel" });
});
```

## Database Adapters

### MongoDB Adapter Setup

```typescript
import { MongoClient } from "mongodb";

const client = new MongoClient(process.env.MONGODB_URI!);

export const mongoAdapter = {
  async findUserByEmail(email: string) {
    const db = client.db("myapp");
    return await db.collection("users").findOne({ email });
  },
  
  async findUserById(id: string) {
    const db = client.db("myapp");
    return await db.collection("users").findOne({ _id: new ObjectId(id) });
  },
  
  async createUser(data: { email: string; password: string }) {
    const db = client.db("myapp");
    const result = await db.collection("users").insertOne({
      ...data,
      createdAt: new Date()
    });
    
    return {
      id: result.insertedId.toString(),
      ...data,
      createdAt: new Date()
    };
  }
};
```

### Custom Database Adapter

```typescript
import type { AuthDbAdapter } from "authrix";

export const customAdapter: AuthDbAdapter = {
  async findUserByEmail(email: string) {
    // Your database logic here
    const user = await yourDb.query("SELECT * FROM users WHERE email = ?", [email]);
    return user ? {
      id: user.id.toString(),
      email: user.email,
      password: user.password,
      createdAt: user.created_at
    } : null;
  },
  
  async findUserById(id: string) {
    const user = await yourDb.query("SELECT * FROM users WHERE id = ?", [id]);
    return user ? {
      id: user.id.toString(),
      email: user.email,
      password: user.password,
      createdAt: user.created_at
    } : null;
  },
  
  async createUser(data: { email: string; password: string }) {
    const result = await yourDb.query(
      "INSERT INTO users (email, password, created_at) VALUES (?, ?, ?)",
      [data.email, data.password, new Date()]
    );
    
    return {
      id: result.insertId.toString(),
      email: data.email,
      password: data.password,
      createdAt: new Date()
    };
  }
};
```

## Key Benefits of the New Architecture

1. **Framework Agnostic**: Core logic separated from framework-specific code
2. **Backward Compatible**: Existing Express.js code continues to work
3. **Tree Shakable**: Import only what you need
4. **Type Safe**: Full TypeScript support across all frameworks
5. **Flexible**: Easy to adapt to new frameworks
6. **Consistent API**: Similar patterns across different frameworks

## Tips and Best Practices

### Environment Variables

```bash
# .env
JWT_SECRET=your-super-secret-jwt-key-here
MONGODB_URI=mongodb://localhost:27017/myapp
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key
```

### Error Handling

```typescript
// Global error handler for Express
app.use((error, req, res, next) => {
  if (error.name === "AuthrixError") {
    return res.status(error.statusCode || 400).json({
      error: error.message,
      code: error.code
    });
  }
  
  console.error("Unexpected error:", error);
  res.status(500).json({ error: "Internal server error" });
});
```

### Security Headers

```typescript
// Express.js
import helmet from "helmet";

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
    }
  }
}));

// Next.js (next.config.js)
module.exports = {
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          {
            key: "X-Frame-Options",
            value: "DENY"
          },
          {
            key: "X-Content-Type-Options",
            value: "nosniff"
          }
        ]
      }
    ];
  }
};
```
