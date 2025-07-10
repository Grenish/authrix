# Framework Usage Examples

## Express.js (Original - Still Supported)

```typescript
import express from "express";
import cookieParser from "cookie-parser";
import { initAuth, signin, signup, logout, authMiddleware, mongoAdapter } from "authrix";

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

// Protected route
app.get("/profile", authMiddleware, (req, res) => {
  res.json({ success: true, user: req.user });
});
```

## Next.js App Router

```typescript
// app/auth/signup/route.ts
import { initAuth, signupNextApp, mongoAdapter } from "authrix";

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

// app/auth/signin/route.ts
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

// app/profile/page.tsx
import { getCurrentUserNextApp } from "authrix";
import { redirect } from "next/navigation";

export default async function ProfilePage() {
  const user = await getCurrentUserNextApp();
  
  if (!user) {
    redirect("/signin");
  }
  
  return (
    <div>
      <h1>Welcome, {user.email}!</h1>
      <p>User ID: {user.id}</p>
    </div>
  );
}
```

## Next.js Pages Router

```typescript
// pages/api/auth/signup.ts
import type { NextApiRequest, NextApiResponse } from "next";
import { initAuth, signupNextPages, mongoAdapter } from "authrix";

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter,
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

// pages/api/auth/me.ts
import { withAuth } from "authrix";

export default withAuth(async function handler(req, res) {
  // req.user is automatically available here
  res.json({ success: true, user: req.user });
});

// pages/profile.tsx
import { useEffect, useState } from "react";
import { getCurrentUserReact } from "authrix";

export default function Profile() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    getCurrentUserReact().then(userData => {
      setUser(userData);
      setLoading(false);
    });
  }, []);
  
  if (loading) return <div>Loading...</div>;
  if (!user) return <div>Please sign in</div>;
  
  return (
    <div>
      <h1>Welcome, {user.email}!</h1>
    </div>
  );
}
```

## React SPA (Client-Side)

```typescript
// AuthContext.tsx
import React, { createContext, useContext, useEffect, useState } from "react";
import { getCurrentUserReact, signupReact, signinReact, logoutReact } from "authrix";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    getCurrentUserReact().then(userData => {
      setUser(userData);
      setLoading(false);
    });
  }, []);
  
  const signup = async (email, password) => {
    const result = await signupReact(email, password);
    setUser(result.user);
    return result;
  };
  
  const signin = async (email, password) => {
    const result = await signinReact(email, password);
    setUser(result.user);
    return result;
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

// components/ProtectedRoute.tsx
import { withAuthReact } from "authrix";

const LoginComponent = () => <div>Please log in</div>;

export const ProtectedRoute = withAuthReact({
  fallback: LoginComponent,
  redirectTo: "/login"
});

// Usage
function MyProtectedComponent() {
  return <div>This is protected content</div>;
}

export default ProtectedRoute(MyProtectedComponent);
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
} from "authrix";

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: yourCustomAdapter,
});

// In your custom framework handler
async function handleSignup(request, response) {
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
async function protectedHandler(request, response) {
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

## Key Benefits of the New Architecture

1. **Framework Agnostic**: Core logic separated from framework-specific code
2. **Backward Compatible**: Existing Express.js code continues to work
3. **Tree Shakable**: Import only what you need
4. **Type Safe**: Full TypeScript support across all frameworks
5. **Flexible**: Easy to adapt to new frameworks
6. **Consistent API**: Similar patterns across different frameworks
