# Authrix

**Authrix** is a lightweight, flexible authentication library for Node.js and TypeScript.
Designed to be database-agnostic and framework-agnostic, it supports custom adapters for MongoDB, Firebase, Supabase, and more.

Built for developers who want full control over authentication logic without the bloat of UI or opinionated frameworks. Works seamlessly with **Express.js**, **Next.js**, **React**, and any other JavaScript framework.

---

## ⚠️ Status

This library is available on npm but is still in **early development** and has not been thoroughly tested. It is not recommended for production use at this stage, as it may contain bugs or incomplete features that could lead to unexpected behavior.

---

## ✨ Features

- 🔐 User signup and signin with secure JWT-based authentication
- 🍪 Cookie-based session management with HttpOnly and secure flags
- 🔌 Pluggable database adapters: MongoDB, Firebase, Supabase, or custom
- 🌐 **Framework-agnostic**: Works with Express.js, Next.js, React, and more
- 🚀 OAuth provider helpers for GitHub and Google
- 🛡️ Flexible middleware for route protection
- 📝 TypeScript-first with strong typing for easy integration
- 🪶 Minimal dependencies, zero UI — integrate with any frontend or backend
- 🔄 Backward compatible with existing Express.js implementations

---

## 🚀 Framework Support

### Express.js (Original)
```typescript
import { initAuth, signin, signup, authMiddleware } from "authrix";
```

### Next.js App Router
```typescript
import { signupNextApp, getCurrentUserNextApp } from "authrix";
```

### Next.js Pages Router
```typescript
import { signupNextPages, withAuth } from "authrix";
```

### React SPA
```typescript
import { signupReact, getCurrentUserReact, withAuthReact } from "authrix";
```

### Universal (Any Framework)
```typescript
import { signupUniversal, validateAuth } from "authrix";
```

---

## Installation

```bash
npm publish --access public
```

---

## Quick Start

### Express.js (Traditional)

```typescript
import express from "express";
import cookieParser from "cookie-parser";
import { initAuth, signin, signup, authMiddleware, mongoAdapter } from "authrix";

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter,
});

const app = express();
app.use(express.json());
app.use(cookieParser());

app.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await signup(email, password, res);
    res.status(201).json({ success: true, user });
  } catch (error) {
    res.status(400).json({ success: false, error: { message: error.message } });
  }
});

app.get("/profile", authMiddleware, (req, res) => {
  res.json({ success: true, user: req.user });
});

app.listen(3000);
```

### Next.js App Router

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
    return Response.json({ success: false, error: { message: error.message } }, { status: 400 });
  }
}

// app/profile/page.tsx
import { getCurrentUserNextApp } from "authrix";
import { redirect } from "next/navigation";

export default async function ProfilePage() {
  const user = await getCurrentUserNextApp();
  if (!user) redirect("/signin");
  
  return <div>Welcome, {user.email}!</div>;
}
```

### React SPA

```typescript
// hooks/useAuth.ts
import { useState, useEffect } from "react";
import { getCurrentUserReact, signupReact, signinReact, logoutReact } from "authrix";

export function useAuth() {
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
  
  return { user, loading, signup, signin, logout };
}
```

---

## 📁 Framework-Specific Documentation

For detailed examples and advanced usage patterns, see:
- [Framework Usage Examples](./FRAMEWORK_USAGE.md)

---

## Configuration

Call `initAuth()` once at startup to configure:

| Option       | Description                                      | Required |
| ------------ | ------------------------------------------------ | -------- |
| `jwtSecret`  | Secret key to sign JWT tokens                    | Yes      |
| `db`         | Database adapter implementing `AuthDbAdapter`    | Yes      |
| `cookieName` | Name of the auth cookie (default `"auth_token"`) | No       |

---

## Adapters (Planned)

You must provide a database adapter implementing:

```ts
interface AuthDbAdapter {
  findUserByEmail(email: string): Promise<AuthUser | null>;
  findUserById(id: string): Promise<AuthUser | null>;
  createUser(data: { email: string; password: string }): Promise<AuthUser>;
}
```

See [Mongo Adapter](./adapters/mongo.ts) for example.

---

## OAuth Providers (Planned)

Authrix provides helper functions to integrate GitHub and Google OAuth login flows.
Check out the `/providers` directory for usage examples.

---

## Contributing

Contributions are welcome! Please open issues or pull requests for bugs, features, or adapters for other databases.

---

## License

MIT License. See [LICENSE](./LICENSE) for details.