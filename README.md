# Authrix

**Authrix** is a lightweight, flexible authentication library for Node.js and TypeScript.
Designed to be database-agnostic and easy to integrate, it supports custom adapters for MongoDB, Firebase, Supabase, Prisma, and more.

Built for developers who want full control over authentication logic without the bloat of UI or opinionated frameworks.

---

## ⚠️ Status

This library is **not yet published** on npm and is under active development.
APIs and features may change before the first stable release.


---

## Features (Planned)

- User signup and signin with secure JWT-based authentication
- Cookie-based session management with HttpOnly and secure flags
- Pluggable database adapters: MongoDB, Firebase, Supabase, Prisma, or custom
- OAuth provider helpers for GitHub and Google
- Middleware for route protection (`requireAuth`)
- TypeScript-first with strong typing for easy integration
- Minimal dependencies, zero UI — integrate with any frontend or backend

---

## Installation

TBA

---

## Quick Start (Planned)

```ts
import express from "express";
import { initAuth, signin, signup, logout, requireAuth } from "authrix";
import { mongoAdapter } from "./adapters/mongo";

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter,
  cookieName: "auth_token",
});

const app = express();
app.use(express.json());
app.use(require("cookie-parser")());

app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  const user = await signup(email, password, res);
  res.status(201).json(user);
});

app.post("/signin", async (req, res) => {
  const { email, password } = req.body;
  const user = await signin(email, password, res);
  res.json(user);
});

app.post("/logout", (req, res) => {
  logout(res);
  res.json({ message: "Logged out successfully" });
});

app.get("/profile", requireAuth, (req, res) => {
  res.json(req.user);
});

app.listen(3000);
```

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

MIT © \[Your Name or Company]