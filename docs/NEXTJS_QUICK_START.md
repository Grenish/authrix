# Authrix + Next.js (App Router) Quick Start

This guide shows the fastest way to wire up Authrix in a Next.js App Router project: initialize Authrix, add signup/signin/logout endpoints, and set up forgot password.

## 1) Install and configure

- Install: `npm install authrix`
- Add environment variables (for Mongo adapter and JWT):
  - `JWT_SECRET` (12+ chars)
  - `MONGO_URI` (e.g., mongodb+srv://...)
  - `DB_NAME` (e.g., myapp)
  - Optional (email providers for forgot password): `RESEND_API_KEY` | `SENDGRID_API_KEY` | SMTP vars

## 2) Initialize Authrix once (server-only module)

Create `src/lib/authrix.ts` (or `app/lib/authrix.ts`) and call `initAuth` exactly once at import time.

```ts
// src/lib/authrix.ts
import { initAuth } from 'authrix';
import { mongoAdapter } from 'authrix/adapters/mongo';

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter,
  // Optional: customize cookie name or security
  // cookieName: 'auth_token',
  // forceSecureCookies: process.env.NODE_ENV === 'production',
  // Optional: email providers for forgot password flows
  email: { autoDetect: true },
});
```

Tip: Import this module before exporting any route handlers so configuration is ready.

### Alternative: configure DB without env (factory)

If you prefer not to rely on env for DB config, use the factory directly:

```ts
// src/lib/authrix.ts
import { initAuth } from 'authrix';
import { createMongoAdapter, configureMongoAdapter } from 'authrix/adapters/mongo';

// Option A — direct factory
const db = createMongoAdapter({
  uri: process.env.MONGO_URI!,
  // Either pass dbName explicitly or omit if included in the URI path (mongodb://.../mydb)
  dbName: process.env.DB_NAME,
  // optional: retryConnect: true, retryAttempts: 3
});

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db,
  email: { autoDetect: true },
});

// Option B — global override + keep mongoAdapter
// configureMongoAdapter({ uri: 'mongodb://127.0.0.1:27017/mydb' });
// initAuth({ jwtSecret: process.env.JWT_SECRET!, db: mongoAdapter });
```

## 3) Auth endpoints (App Router)

Create routes and export Authrix’s prebuilt handlers. These return `Response` and set `Set-Cookie` automatically.

Runtime note (MongoDB): The MongoDB driver requires the Node.js runtime. In App Router route files, add:

```ts
export const runtime = 'nodejs';
```

Signup
```ts
// app/api/auth/signup/route.ts
import '@/lib/authrix';
import { auth } from 'authrix';

export const runtime = 'nodejs';
export const POST = auth.handlers.signup;
```

Signin
```ts
// app/api/auth/signin/route.ts
import '@/lib/authrix';
import { auth } from 'authrix';

export const runtime = 'nodejs';
export const POST = auth.handlers.signin;
```

Logout
```ts
// app/api/auth/logout/route.ts
import '@/lib/authrix';
import { auth } from 'authrix';

export const runtime = 'nodejs';
export const POST = auth.handlers.logout;
```

Current user
```ts
// app/api/auth/current-user/route.ts
import '@/lib/authrix';
import { auth } from 'authrix';

export const runtime = 'nodejs';
export const GET = auth.handlers.currentUser;
```

Validate token (useful for middleware-assisted checks)
```ts
// app/api/auth/validate/route.ts
import '@/lib/authrix';
import { auth } from 'authrix';

export const runtime = 'nodejs';
export const POST = auth.handlers.validateToken;
```

## 4) Forgot password (App Router)

Use the core forgot-password functions in small wrappers.

Initiate reset (send code)
```ts
// app/api/auth/forgot/initiate/route.ts
import '@/lib/authrix';
import { initiateForgotPassword } from 'authrix/forgotPassword';

export async function POST(request: Request) {
  try {
    const { email } = await request.json();
    if (!email) return Response.json({ error: 'Email is required' }, { status: 400 });

    const result = await initiateForgotPassword(email, {
      // Optional tuning: codeLength, codeExpiration, rate limits, templates
      useEmailService: true,
    });
    return Response.json(result);
  } catch (err: any) {
    return Response.json({ error: err?.message || 'Failed to initiate reset' }, { status: 500 });
  }
}
```

Complete reset (verify code and set new password)
```ts
// app/api/auth/forgot/reset/route.ts
import '@/lib/authrix';
import { resetPasswordWithCode } from 'authrix/forgotPassword';

export async function POST(request: Request) {
  try {
    const { email, code, newPassword } = await request.json();
    if (!email || !code || !newPassword) {
      return Response.json({ error: 'Email, code, and newPassword are required' }, { status: 400 });
    }

    const result = await resetPasswordWithCode(email, code, newPassword, {
      // Optional: requireStrongPassword, invalidateAllSessions
    });
    return Response.json(result);
  } catch (err: any) {
    const message = err?.message || 'Failed to reset password';
    const status = /invalid|expired|unauthorized/i.test(message) ? 401 : 400;
    return Response.json({ error: message }, { status });
  }
}
```

## 5) Client usage (minimal)

- Signup/signin: POST `{ email, password }` to `/api/auth/signup` or `/api/auth/signin`.
- Cookies are httpOnly; fetch user via `/api/auth/current-user`.

Example (React client action)
```ts
export async function signIn(email: string, password: string) {
  const res = await fetch('/api/auth/signin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  if (!res.ok) throw new Error('Signin failed');
  return res.json();
}
```

## 6) Optional: Middleware check

You can add a lightweight check in `middleware.ts` using a validation endpoint above.

```ts
// middleware.ts (optional)
import { NextResponse } from 'next/server';

export async function middleware(request: Request) {
  const token = (request as any).cookies?.get?.('auth_token')?.value;
  if (!token) return NextResponse.next();
  const res = await fetch(new URL('/api/auth/validate', request.url), {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}` }
  });
  // Optionally redirect if invalid
  return NextResponse.next();
}

export const config = { matcher: ['/dashboard/:path*'] };
```

## 7) Troubleshooting

- Ensure `initAuth` ran before handlers (import your `lib/authrix` in each route file).
- For Mongo (env flow): set `MONGO_URI` and `DB_NAME`.
- Password pepper: set `AUTHRIX_PASSWORD_PEPPER` (32+ chars) in all environments. Changing this will invalidate existing password hashes; in development, Authrix can verify using a previous pepper once and then rehash to the current pepper. You can disable that behavior via `AUTHRIX_ALLOW_PREV_PEPPER_FALLBACK=false`.
- For Mongo (App Router): add `export const runtime = 'nodejs'` to each `/api/auth/*` route file to ensure the Node.js runtime (Edge does not support the Mongo driver).
- Error: missing DB name. Fix one of:
  - Set `DB_NAME` env (preferred).
  - Use `MONGO_DB` env (deprecated; accepted with one-time warning, migrate to `DB_NAME`).
  - Include the database segment in the URI (e.g., `mongodb://127.0.0.1:27017/mydb`).
  - Use the factory: `createMongoAdapter({ uri, dbName })`.

Troubleshooting sign-in: If you see “Invalid email or password” after changing secrets, check for pepper drift. Set a stable `AUTHRIX_PASSWORD_PEPPER`. In dev, fallback verification may succeed once and rehash; to force strict behavior, set `AUTHRIX_ALLOW_PREV_PEPPER_FALLBACK=false`.
- For forgot password email, provide provider creds or keep `email.autoDetect: true` and set `RESEND_API_KEY`/`SENDGRID_API_KEY`/SMTP env.
- Handlers must be exported as function references (as above). They return `Response` and set cookies for you.

Migration note: `MONGO_DB` is still accepted but will log a one-time deprecation warning; switch to `DB_NAME`.
