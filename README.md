# Authrix

<div align="center">
  <img src="./logo/logo.svg" alt="Authrix Logo" width="220" height="180" />
  <h3>Unified, framework‑agnostic authentication for Node.js, TypeScript & modern runtimes</h3>
</div>

[![npm version](https://img.shields.io/npm/v/authrix.svg)](https://www.npmjs.com/package/authrix)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/Tests-Jest-green.svg)](https://jestjs.io/)
[![Security Focus](https://img.shields.io/badge/Security-Hardened-success.svg)](#security)

Authrix provides production‑grade authentication primitives with minimal ceremony: JWT sessions, secure cookie handling, rolling session refresh, password flows, SSO/OAuth, email flows, and extensible adapters. Version 2.1 introduces the **unified `auth` namespace** simplifying the API surface while remaining backward compatible (legacy exports emit one‑time deprecation warnings).

---

## TL;DR

```ts
import { initAuth, auth } from 'authrix';
import { mongoAdapter } from 'authrix/adapters/mongo';

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter,
  cookieName: 'auth_token',
  sessionMaxAgeMs: 7 * 24 * 60 * 60 * 1000,
  rollingSessionEnabled: true,
  rollingSessionThresholdSeconds: 15 * 60, // refresh when ≤ 15m left
});

// Express example
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  const { user } = await auth.actions.signup(email, password, { res }); // sets cookie
  res.status(201).json({ success: true, user });
});

app.post('/api/auth/signin', async (req, res) => {
  const { email, password } = req.body;
  const { user } = await auth.actions.signin(email, password, { res });
  res.json({ success: true, user });
});

app.get('/api/auth/me', async (req, res) => {
  const user = await auth.session.getCurrentUserFromRequest(req); // auto token extract
  if (!user) return res.status(401).json({ success: false, error: 'Not authenticated' });
  res.json({ success: true, user });
});

app.get('/api/private', auth.middleware.requireAuth, (req, res) => {
  res.json({ success: true, user: (req as any).user });
});
```

---

## Table of Contents
1. [Architecture](#architecture)
2. [Feature Overview](#features)
3. [Installation](#installation)
4. [Initialization & Configuration](#configuration)
5. [Unified API Surface](#unified-api)
6. [Framework Usage](#framework-usage)
7. [Sessions & Rolling Refresh](#sessions-and-rolling-refresh)
8. [Cookies & Security Defaults](#cookies)
9. [OAuth / SSO](#oauth--sso)
10. [Database Adapters](#database-adapters)
11. [Email & 2FA / Forgot Password](#email--2fa--recovery)
12. [Structured Logging](#logging)
13. [Extensibility (Adapters & Providers)](#extensibility)
14. [Migration (≤2.0 → 2.1)](#migration)
15. [Roadmap](#roadmap)
16. [Contributing](#contributing)
17. [License](#license)

---

## Architecture

```
┌──────────────────────────────────────────────┐
│                    auth                      │  <- unified facade
├──────────────┬───────────────┬───────────────┤
│ actions      │ session       │ middleware    │
│ signup/signin│ token→user    │ require/opt   │
├──────────────┴───────┬───────┴──────┬────────┤
│ handlers (Next.js)   │ cookies util │ env     │
├───────────────────────────────────────────────┤
│ Core Logic (pure functions)                   │
├───────────────────────────────────────────────┤
│ Adapters: Mongo | PostgreSQL | (Prisma WIP)   │
│ Providers: Google | GitHub | ...              │
│ Email: Gmail | SendGrid | Resend | SMTP       │
└───────────────────────────────────────────────┘
```

Design principles:
* Pure core (no framework imports) → thin framework façades.
* Minimal public surface; strong defaults; explicit opt‑ins.
* Extensible via small interfaces (db adapter, email provider, oauth provider).
* Predictable error model (`Error` with message; route layer decides JSON shape).

---

## Features

| Area | Highlights |
|------|------------|
| Auth Core | Signup, Signin, Logout, Session inspection |
| Security | Explicit JWT signature validation; cookie normalization; optional rolling refresh |
| Cookies | Central name + normalization (HttpOnly, SameSite=lax, Secure in prod) |
| OAuth/SSO | pluggable providers (Google, GitHub) with state verification |
| Email | Multiple transports (gmail, sendgrid, resend, smtp, console) |
| Recovery | Forgot password + (email) 2FA foundations |
| Adapters | MongoDB, PostgreSQL, Prisma (scaffold) |
| Logging | Structured logger with contextual warnings |
| Extensibility | Simple contracts for adapters/providers/email |

---

## Installation

```bash
npm install authrix
# or yarn add authrix / pnpm add authrix / bun add authrix
```

Peer deps (install only what you use): `mongodb`, `pg`, `next`, `react`, etc.

---

## Configuration

Call `initAuth` once at application bootstrap (server entry, Next.js edge route, etc.).

```ts
import { initAuth } from 'authrix';
import { mongoAdapter } from 'authrix/adapters/mongo';

initAuth({
  jwtSecret: process.env.JWT_SECRET!,      // required, min 32 chars recommended
  db: mongoAdapter,                        // optional if only stateless operations
  cookieName: 'auth_token',                // optional override
  forceSecureCookies: false,               // force Secure attr regardless of NODE_ENV
  sessionMaxAgeMs: 7 * 24 * 60 * 60 * 1000,// absolute lifetime of issued tokens
  rollingSessionEnabled: true,             // enable rolling refresh
  rollingSessionThresholdSeconds: 15 * 60, // refresh when remaining life ≤ threshold
});
```

Config fields (selected):
* `jwtSecret` (string, required)
* `db` (adapter) – provides persistence for user lookup & future session state needs
* `cookieName` (string) – default: `auth_token`
* `sessionMaxAgeMs` (number) – default: 7 days
* `rollingSessionEnabled` (boolean) – off by default if unspecified
* `rollingSessionThresholdSeconds` (number) – default internal heuristic (e.g. 900)
* `forceSecureCookies` (boolean) – override environment heuristic

Access at runtime via `auth.config` (read-only snapshot / accessor pattern) if needed.

---

## Unified API

```ts
import { auth } from 'authrix';

auth.actions.signup(email, password, { res?, autoSignin? });
auth.actions.signin(email, password, { res? });
auth.actions.logout({ res? });

const user = await auth.session.getCurrentUserFromToken(token);
const user2 = await auth.session.getCurrentUserFromRequest(req);
const { user: refreshed, refreshedToken } = await auth.session.getCurrentUserFromTokenWithRefresh(token);

// Express / API middleware
auth.middleware.requireAuth(req, res, next); // attaches user → req.user
auth.middleware.optionalAuth(req, res, next);

// Next.js route handlers (App Router) dynamic helpers
auth.handlers.signup(request);
auth.handlers.signin(request);
auth.handlers.logout(request);
auth.handlers.currentUser(request);

// Cookie helpers
auth.cookies.name;              // string
auth.cookies.create(token, opts?); // returns Set-Cookie string
auth.cookies.clear();              // logout cookie string

// Environment insight
auth.env.isNext; auth.env.isNode; auth.env.details; 
```

All legacy direct exports (e.g. `signupCore`) still work but emit a single deprecation warning (development only).

---

## Framework Usage

### Express
```ts
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  const { user } = await auth.actions.signup(email, password, { res });
  res.status(201).json({ success: true, user });
});

app.get('/api/secure', auth.middleware.requireAuth, (req, res) => {
  res.json({ success: true, user: (req as any).user });
});
```

### Next.js (App Router)
```ts
// app/api/auth/signin/route.ts
import { auth } from 'authrix';
export const POST = auth.handlers.signin; // returns Response with cookie

// app/api/auth/me/route.ts
import { auth } from 'authrix';
export const GET = auth.handlers.currentUser;
```

### Universal (Raw Fetch / Edge)
Use `auth.session.getCurrentUserFromToken(token)` after extracting cookie manually if necessary.

---

## Sessions and Rolling Refresh

Rolling refresh keeps users active without silent expiration while preserving an absolute max lifetime:
1. Each request (middleware or explicit call) checks remaining lifetime.
2. If `remainingSeconds ≤ rollingSessionThresholdSeconds` and `rollingSessionEnabled`, a new token is issued + cookie updated.
3. Token is still fully signed & time‑boxed by `sessionMaxAgeMs` at issue time.

Disable by setting `rollingSessionEnabled: false`.

Edge cases handled: tampered token → rejection; expired token → null user; refresh only when threshold reached (no churn).

---

## Cookies

Defaults (unless overridden):
* `HttpOnly: true`
* `SameSite: lax`
* `Secure: true` in production OR when `forceSecureCookies` true
* `Path: /`
* `Max-Age` normalized to seconds (internal uses ms; outward always correct)

Helpers:
```ts
const headerValue = auth.cookies.create(token, { sameSite: 'strict' });
res.setHeader('Set-Cookie', headerValue);
```

Logout cookie:
```ts
res.setHeader('Set-Cookie', auth.cookies.clear());
```

---

## OAuth / SSO

Providers (Google, GitHub) reside under `providers/*`. High‑level orchestration lives in core and is exposed via handler helpers (see `docs/OAUTH_USAGE.md`). Unified namespace does not yet encapsulate bespoke OAuth flows; migration planned (see roadmap). For now, continue using documented provider helpers; future minor will add `auth.oauth.*` façade.

---

## Database Adapters

Currently shipped: MongoDB, PostgreSQL. Prisma scaffold exists (contributions welcome).

Adapter contract snapshot (simplified):
```ts
interface AuthDbAdapter {
  createUser(data): Promise<User>;
  getUserByEmail(email): Promise<User|null>;
  getUserById(id): Promise<User|null>;
  updateUser(id, partial): Promise<User>;
  // plus SSO + password reset helpers
}
```

Normalization: emails / usernames are lowercased & trimmed in adapters (maintain this in custom adapters). Duplicate conflicts must throw informative `Error` messages.

---

## Email & 2FA / Recovery

Email providers selected at config time. See `docs/2FA_EMAIL_SETUP_GUIDE.md` & `docs/SSO_FORGOT_PASSWORD_GUIDE.md` for end‑to‑end flows. These modules will adopt structured logging fully in upcoming releases (currently partially migrated).

---

## Logging

Use the central logger:
```ts
import { logger } from 'authrix';
logger.debug('Auth flow start', { email });
logger.structuredWarn({
  category: 'deprecation',
  action: 'legacy-signup',
  outcome: 'fallback',
  message: 'signupCore is deprecated; use auth.actions.signup'
});
```

Categories used so far: `deprecation`, `security`, `adapter`, `session`.

You can wrap or replace output by providing a custom transport (see source of `utils/logger.ts`).

---

## Extensibility

| Extension | How |
|-----------|-----|
| DB Adapter | Implement `AuthDbAdapter` and pass to `initAuth` |
| Email Provider | Implement send interface (see existing providers) |
| OAuth Provider | Follow provider module pattern (token exchange + profile map) |
| Middleware | Compose `auth.middleware.requireAuth` inside your framework adapters |

Design goals: small, testable, dependency‑light surfaces.

---

## Migration

If upgrading from ≤2.0.x:

| Old | New |
|-----|-----|
| `signupCore(email,pw,res?)` | `auth.actions.signup(email,pw,{res})` |
| `signinCore` | `auth.actions.signin` |
| `logoutCore` | `auth.actions.logout` |
| `getCurrentUser(req)` | `auth.session.getCurrentUserFromRequest(req)` |
| scattered cookie helpers | `auth.cookies.*` |

Deprecations emit once per symbol (non‑prod). Planned removal: 3.0.0 (see roadmap). Begin migrating now; wrappers will persist through at least 2.3.x.

---

## Roadmap

See also `RELEASE_NOTES_2.1.0.md` for detailed schedule.

### Near‑Term (2.1.x → 2.2.x)
* Complete structured logging coverage (providers, email).
* Rolling session test matrix & docs.
* Expanded cookie matrix across runtimes.
* Publish detailed migration guide (FAQ, code mods suggestions).

### Mid‑Term (2.2.x → 2.3.x)
* Provider observability events (oauth.start/success/failure).
* Finalize Prisma adapter.
* JWT secret rotation helper.
* Enhanced recovery & 2FA audit logging.

### 3.0.0 Themes
* Remove deprecated exports.
* Optional strict security mode (always secure cookies, enforced config validation).
* Stable machine‑readable error codes + typed error classes.
* Audit event publishing hook.

---

## Contributing

1. Fork & clone.
2. `npm install`
3. Run tests: `npm test`
4. For significant changes open a draft PR early.

Quality gates: build (`npm run build`), type checks, Jest. Avoid committing `dist/`.

Issue labels you can use: `adapter`, `provider`, `security`, `docs`, `enhancement`.

---

## License

MIT © 2025 Authrix Contributors

---

Need help or migration guidance? Open an issue with the `unified-api` label.

