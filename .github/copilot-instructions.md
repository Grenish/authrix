# Authrix AI Contributor Instructions

Purpose: Enable an AI agent to make high-quality, merge-ready contributions fast. Focus on concrete project realities, not generic advice.

## 1. Architecture Mental Model
- Modular auth library: core logic in `src/core` (signup, signin, session, 2FA, SSO) + thin framework façades (`src/nextjs.ts`, `src/react.ts`, `src/middleware.ts`, `src/universal.ts`).
- Extensibility via adapters and providers:
  - Database adapters in `src/adapters` (Mongo, PostgreSQL, Prisma bridge placeholder). Each implements the `AuthDbAdapter` contract (see `src/types/db` — infer shapes from usages like in `mongo.ts`).
  - OAuth/SSO providers in `src/providers` (Google, GitHub) invoked through higher-level SSO orchestration in core.
  - Email senders in `src/email` (gmail, sendgrid, resend, smtp, console) selected by config.
- Public surface is re-exported through `src/index.ts` and entrypoints declared in `package.json` `exports` map. Keep API stable unless intentionally versioning.
- Runtime supports Node, Next.js App Router (edge-capable) and React SPA (client helpers) by branching only in framework wrappers—core stays universal.

## 2. Key Conventions
- All modules are ES modules (`"type": "module"`); keep imports explicit (no implicit index where clarity helps).
- Input normalization: emails + usernames lowercased & trimmed (see helper logic in `mongo.ts`). Mirror this in any new adapter or feature.
- Error handling: Throw `Error` with human-readable message; upstream route handlers convert to JSON `{ success: false, error: { message } }`. Stay consistent.
- Date fields: Always `Date` objects in DB layer; convert IDs (`ObjectId` → string) before returning to callers.
- Indexing & performance: Adapters create necessary indexes at connect (see `createIndexes()` in `mongo.ts`). For new collections add background index creation and swallow individual index errors (non-fatal) like existing pattern.
- Security defaults: bcrypt (bcryptjs) for password hashing; JWT via `jwtSecret` passed into `initAuth`; HTTP-only cookie named `auth_token` unless overridden.
- Limit queries for potentially unbounded lists (e.g. recent 2FA codes limit 10). Follow similar defensive limits.

## 3. Build & Test Workflow
- Build: `npm run build` uses `tsup` to emit dual CJS + ESM + d.ts into `dist`. Do not rely on path imports to internal `src/**` in published code; import via package entrypoints.
- Tests: Jest (`npm test`, coverage via `npm run test:coverage`). Place new tests under `src/__tests__/**` mirroring source folder structure. Use existing test naming style (one test file per feature area) if extending.
- Clean build artifacts with `npm run clean` before diagnosing build issues.
- Prepublish hooks (`prepare`, `prepack`) auto-build—avoid committing `dist`.

## 4. Adding / Modifying Features
- Extend auth flows in `src/core` keeping pure, framework-agnostic functions. Any HTTP / Request / Response specifics belong in framework wrappers (`src/nextjs.ts`, `src/middleware.ts`, React helpers, etc.).
- When touching public API: confirm/update re-exports in `src/index.ts` and (if new subpath) add to `package.json` `exports` with proper `types`/`require`/`import` triple.
- For a new DB adapter: replicate patterns from `mongo.ts` (connection singleton, index creation, normalization, error code translation e.g. duplicate key 11000 → user-friendly). Ensure all required `AuthDbAdapter` methods exist (see existing adapters for shape).
- For new OAuth provider: place under `src/providers/<provider>.ts`; expose high-level helper through central oauth/sso core without leaking provider-specific internals to framework layers.
- Keep side-effect-free initialization—`initAuth` configures singletons; avoid extra hidden global state.

## 5. Configuration & Environment
- Critical env vars: `JWT_SECRET`, DB adapter specifics (`MONGO_URI`, `DB_NAME` or Postgres URL), OAuth creds (`GOOGLE_*`, `GITHUB_*`), email provider creds. Fail fast with descriptive errors if required values missing.
- Optional collections/table names are overridable but default to sensible names (`users`, `two_factor_codes`). Reflect overrides everywhere instead of hardcoding.

## 6. Security & Validation Patterns
- Normalize & validate early (email, username). Avoid leaking whether a user exists in password reset / 2FA flows—return generic messages while logging internally (see README flows).
- Expiring artifacts: Use TTL index (e.g. `expiresAt` with `expireAfterSeconds: 0`) for codes; if adding new ephemeral docs, follow same TTL pattern.
- 2FA & reset code queries always restrict to non-expired + unused items and limit results; copy that approach.

## 7. Error / Conflict Handling
- Duplicate uniqueness conflicts: Translate adapter-specific error codes to clear field-based message: Email or Username already in use (see duplicate key handling in `createUser` / `updateUser`). Replicate in new adapters.
- Throw, don’t return sentinel objects—callers consistently expect exceptions for failure paths.

## 8. Performance & Resource Management
- Use singleton connections (see `MongoConnection`); expose `reset` + `disconnect` utilities for tests. For new adapters provide similar test hooks.
- Avoid unbounded `find()`; always project only required fields (see projections in user lookups) to reduce payload.

## 9. Testing Guidance
- Mock external services (email, OAuth HTTP exchanges) rather than hitting network. Follow pattern: inject adapter instance; do not embed network calls directly inside core logic without abstraction.
- For regression tests around new features: test both success path and uniqueness / invalid state errors.

## 10. Code Style & Output
- Keep functions small & composable; no large route handlers in core—composition belongs to framework wrappers.
- Prefer explicit return types on exported functions to preserve stable public surface in d.ts.

## 11. Common Pitfalls to Avoid
- Don’t access framework-specific Request/Response inside core modules.
- Don’t bypass normalization when updating user fields (email, username must stay lowercase).
- Don’t introduce breaking changes to existing subpath exports without coordinating a semver bump.
- Don’t swallow connection errors silently—only index creation failures are intentionally ignored.

## 12. Quick Reference (Examples)
- Duplicate user creation handling: see `createUser` in `mongo.ts` (error.code === 11000 logic).
- Expiring codes TTL: index spec `{ expiresAt: 1 }` with `{ expireAfterSeconds: 0 }` in `createIndexes()`.
- Recent 2FA code fetch: `find(query).sort({ createdAt: -1 }).limit(10)` pattern.

Feedback welcome: If any section seems ambiguous (e.g., adapter contract specifics or adding a new export), highlight in PR description for adjustment.
