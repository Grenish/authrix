# Bug & Issue Fixes TODO

Scope: src/ (tests excluded as requested)

Owner: Authrix core
Branch: improvements

---

## 1) Sign-in returns 401 with correct credentials

Likely causes
- Unstable password pepper in dev/test: `utils/hash.ts` generates a random pepper when `AUTHRIX_PASSWORD_PEPPER` is not set. After a process restart, verification fails for previously created users.
- SSO-created users currently store a non-hashed random password (see item 3), which makes password verification always fail if attempted.

Proposed fixes
- utils/hash.ts: Provide a stable, secure fallback when env pepper is missing by deriving pepper from `authConfig.jwtSecret` (HMAC or KDF) to keep it deterministic across restarts in non-production. Keep the hard error in production if env pepper is missing.
- Add explicit startup log/warning that calls out which pepper mode is used (env vs derived) and guidance to set `AUTHRIX_PASSWORD_PEPPER`.
- signinCore: Keep behavior, but improve debug logs to differentiate Unauthorized vs Forbidden rate-limit/lockout paths.

Files
- `src/utils/hash.ts`
- `src/core/signin.ts`
- (optional) `src/config/index.ts` for a one-time boot log hook.

Acceptance criteria
- With a fixed jwtSecret and no AUTHRIX_PASSWORD_PEPPER, users created before restart can still sign in after restart (dev only). In prod, missing pepper still fails fast.
- Entering correct credentials no longer yields 401 solely due to restarts.
- Logs clearly indicate rate-limit lockouts vs invalid credentials.

---

## 2) Signup extra profile fields not persisted (username, firstName, lastName, profilePicture, fullName)

Root cause
- PostgreSQL adapter schema lacks `full_name` and `profile_picture` columns while code tries to use them. Mongo adapter already persists these.

Proposed fixes
- postgresql.ts: Update `initializePostgreSQLTables()` to include `full_name TEXT` and `profile_picture TEXT` columns. Ensure indexes remain valid.
- postgresql.ts: Verify `rowToUser`, `createUser`, and `updateUser` map these fields consistently (already partially implemented).
- Provide an idempotent SQL migration snippet for existing deployments to add the missing columns.

Files
- `src/adapters/postgresql.ts`
- docs snippet in `README.md` or `RELEASE_NOTES_*.md` for migration.

Acceptance criteria
- After signup via Postgres adapter with provided profile fields, those fields are present in the DB row and returned by API.
- Existing tables can be migrated without data loss using the provided SQL.

---

## 3) SSO-created users in same users collection/table and record auth provider

Findings
- Users created via SSO already go through the same adapter (`db.createUser`). However, two issues:
  1) SSO `processSSOAuthentication()` sets a random password but does not hash it before `createUser` — this stores a plaintext password in DB (security bug) and breaks password verification paths.
  2) No field in `AuthUser` or DB records to denote auth method/provider (email/password vs Google/GitHub/etc.).

Proposed fixes
- types/db.ts: Extend `AuthUser` with `authMethod?: 'password' | 'sso'` and `authProvider?: string`.
- core/signup.ts: Set `authMethod='password'` and `authProvider='password'` (or 'email').
- core/sso.ts: Hash the generated password with `hashPassword()` before `createUser`. Set `authMethod='sso'` and `authProvider=provider`.
- adapters/mongo.ts and adapters/postgresql.ts: Persist and project `authMethod` and `authProvider`.
- Optionally include `provider` in JWT claims (already added during SSO), and surface `authMethod`/`authProvider` in returned user payloads when available.

Files
- `src/types/db.ts`
- `src/core/signup.ts`
- `src/core/sso.ts`
- `src/adapters/mongo.ts`
- `src/adapters/postgresql.ts`

Acceptance criteria
- SSO-created users have a hashed password at rest.
- User records include the provider info: e.g., `{ authMethod: 'sso', authProvider: 'google' }` or `{ authMethod: 'password', authProvider: 'password' }`.
- Existing Mongo and Postgres adapters read/write these fields without breaking older data (nullable/optional).

---

## 4) Reduce unnecessary comments; keep minimal concise ones

Guidelines
- Retain short TSDoc/JSDoc for public exports and tricky security-sensitive code paths.
- Remove verbose or redundant narrative comments and TODO clutter.

Targets (non-exhaustive)
- `src/utils/hash.ts` (trim narrative comments; keep policy and security-critical notes brief)
- `src/core/sso.ts` (remove patch history notes; keep high-level doc for handlers)
- `src/core/signin.ts`, `src/core/signup.ts` (keep function docs, remove inline obvious comments)
- Adapters (keep short comments explaining normalization and index creation)

Acceptance criteria
- Files compile without functional changes.
- Public API retains helpful hover docs while inline noise is reduced.

---

## 5) [Good to have] Hover tooltips for necessary code/syntax

Approach
- Add minimal TSDoc to exported functions, types, and core entry points to improve IDE hover help without bloating the code.

Targets
- `src/index.ts` (re-exports; ensure upstream exports have docs)
- `src/auth.ts` (document `auth.actions`, `session`, and `handlers`)
- `src/sso.ts` (document exported SSO handlers and state helpers)
- `src/core/*.ts` exported functions (signinCore, signupCore, logoutCore, etc.)
- `src/types/db.ts` interfaces (AuthUser, AuthDbAdapter)

Acceptance criteria
- Hovering exported APIs in editors shows concise, accurate summaries.
- No heavy commentary beyond 1–3 lines per export.

---

## Validation plan (once fixes are implemented)
- Build/lint: `npm run build` passes with no type errors.
- Unit tests: add/extend tests under `src/__tests__` for:
  - Signin after restart with derived pepper fallback (dev only) and explicit env pepper path.
  - Postgres adapter persisting profile fields.
  - SSO user creation stores hashed password and provider metadata.
- Manual smoke: signup + signin flows on both Mongo and Postgres (where available), plus SSO happy path using provider mocks.

---

## Quick migration note for Postgres (existing tables)
Optional SQL to add missing columns safely:

```
ALTER TABLE auth_users
  ADD COLUMN IF NOT EXISTS full_name TEXT,
  ADD COLUMN IF NOT EXISTS profile_picture TEXT,
  ADD COLUMN IF NOT EXISTS auth_method TEXT,
  ADD COLUMN IF NOT EXISTS auth_provider TEXT;
```

Document environment requirements
- Set `JWT_SECRET` and `AUTHRIX_PASSWORD_PEPPER` (prod required). In dev, if the pepper is omitted, a stable fallback will be derived from `JWT_SECRET` after fix.
