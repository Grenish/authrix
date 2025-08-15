# Bug & Issue Resolution Plan Checklist

Scope: `src/` (tests excluded)
Owner: Authrix core • Branch: `improvements`

## 0) Prep
- [x] Ensure `initAuth()` is called with a real `jwtSecret` and DB adapter. (Init validation/logging added)
- [x] Production: set `AUTHRIX_PASSWORD_PEPPER`. Dev: plan stable fallback. (Stable dev fallback implemented in hash utils)

## 1) Sign-in returns 401 with correct credentials
- [x] Stable dev-only pepper fallback derived from `authConfig.jwtSecret` when env pepper is missing.
  - Files: `src/utils/hash.ts`
  - Done when: Correct creds work across restarts in dev; prod still fails fast if pepper missing.
- [x] Improve signin diagnostics to separate invalid creds vs lockout.
  - Files: `src/core/signin.ts`
  - Done when: Logs distinguish Unauthorized vs Forbidden.
- [ ] Optional: one-time startup warning indicating pepper mode.
  - Files: `src/config/index.ts`

## 2) SSO-created users: secure password + provider metadata
- [x] Hash auto-generated password before creating SSO users.
  - Files: `src/core/sso.ts` (use `hashPassword()`)
  - Done when: No plaintext SSO passwords at rest.
- [x] Add provider metadata fields to user model.
  - Files: `src/types/db.ts` (add `authMethod?: 'password'|'sso'`, `authProvider?: string`)
  - Files: `src/core/signup.ts` (set `authMethod='password'`, `authProvider='password'`)
  - Files: `src/core/sso.ts` (set `authMethod='sso'`, `authProvider=provider`)
  - Files: `src/adapters/mongo.ts`, `src/adapters/postgresql.ts` (persist/project optional fields)
  - Done when: Records carry provider info; adapters handle null/omitted for legacy data.

## 3) Signup extra profile fields persist (Postgres)
- [x] Extend Postgres schema with `full_name` and `profile_picture`.
  - Files: `src/adapters/postgresql.ts` (`initializePostgreSQLTables()`)
- [x] Verify mapping for `rowToUser`, `createUser`, `updateUser` includes these.
  - Files: `src/adapters/postgresql.ts`
- [x] Provide idempotent migration SQL for existing deployments.
  - Docs: `README.md` or release notes
  - Done when: Fields are stored and returned by API.

## 4) Comment cleanup (minimal, helpful)
- [x] Trim redundant comments; keep short TSDoc on public APIs and security-sensitive paths.
  - Files: `src/utils/hash.ts`, `src/core/sso.ts`, `src/core/signin.ts`, `src/core/signup.ts`, adapters
  - Done when: No functional changes; concise docs remain for hovers.

## 5) Hover tooltips (good to have)
- [ ] Add concise TSDoc (1–3 lines) to exported functions, types, and entrypoints.
  - Files: `src/auth.ts`, `src/sso.ts`, `src/core/*.ts`, `src/types/db.ts`; ensure `src/index.ts` re-exports surface docs
  - Done when: IDE hover shows accurate summaries.

## 6) Validation / Quality gates
- [ ] Build & typecheck pass (`npm run build`).
- [ ] Tests updated/added:
  - Signin works across restart with dev pepper fallback and with explicit env pepper.
  - Postgres persists `fullName` and `profilePicture`.
  - SSO creation stores hashed password and provider metadata.
- [ ] Manual smoke (where available): signup + signin on Mongo/Postgres; SSO happy path with provider mocks.

## 7) Documentation
- [x] Document env requirements: `JWT_SECRET` and `AUTHRIX_PASSWORD_PEPPER` (prod required; dev fallback behavior noted).
- [x] Add Postgres migration snippet and brief release note for provider metadata.
