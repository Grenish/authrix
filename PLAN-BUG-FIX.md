# Bug Fix Plan — Env Vars Not Loading & Password Verification Failing (Mongo + Next.js)

Purpose: Resolve two reported issues for Next.js + Mongo adapter:
- Env variables (MONGO_URI/DB_NAME) not picked up when using factory (createMongoAdapter)
- Sign-in rejecting valid credentials due to password hash verification inconsistencies

## Scope & Constraints
- Touch only `src/**` for code fixes; add minimal docs/tests to validate.
- Do not add tests or `src/_test_` or anything related to test unless asked specfically.
- Maintain backward compatibility; do not break public APIs.
- Keep Mongo adapter universal; framework specifics stay in wrappers/docs.

## Quick Status (what’s already done in code)
- Mongo adapter: supports env + override + factory; DB name inference; improved error text; retry/backoff; index guard.
- Hashing: added fallback verification with previous pepper and rehash to current pepper on success.
- Next.js examples: init at import-time; routes can set `export const runtime = 'nodejs'`.

## Plan A — Env Vars Not Loading in Next.js (MongoDB)

Hypotheses
- H1: In Next.js route handlers, `process.env.MONGO_URI` is undefined (Edge runtime or init order), so `createMongoAdapter({ uri: process.env.MONGO_URI! })` passes `undefined` into the factory; adapter then throws missing config.
- H2: DB name missing (no DB_NAME, and URI without `/dbname`).
- H3: Init module not imported before handlers, so configuration/derived pepper/env state differs at call time.

Execution Steps
- [x] A1: Harden factory/env layering in adapter
	- [x] A1.1 In `src/adapters/mongo.ts` `createMongoAdapter`, if `options.uri` is falsy:
		- [x] Fallback to `process.env.MONGO_URI` instead of passing `undefined` override.
		- [x] If still missing, throw explicit error: “createMongoAdapter called without uri and MONGO_URI not set (Next.js: ensure runtime='nodejs' and .env.local at project root).”
	- [x] A1.2 If `options.dbName` is falsy, infer from URI path; else fallback to `process.env.DB_NAME`.
	- [x] A1.3 Ensure we do not write `undefined` into override; only set defined keys.

- [x] A2: Improve diagnostics for Next.js users
	- [x] A2.1 In `loadConfig()` missing-config error, append a Next.js hint: “If using App Router, add `export const runtime = 'nodejs'` to your route handler files or include dbName in the URI path.”
	- [x] A2.2 Add masked env echo in error detail (e.g., show whether `typeof process.env.MONGO_URI` is defined without printing values).

- [x] A3: Stabilize Next.js init usage (docs/examples)
	- [x] A3.1 In `docs/NEXTJS_QUICK_START.md`, add a note to set `export const runtime = 'nodejs'` for `/api/auth/*` routes when using Mongo (Edge lacks Node driver).
	- [x] A3.2 Show both env-driven (`mongoAdapter`) and factory paths; stress including `/dbname` in URI if not using `DB_NAME`.
	- [x] A3.3 Document importing a server-only `lib/authrix.ts` that runs `initAuth` at import time.

- [ ] A4: Add light runtime self-checks (optional, dev-only)
	- [ ] A4.1 Expose `healthCheckMongo()` in adapter docs; add tiny “/api/auth/debug/health” example in docs to confirm DB connectivity.
	- [ ] A4.2 Suggest using `getAuthrixStatus()` to print config presence during local debugging.

Tests
- [ ] T-Env-1: Unit test for `createMongoAdapter` fallback logic when options.uri is undefined but env present.
- [ ] T-Env-2: Unit test for DB name inference from URI path; and explicit `DB_NAME` precedence.
- [ ] T-Env-3: Error text includes Next.js hint when env missing.

## Plan B — Password Verification Failing (Hash Mismatch)

Hypotheses
- H1: Pepper drift between signup and signin (e.g., dev-generated vs derived-from-jwt or missing `AUTHRIX_PASSWORD_PEPPER`).
- H2: JWT/pepper changes across restarts; existing hashes cannot be verified if pepper differs (expected unless stable pepper is configured).
- H3: Init order causing derived pepper to switch mid-run.

Execution Steps
- [x] B1: Confirm fallback verification path
	- [x] B1.1 `src/utils/hash.ts` retries verification with previous pepper on failure and flags rehash to current pepper; code path verified.
	- [x] B1.2 `signinCore` enables `updateHash` so rehash occurs when `db.updateUser` exists, with failures swallowed.

- [x] B2: Strengthen guidance and toggles
	- [x] B2.1 Docs: advise setting `AUTHRIX_PASSWORD_PEPPER` (32+ chars) in all environments; warn that changing it invalidates existing passwords.
	- [x] B2.2 Add a troubleshooting note for “Invalid email or password” specifically calling out pepper drift and the new fallback behavior.
	- [x] B2.3 Optional: gate fallback with an env flag (`AUTHRIX_ALLOW_PREV_PEPPER_FALLBACK=true/false`). Default is enabled in non-production.

Tests
- [ ] T-Hash-1: Signup → verify (current pepper) → should pass.
- [ ] T-Hash-2: Simulate pepper switch mid-process: set initial pepper, create hash; switch to new pepper; verify succeeds via previous pepper; rehash flagged.
- [ ] T-Hash-3: After rehash, verify with current pepper only passes.

## Code Change Targets (by file)
- Adapter: `src/adapters/mongo.ts`
	- `createMongoAdapter`: fallback to env when options are undefined; avoid writing undefined; clearer errors.
	- `loadConfig`: add Next.js runtime hint and masked presence info.
- Hashing: `src/utils/hash.ts`
	- Verify-and-rehash fallback already added; consider optional feature flag.
- Core: `src/core/signin.ts`
	- Confirm `updateHash` path stays enabled; no change expected.
- Docs: `docs/NEXTJS_QUICK_START.md` and example READMEs
	- Add runtime='nodejs' tip; DB name remedies; debugging tips (health/status helpers).
- Tests: `src/__tests__/**`
	- New unit tests for adapter env/factory behavior; hashing fallback scenarios.

## Rollout & Verification
- [ ] Build passes (tsup), types OK.
- [ ] Run new unit tests locally.
- [ ] Manual smoke: Next.js app with `.env.local` (MONGO_URI, DB_NAME, JWT_SECRET, AUTHRIX_PASSWORD_PEPPER) → signup + signin works.
- [ ] Manual: remove DB_NAME but include db in URI path → works.
- [ ] Manual: change JWT_SECRET in dev → signin works due to fallback, rehash occurs; recommend stabilizing pepper.

## Acceptance Criteria
- Env-driven and factory flows both succeed when env present; clear actionable error when missing.
- Adapter no longer fails when factory called with undefined options if env is set.
- Signin works for users created before pepper derivation switch within a process; rehashes to current pepper.
- Docs instruct how to set runtime='nodejs' and stabilize pepper.

## Backout Plan
- If issues arise, revert adapter fallbacks to prior behavior; keep improved error messaging. Keep hashing fallback behind optional flag if needed.

## Timeline (suggested)
- Day 1: Implement adapter fallback + error message updates; add tests T-Env-1..3.
- Day 2: Finalize docs; add hashing tests T-Hash-1..3; verify Next.js smoke.

