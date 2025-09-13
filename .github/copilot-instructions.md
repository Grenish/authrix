## Authrix AI Contributor Guide (Focused Instructions for Coding Agents)

Purpose: Equip an AI agent to make correct, low‑friction contributions to the Authrix authentication library (v2.1.x) immediately. Keep edits minimal, respect existing patterns, and prefer incremental improvements.

### 1. Architectural Big Picture
Unified facade `auth` (in `src/auth.ts`) exposes: `actions`, `session`, `middleware`, `handlers`, `cookies`, `env`.
Core logic (signup / signin / logout / session / password reset / SSO) lives under `src/core/` as small pure functions. Framework specifics (Next.js, React helpers, middleware) are thin adapters under `src/frameworks` / root barrels.
Global runtime configuration is a singleton in `src/config/index.ts` (`authConfig`, initialized via `initAuth`). Avoid introducing additional global mutable state—extend config through that singleton if necessary.
Build outputs multiple subpath exports (see `package.json:exports`) each mapping to a dedicated entry file in `tsup.config.ts`. When adding a new public module, update BOTH `src/<name>.ts` and `tsup.config.ts` entries and `package.json.exports` consistently.

### 2. Key Conventions & Patterns
TypeScript module format: ESM + CJS dual build via tsup with tree‑shaking and property mangling of names starting with `_`. Avoid adding console logs; they are stripped anyway—prefer the central `logger` in `src/utils/logger.ts`.
Deprecation strategy: Legacy direct exports remain (emitting one‑time warnings). If adding a deprecation, mirror this pattern (single warn, development only) instead of removing immediately.
Password hashing & security utilities centralized in `src/utils/hash.ts`; do not inline crypto logic in feature modules—call those helpers.
Cookie handling centralized (see `internalCookies` in `src/internal/cookies.*`). Never hand‑craft Set-Cookie headers outside those helpers.
Environment detection & lazy Next.js handler loading uses dynamic `import()` in `auth.ts`; preserve the lazy, cached pattern if extending handlers.
Email services registered via `EmailServiceRegistry` (`src/core/emailRegistry.ts`) and optionally auto-detected from env inside `initEmailServices()`—extend by registering a new provider class and adding detection logic (non-breaking) instead of branching in consumer code.

### 3. Build & Test Workflow (Agent Essentials)
Build: `npm run build` (tsup) produces minified dual-format files under `dist/`. Do not check in `dist/`.
Tests: `npm test` (Jest + ts-jest ESM). Coverage: `npm run test:coverage`. For focused categories use name patterns (e.g. security: `npm run test:security`).
When adding new source that should be covered, ensure it sits under `src/` so it is included by coverage globs (exclude d.ts and `src/index.ts`).
If adding a new entry file intended for publishing, include it in: `tsup.config.ts entry[]`, `package.json exports`, and confirm types generation.

### 4. Error & Logging Model
Errors: Throw plain `Error` with a concise, user-comprehensible message. API route layers decide JSON formatting. Avoid throwing custom classes unless introducing a fully adopted error taxonomy.
Logging: Use `logger` (import from root) with structured methods. For deprecations or security notices, follow existing categories (`deprecation`, `security`, `adapter`, `session`).

### 5. Session & Rolling Refresh
Session lifetime & rolling refresh thresholds stored in `authConfig` (`sessionMaxAgeMs`, `rollingSessionEnabled`, `rollingSessionThresholdSeconds`). If adding session behavior, read them via accessors—do not capture values at module top if they might change during init ordering.
Token inspection functions live in `src/core/session.ts`. Add enhancements there; keep side‑effects (like cookie issuance) outside core pure logic.

### 6. Adding Framework Integrations / Handlers
Next.js handlers are factory-generated in `frameworks/nextjs.*` (loaded lazily). To add a new handler:
1. Implement a factory `createXHandler` in the Next.js module.
2. Map it in `HANDLER_MAP` inside `auth.ts`.
3. Expose via `handlers.<name>` with the same lazy pattern (define property getter, then redefine).
Maintain `createRouteHandler` error semantics (returns JSON `{ success:false, error:{message} }`).

### 7. Extensibility Points
DB Adapters: Implement `AuthDbAdapter` (`src/types/db.ts`) functions (create / get / update user + SSO / recovery helpers). Normalize email (trim+lowercase) like existing adapters.
Email Providers: Implement send interface mirrored by existing providers (Resend, SendGrid, Gmail, SMTP, Console). Register via `EmailServiceRegistry.register(name, instance)` and set capabilities if available.
OAuth Providers: Follow shape in `src/providers/<provider>.ts` (state verification, token exchange, profile normalization). Keep provider-specific HTTP inside provider module, not core logic.

### 8. File & Export Hygiene
Do not introduce circular dependencies between entry files; keep shared logic in internal modules.
Avoid expanding the public surface casually—prefer enhancing the unified `auth` namespace unless a clear subpath export is justified.
When renaming or moving a core function with external usage, consider adding a wrapper with a one‑time deprecation warning for at least one minor version.

### 9. Testing Additions
Use existing Jest setup (`jest.setup.ts`) which seeds `JWT_SECRET`. If a test needs a different secret, override locally but restore after. Mock console warnings sparingly—setup already stubs `console.warn`.
Prefer unit tests near behavior modules under `__tests__/` mirroring directory (e.g., `src/core/__tests__/signup.test.ts`).

### 10. Security Practices (Project-Specific)
Never derive peppers or secrets ad hoc; rely on `AUTHRIX_PASSWORD_PEPPER` (override usage currently deprecated—see warning in `config/index.ts`).
If adding password policy logic, extend `validatePassword` in `utils/hash.ts` instead of duplicating rules.
Do not leak secret values in thrown errors or logs—log only presence / status indicators.

### 11. Performance Considerations
Hot paths: signup/signin/session token validation. Keep these free of synchronous I/O beyond hashing and JWT operations. Any new optional runtime checks should be feature-flagged (config) or short‑circuited fast.
Minification removes `console.*`; avoid depending on side effects of removed statements.

### 12. PR Scope Guidance for Agent
Small, self‑contained changes: docs, new adapter/provider, incremental tests, handler additions.
When uncertain about a breaking change to exports or config shape, open a draft PR (or request human review) rather than merging code that alters public API signatures.

### 13. Quick Reference (Examples)
Initialize: `initAuth({ jwtSecret, db: mongoAdapter, session:{ rolling:{ enabled:true, thresholdSeconds:900 }}})`
Signup action usage: `await auth.actions.signup(email, pwd, { res })`
Session check: `await auth.session.getUser({ req })`
Create cookie manually (advanced): `res.setHeader('Set-Cookie', auth.cookies.create(token))`

Keep this file concise—add only patterns proven in code. Remove or refactor stale guidance when behavior changes in source.
