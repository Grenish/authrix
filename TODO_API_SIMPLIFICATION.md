## Authrix API Simplification & Bug Fix Plan

Purpose: Track remediation of identified issues (bugs + DX complexity) and guide phased consolidation of exported endpoints while preserving backward compatibility.

Legend: [P0]=Critical, [P1]=High, [P2]=Normal, [P3]=Nice-to-have

---

### 1. Critical Bug Fixes
- [x] [P0] Cookie maxAge unit mismatch (ms vs seconds) in Next.js cookie string generation
  - Action: Introduce converter when producing Set-Cookie headers (divide by 1000). Add helper `normalizeCookieForHeader()`.
  - Add regression test: ensure 7d == 604800 seconds not large ms.
- [x] [P0] Duplicate signup 409 not returned
  - Action: In signup handlers detect `instanceof ConflictError` (or error name) → 409.
- [x] [P0] Middleware structural token check accepts unsigned tokens
  - Action: After structural parsing attempt `verifyToken` if secret exists; invalidate on failure.
- [x] [P1] forceNextJsAvailability ineffective (mutates copy)
  - Action: Add `ModuleLoader.setOverride()` that merges into internal static state; update helper to use it.
- [x] [P1] Environment info possibly stale (async load not awaited)
  - Action: Add async `getNextJsEnvironmentInfoAsync()` or make existing function return last-known plus schedule refresh; document behavior.
- [x] [P1] atob fallback missing (Node runtime)
  - Action: Use `(typeof atob !== 'undefined' ? atob(str) : Buffer.from(str,'base64').toString('binary'))` in JWTUtils.
- [x] [P1] Password verify fallback silently masks error
  - Action: Log `warn` (dev & prod) when fallback path taken with context.
- [x] [P2] logoutCore clearing unrelated cookie names
  - Action: Gate extra cookie clearing behind option `extraClear?: string[]` (default none). Remove hardcoded session_id/csrf_token/refresh_token.
- [x] [P2] Inconsistent emailVerified/emailVerifiedAt semantics
  - Action: Guarantee setting of both when auto-verified; document adapter expectations.
- [x] [P2] Rate limiting keyed only by email; missing IP dimension
  - Action: Extend limiter store to combine `email|ipHash` when IP available; expose hook to override limiter.

### 2. API Surface Consolidation
- [x] [P0] Design unified grouped namespace API (`auth` object) for Next.js & universal usage.
  - Structure:
    - `auth.actions` (signup, signin, logout)
    - `auth.session` (getUser, isAuthenticated)
    - `auth.middleware` (guard, optional, withUser)
    - `auth.handlers` (factory returning route handlers)
    - `auth.cookies` (create, clear)
    - `auth.env` (detect, reset, injectTest)
- [x] [P1] Implement internal abstraction: single `applyAuthCookie()` with pluggable context (res, Next cookies(), manual).
- [x] [P1] Replace duplicated Next.js variants with thin wrappers calling unified layer. (Legacy variants removed in favor of auth namespace.)
- [x] [P1] Introduce deprecation shims for legacy exports (signupNext*, signinNext*, etc.) emitting one-time dev warning.
- [x] [P2] Remove *_Flexible variants (alias them only) once unified layer stable. (Removed from nextjs entrypoint; unified namespace enforced.)
- [x] [P2] Hide *Core exports from primary index; move to secondary entrypoint `authrix/advanced` (deprecated wrappers left for transition).
- [x] [P3] Consider tree-shake friendly barrel splitting (core, sso, oauth) after consolidation (benchmark bundle size deltas).
  - Added new `authrix/core` minimal barrel (no SSO/OAuth/providers). Baseline index.mjs 5.63 KB → core.barrel.mjs (will measure after build). Further barrels for `sso` & `oauth` already exist; core now separately importable.

### 3. Deprecation & Migration Support
- [ ] [P1] Create migration doc `docs/API_SIMPLIFICATION.md` with mapping Old → New.
- [x] [P1] Implement one-time deprecation logger utility (memo set of emitted keys).
- [x] [P2] Add package.json `exports` for new grouped entrypoints: `./next`, `./universal`, `./security`, `./advanced`.
  - Implemented: ./next (alias of nextjs), ./security (new), ./advanced (already), ./universal (already present), ./core (additional minimal barrel).
  

### 4. Cookie & Session Normalization
- [x] [P0] Add `normalizeCookieOptions({ framework: 'header' | 'express' })` returning properly scaled options.
  - Implemented in `internal/cookies.ts` converting ms→s for header output, preserving ms for express, applying defaults.
- [x] [P1] Centralize cookie name retrieval; remove duplicate constant logic.
  - Added internalCookies.getAuthCookieName and refactored auth.ts usage.
- [ ] [P1] Add test matrix: Express vs Next (App & Pages) cookie lifetimes & attributes (HttpOnly, Secure, SameSite, Path).
  - Initial skeleton cookieMatrix.test.ts added (header vs express + name consistency). Needs Next App/Pages environment simulation for full coverage.
- [x] [P2] Option to force secure cookies in development via config flag for parity testing.

### 5. Security Hardening
- [x] [P1] Signature validation in middleware (explicit verifyToken pre-check) + negative tampered token test added.
- [ ] [P2] Optional rolling session update (refresh exp) toggle in signin / session access. (Config + refresh logic implemented; add dedicated tests & docs)
- [ ] [P3] Pluggable limiter interface & doc (future: redis adapter).

### 6. Logging & Diagnostics
- [x] [P2] Replace scattered console.debug with logger.debug; unify log tags `[AUTHRIX]`.
- [x] [P2] Add structured context to warnings (category, action, outcome) to simplify future filtering.
- [ ] [P3] Add `auth.env.info()` caching timestamp & last detection source.

### 7. Testing Tasks (Post-Refactor)
- [ ] [P0] Unit tests: cookie generation (ms→s conversion), conflict status, middleware signature validation.
- [ ] [P1] Snapshot tests for unified auth.handlers outputs (shape, headers) across contexts.
- [ ] [P1] Deprecation warnings: ensure fired once per symbol.
- [ ] [P2] Rate limiter extended key (email+ip) test with simulated IP.
- [ ] [P2] Logout does not clear unrelated cookies unless specified.
- [ ] [P3] Benchmark bundle size pre vs post consolidation (document in BUNDLE_OPTIMIZATION.md).

### 8. Documentation Updates
- [ ] [P1] New unified usage examples (Next App, Pages, Universal, Express) referencing `auth.actions.*`.
- [ ] [P1] Security note: middleware now validates signature.
- [ ] [P2] Clarify cookie lifetime units & conversion.
- [ ] [P2] Add section on deprecation timeline + removal schedule.
- [ ] [P3] Extend CONTRIBUTING with policy for adding new endpoint (must integrate into unified object, avoid flat export proliferation).

### 9. Implementation Phasing
| Phase | Goals | Exit Criteria |
|-------|-------|---------------|
| 1 | Critical bug fixes (cookies, conflict status, middleware signature) | Tests green; no breaking changes |
| 2 | Unified internal abstractions + grouped namespace (parallel with legacy) | New API documented; deprecation warnings functional |
| 3 | Cleanup & security hardening (logging, logout scope, atob fallback) | All P1 items complete |
| 4 | Deprecation follow-through & docs | Migration guide published; adoption examples merged |
| 5 | Optional enhancements (limiter plugin, rolling sessions) | P2/P3 backlog triaged |

### 10. Old → New Mapping (Representative)
| Old Export | New Usage (Planned) | Notes |
|------------|--------------------|-------|
| signupNextApp / signupNextPages / signupNext | `auth.actions.signup()` | Auto-detect context; optional explicit `{ context: 'pages' }` |
| signinNextApp / signinNextPages / signinNext | `auth.actions.signin()` | Same consolidation |
| logoutNext* variants | `auth.actions.logout()` | Returns `{ message }` |
| getCurrentUserNext* | `auth.session.getUser()` | Unified token extraction |
| isAuthenticatedNext* | `auth.session.isAuthenticated()` | |
| createSignupHandler / *Pages | `auth.handlers.signup()` | factory chooses response mode |
| createSigninHandler / *Pages | `auth.handlers.signin()` | |
| createCurrentUserHandler* | `auth.handlers.currentUser()` | |
| createLogoutHandler* | `auth.handlers.logout()` | |
| createTokenValidationHandler* | `auth.handlers.validateToken()` | |
| signupCore / signinCore (direct) | `import { core } from 'authrix/advanced'; core.signup()` | Advanced only; warn on main import |

### 11. Risk Mitigation
- Incremental: Keep legacy exports until at least one minor release after new grouped API stable.
- Add comprehensive tests before removing old paths.
- Version gating: If any breaking change required (e.g., removing *Core from main index) schedule for next major.

### 12. Open Questions (To Clarify Before Phase 2)
- Should we expose environment detection sync or enforce async? (Leaning: keep sync returning cached snapshot).
- Formal session invalidation (blacklist) roadmap? (Maybe out-of-scope for this simplification; document placeholder.)

### 13. Deferred / Backlog Ideas
- Opaque session store option (Redis) instead of JWT.
- Codemod script to auto-rewrite old imports to new grouped namespace.
- Bundle analyzer CI job to enforce export growth budget.

---

### Progress Tracking Snapshot (initial)
- Critical fixes: 0 / 4
- High priority: 0 / 9
- Normal: 0 / 15
- Nice-to-have: 0 / 10

File created: 2025-08-13
