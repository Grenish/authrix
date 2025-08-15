## Authrix Email Services API Simplification & Bug Fix Plan

Purpose: Track remediation of identified issues (bugs + DX complexity) and guide phased consolidation of email provider endpoints while preserving backward compatibility.

Legend: [P0]=Critical, [P1]=High, [P2]=Normal, [P3]=Nice-to-have

---

### 1. Critical Bug Fixes
- [x] [P0] Duplicate email registries (core vs providers) cause split state
  - Action: Unify into a single `EmailServiceRegistry` used by both core and providers; remove duplicate.
- [x] [P0] Core defaults expect `'default'` service but providers set a separate default
  - Action: Implement `setDefault()` on unified registry; ensure `sendVerificationEmail()` resolves `'default'` consistently.
- [x] [P1] Import-time side effects (auto-init in `src/email/index.ts`)
  - Action: Remove auto-init and logs; provide explicit `initEmailServices()` call path.
- [x] [P1] Mixed ESM/CJS usage (require in ESM)
  - Action: Replace `require()` with dynamic `import()` or Node `createRequire` only where needed; verify dual build.
- [x] [P1] Inconsistent env validation across providers
  - Action: Normalize required env checks and error messages; add setup hints.
- [ ] [P2] Provider init failure messages unhelpful
  - Action: Add clear error translation (auth vs network vs config) and suggested fixes.

### 2. API Surface Consolidation
- [x] [P0] Single explicit initialization API
  - Design: `initEmailServices({ defaultEmailService: 'resend', providers: { resend: {...}, sendgrid: {...}, gmail: {...}, smtp: {...} } })` (alias: `defaultService`).
  - Wire from `initAuth` and allow env-only fallback for convenience.
- [x] [P1] Shared option types
  - Introduce `src/types/email.ts` with `EmailMetadata`, `SendEmailOptions`, `EmailTemplate`, `TestResult`.
  - Refactor providers to use shared types; unsupported fields are ignored gracefully. (Types file added; provider refactor pending)
- [x] [P1] Registry helpers
  - Methods: `register`, `get`, `setDefault`, `getDefault`, `list`, `clear`, `status()`.
- [x] [P2] Capability map per provider
  - Expose optional `capabilities` (templates, headers, tracking, tags) for developer guidance.
  - Added `EmailServiceCapabilities` type and wired per-provider capabilities; query via `EmailServiceRegistry.getCapabilities(name)` or `EmailServiceRegistry.status().capabilities`.

### 3. Deprecation & Migration Support
- [x] [P1] Deprecate providers’ standalone registry and auto-init
  - One-time console warnings added in `src/email/providers.ts` (import + shim calls).
- [x] [P1] Migration doc `docs/EMAIL_API_MIGRATION.md` (Old → New mapping + examples).
- [x] [P2] Keep `initializeEmailServices/getAvailableEmailServices/getEmailServiceInstructions` as shims to unified API for one minor release (with deprecation warnings).

### 4. Configuration & Environment
- [x] [P1] Config-first initialization via `authConfig`
  - Support `defaultEmailService` and per-provider configs. (Alias added; wired in `initEmailServices` and `initAuth`.)
- [x] [P2] Deterministic auto-default priority (env): `resend > sendgrid > gmail > smtp > console`.
- [x] [P2] Document all env vars with examples and troubleshooting. (See `docs/EMAIL_ENV_VARS.md`.)

### 5. Security & Validation
- [x] [P1] Normalize email format validation and error messages across providers.
- [x] [P2] Do not leak user existence in messaging flows; keep generic user-facing errors.
- [x] [P2] Option to pass rate limit context (email+ip) from twoFactor into send flows for diagnostics only (no PII in logs). (Plumbed non-PII via `EmailMetadata.rateLimit`.)

### 6. Logging & Diagnostics
- [ ] [P2] Use centralized logger; tag `[AUTHRIX][EMAIL]` and include provider/service name + category.
- [ ] [P2] Add `testConnection()` unified helper that delegates to provider when available, returns normalized `TestResult`.
- [ ] [P3] Optional health snapshot `email.status()` exposing registered, configured, default, and recommendations.

### 7. Testing Tasks
- [ ] [P0] Registry tests: register/get/default/list/clear and default resolution matrix.
- [ ] [P1] Init tests: env combinations + config overrides + shim behavior (no side effects on import).
- [ ] [P1] Core integration: `initiateEmailVerification()` dispatches via unified registry (providers mocked).
- [ ] [P2] Provider send happy-path + permanent/temporary error retry behavior (mock network/client libs).
- [ ] [P2] ESM/CJS smoke tests for imports.

### 8. Documentation Updates
- [ ] [P1] README: Quickstart for choosing a provider and initializing via `initAuth`.
- [ ] [P1] Provider guides: Resend, SendGrid, Gmail, SMTP with env samples and pitfalls.
- [ ] [P2] Troubleshooting: auth failures, domain verification, blocked recipients, TLS issues.
- [ ] [P2] Examples: Next App/Pages, Express, React SPA using the unified initialization.

### 9. Implementation Phasing
| Phase | Goals | Exit Criteria |
|------|-------|---------------|
| 1 | Unify registry + remove side effects + ESM fixes | Single registry used; no import-time init; build succeeds |
| 2 | Standardize types + provider refactors | All providers on shared types; tests passing |
| 3 | Wire into `initAuth` + config/env priority | Default service resolved deterministically; docs updated |
| 4 | Deprecation + migration | Shim warnings in place; migration doc published |

### 10. Old → New Mapping (Representative)
| Old | New | Notes |
|-----|-----|------|
| `EmailServiceRegistry` (in providers.ts) | Unified `EmailServiceRegistry` (core module) | Single source of truth |
| Auto-init in `src/email/index.ts` | `initEmailServices()` via `initAuth()` | No side effects on import |
| `initializeEmailServices()` | `initEmailServices()` (shim calls unified; deprecated) | One release grace period |
| Provider-specific `SendEmailOptions` | Shared `SendEmailOptions` in `src/types/email.ts` | Extra fields optional |

### 11. Risk Mitigation
- Keep shims and warnings for at least one minor release.
- Add thorough tests before removing legacy paths.
- Provide clear provider setup docs and errors to reduce support load.

### 12. Open Questions
- Should console provider be registered automatically in production when no provider configured? (Leaning: only in development.)
- Where should advanced features (tags/tracking/webhooks) live in shared types vs provider extensions?
- Do we expose a generic email-sending API (beyond verification) or keep scope focused?

### 13. Deferred / Backlog
- Webhook validation helpers (SendGrid/Resend events).
- Metrics adapter for delivery/open rates (pluggable).
- SMS providers parity with email registry patterns.

---

### Progress Tracking Snapshot (updated)
- P0: 3 / 4
- P1: 7 / 11
- P2: 6 / 13
- P3: 0 / 1

File created: 2025-08-15
