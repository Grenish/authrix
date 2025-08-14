# Authrix 2.1.0 (Beta) – Unified API & Security Hardening

Date: 2025-08-13
Status: Draft (pending version bump from 2.0.3 → 2.1.0)

## Overview
This release streamlines the public API, hardens security, and improves observability. A unified `auth` namespace now groups core actions, session helpers, middleware, handlers, cookie utilities, and environment detection. Critical security gaps (implicit token trust) are closed via explicit signature verification. Optional rolling session refresh is introduced to extend user experience without sacrificing session expiry semantics. Logging now uses a centralized structured logger with contextual warning metadata.

Backward compatibility is preserved through deprecation wrappers that emit one‑time warnings (non-production). Migration can be incremental.

## Key Changes
- Unified namespace: `auth.actions`, `auth.session`, `auth.middleware`, `auth.handlers`, `auth.cookies`, `auth.env`.
- Central cookie abstraction (name resolution + normalization + ms→s `Max-Age` safeguard).
- Explicit JWT signature & expiry verification in middleware / require paths before user resolution.
- Optional rolling session refresh (configurable threshold & enable flag).
- Structured logging: `logger.structuredWarn({ category, action, outcome, message })` applied in core + deprecations.
- Barrel / subpath export optimization: `./next`, `./universal`, `./security`, `./advanced`, `./core`.
- Deprecation wrappers for legacy core functions with single emission warnings.
- Test additions: tampered token negative path; cookie unit normalization baseline.

## Security Improvements
| Area | Previous Behavior | New Behavior |
|------|-------------------|--------------|
| Middleware token check | Could rely on decoded payload without explicit signature validation | Forced `verifyToken` call early; rejected tampered tokens |
| Max-Age handling | Risk of mixing ms & s | Normalization ensures seconds in `Set-Cookie` |
| Session longevity | Static expiry only | Optional rolling refresh when near threshold |
| Warning surface | Ad hoc `console.warn` messages | Structured warnings for deprecations & risk notices |

## New / Updated Configuration
| Field | Purpose | Default |
|-------|---------|---------|
| `sessionMaxAgeMs` | Canonical session lifetime (ms) | 7 days equivalent |
| `rollingSessionEnabled` | Enable rolling refresh | `false` |
| `rollingSessionThresholdSeconds` | Refresh when remaining life ≤ threshold | 900 (example default) |
| `forceSecureCookies` | Force `Secure` attribute | `undefined` (env-based) |

## Unified Namespace Snapshot
```
auth.actions.signup(email, password)
auth.actions.signin(email, password)
auth.actions.logout()
auth.session.getCurrentUserFromToken(token)
auth.session.getCurrentUserFromRequest(req)
auth.session.getCurrentUserFromTokenWithRefresh(token)
auth.middleware.requireAuth(req, res, next)
auth.middleware.optionalAuth(req, res, next)
auth.handlers.signup / signin / logout / currentUser / validateToken
auth.cookies.create(token, opts?)
auth.cookies.clear()
auth.cookies.name
auth.env.isNext / isNode / isBrowser / details
```

## Deprecations (Non-Breaking in 2.1.x)
| Deprecated | Replacement |
|------------|-------------|
| `signupCore` / `signinCore` / `logoutCore` direct usage | `auth.actions.*` |
| Scatter of cookie helpers | `auth.cookies.*` |
| Legacy flexible middleware variants | `auth.middleware.requireAuth` / `optionalAuth` |

(Removal targeted for 3.0.0; see Roadmap.)

## Migration Quick Guide
1. Replace direct imports: `import { signupCore } from 'authrix'` → `import { auth } from 'authrix'; await auth.actions.signup(...)`.
2. For cookie name, use `auth.cookies.name` instead of hardcoded `'auth_token'`.
3. For middleware, adopt `auth.middleware.requireAuth` (Express / Next API) or use Next route handlers via `auth.handlers.*`.
4. Optional rolling refresh: set `rollingSessionEnabled: true` and tune `rollingSessionThresholdSeconds`.
5. Remove any manual `Max-Age` calculations—central utilities now normalize.

## Rolling Session Behavior
When enabled, a new token is issued if remaining lifetime ≤ `rollingSessionThresholdSeconds`, extending session continuity while preserving a bounded absolute lifetime (re-issue retains canonical `sessionMaxAgeMs`).

## Logging & Observability
- Central logger reduces scattered `console.debug` usage.
- Structured warnings enable downstream filtering (e.g., collect only `{ category: 'deprecation' }`).
- Future: structured audit events & provider instrumentation (see Roadmap).

## Tests & Quality
| Test Area | Added / Updated |
|-----------|-----------------|
| Middleware tamper rejection | Added explicit negative test |
| Cookie maxAge normalization | Added baseline test |
| Rolling session refresh | Pending (see Roadmap) |
| Logging output | Adjusted expectations where brittle | 

## Potential Minor Behavior Changes
- Cookies now consistently include normalized security attributes (`HttpOnly`, `SameSite=lax` by default, `Secure` in production or forced). Adjust integration tests if they assumed missing attributes.
- Warning message formats changed to structured metadata; tests matching raw strings may need update.

## Upgrade Steps
```
npm install authrix@^2.1.0
```
Then incrementally migrate to the unified namespace. Keep legacy calls during transition; remove once refactor complete.

## Future Roadmap
### Near-Term (2.1.x → 2.2.x)
- Complete structuredWarn rollout (providers, email transports).
- Rolling session test matrix: (no refresh > threshold, refresh ≤ threshold, disabled path).
- Expanded cookie attribute test matrix (Next App Router vs Pages vs Express).
- Publish standalone migration guide (FAQ + code diff examples).
- Dual-dimension rate limiter (email + IP) tests & pluggable limiter contract doc.

### Mid-Term (2.2.x → 2.3.x)
- Provider observability events (oauth.start / success / failure) with correlation IDs.
- Prisma adapter completion & benchmark comparison docs.
- Harden forgot-password & 2FA flows (consistent generic responses, structured logging).
- Edge runtime guide refinements for cookie + streaming nuances.
- Config validation diagnostics (aggregate warnings on init).

### Pre-3.0.0
- JWT secret rotation helper & keyset strategy doc.
- Session replay mitigation exploration (nonce binding or token binding draft API).
- Deprecation reminder escalation (include planned removal version in messages).

### 3.0.0 Themes (Planned)
- Removal of deprecated legacy exports introduced prior to 2.1.0.
- Opt-in strict mode (enforce secure cookies everywhere unless explicitly disabled).
- Machine-readable error codes (stable contract) & unified error class taxonomy.
- Optional audit event hook (webhook / queue dispatcher).

## Deprecation Timeline (Tentative)
| Version | Action |
|---------|--------|
| 2.1.x | Introduce unified API + soft deprecations |
| 2.2.x | Publish full migration doc; broaden structured warnings |
| 2.3.x | Escalate deprecation messaging (removal notice) |
| 3.0.0 | Remove deprecated exports |

## Feedback
Open an issue tagged `unified-api` for migration questions or edge cases, especially around rolling refresh behavior and cookie interoperability in hybrid (App + Pages) Next.js deployments.

---
If you rely on any soon-to-be-deprecated path not listed here, please report it before 2.3.0 for inclusion in the final removal notice.
