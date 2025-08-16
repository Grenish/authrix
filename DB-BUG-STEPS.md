# ✅ MongoDB Adapter API Improvement Checklist

### 1. Core API Enhancements
- [x] **Keep existing export:**  
  `export const mongoAdapter: AuthDbAdapter;` (env‑driven, unchanged).
- [x] **Add explicit factory export:**  
  `export function createMongoAdapter(options?: {...}): AuthDbAdapter`.
  - [x] Accept `uri`, `dbName`, optional collection names, pooling options.
  - [x] If `dbName` not passed, auto‑infer from URI (mongodb://.../mydb).
  - [x] No mutation of `process.env`.
- [x] **Add convenience helpers:**
  - [x] `parseMongoUri(uri) -> { dbName?: string }`.
  - [x] `configureMongoAdapter(opts)` → sets global override config, used in place of env.
  - [x] `healthCheckMongo() -> Promise<{ ok: boolean; message?: string }>`.

---

### 2. Backward Compatibility & Deprecation
- [x] Keep env‑driven adapter fully functional.  (mongoAdapter usage unchanged)
- [x] Make `DB_NAME` canonical, accept **`MONGO_DB` as alias**: (implemented in `src/adapters/mongo.ts` loadConfig)
  - [x] Emit one-time `console.warn` on `MONGO_DB` usage (“deprecated, use DB_NAME instead”).
- [x] Maintain lazy/singleton connection behavior (no eager connect).  (existing `MongoConnection` pattern preserved)

---

### 3. Optimizations
- [x] **URI/dbName inference:**
  - [x] If no DB_NAME but URI path exists, infer dbName. (in `loadConfig()` using `parseMongoUri`)
  - [x] Throw detailed error if neither present (env + factory examples included).
- [x] **Index creation guard:**
  - [x] Added “created once” flag keyed by `dbName|authCollection|twoFactorCollection` to avoid duplicate work.
- [x] **Improved diagnostics:**
  - [x] Clear error with missing key names and examples.
  - [x] SRV hint included for mongodb+srv DNS/TLS/IP allowlist issues.
- [x] **Connection pooling:**
  - [x] Defaults unchanged; overrides accepted via `configureMongoAdapter({ options })` and factory options.
- [x] **Resilience (optional):**
  - [x] Added lightweight retry with backoff (`retryConnect`, `retryAttempts`). Default off.

---

### 4. Implementation Steps
- [x] Implement `createMongoAdapter` in `src/adapters/mongo.ts`:
  - [x] Build adapter instance using options > config override > env fallback. (via `configureMongoAdapter` layering)
  - [x] Keep clean layering; no env mutation. (override only; env untouched)
- [x] Implement `configureMongoAdapter()`:
  - [x] Store global in‑mem override for env reads. (module-level override object)
  - [x] Ensure `mongoAdapter` respects this override. (used in `loadConfig()`)
- [x] Implement `parseMongoUri()` for dbName inference/error clarity. (exported helper)
- [x] Export new utilities and adapters in `src/adapters/index.ts`. (named exports added)
- [x] Enhance `loadConfig()`:
  - [x] Accept DB_NAME or MONGO_DB. (with one-time deprecation warn)
  - [x] Emit deprecation warning if using MONGO_DB. (console.warn once)
  - [x] Apply dbName inference from URI path. (uses `parseMongoUri`)
- [x] Add `healthCheckMongo()` wrapper to test connectivity. (returns { ok, message? })
- [x] Ensure index creation has guard (dbName+collection signature). (signature set prevents duplicates)

---

### 5. Testing & Validation
- [ ] **Env-driven flow:**  
  - [ ] Verify `MONGO_URI + DB_NAME` works.  
  - [ ] Verify `MONGO_DB` works with warning.
- [ ] **Factory flow:**  
  - [ ] Call `createMongoAdapter({ uri, dbName })` with no env → succeeds.  
  - [ ] Omit dbName but include in URI → auto-inferral works.  
  - [ ] Invalid config → clear actionable error.
- [ ] **configureMongoAdapter() flow:**  
  - [ ] Call override before `initAuth`; ensure mongoAdapter uses override instead of env.
- [ ] **healthCheckMongo():**  
  - [ ] Returns `{ ok: true }` when valid, `{ ok: false, message }` when invalid.
- [ ] **Index guard:**  
  - [ ] Multiple reloads don’t trigger duplicate index operations.
- [ ] **Resilience flag:**  
  - [ ] With `retryConnect: true`, transient errors recover gracefully.  
  - [ ] With default `false`, behavior unchanged.

---

### 6. Documentation
- [x] Update **NEXTJS_QUICK_START.md**:
  - [x] Show env‑driven usage (as today).
  - [x] Show factory usage via `createMongoAdapter(...)` as alternative. (added Option A/B section)
- [x] Add Troubleshooting section:
  - [x] Example errors when DB_NAME missing. (added explicit remedies)
  - [x] How to fix via env or explicit factory. (documented)
- [x] Add migration notes:
  - [x] Users on `MONGO_DB` → switch to `DB_NAME` or tolerate warning. (note at bottom)
- [x] Update examples:
  - [x] Next.js with `mongoAdapter` env flow. (resend example)
  - [x] Commented alternative using `createMongoAdapter`. (comment block in `app/lib/authrix.ts`)

---

### 7. Acceptance Criteria
- [ ] Existing `mongoAdapter` continues to work in env scenarios.  
- [ ] DB_NAME or MONGO_DB both accepted, with proper warnings.  
- [ ] `createMongoAdapter` works standalone without env.  
- [ ] Connection and cookie handling unaffected.  
- [ ] Clear error messages and diagnostics where misconfigured.  
- [ ] Types remain stable (`AuthDbAdapter` contract unchanged).  

---

### 8. Nice-to-Have (Post-MVP)
- [ ] Add `eagerConnect?: boolean` option in factory.
- [ ] Add structured logging toggle (`AUTHRIX_DEBUG_DB`).  