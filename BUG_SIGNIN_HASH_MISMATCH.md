## Bug Report: Signin Always Fails With `Invalid email or password` (401) Despite Correct Credentials

### ID
BUG-SIGNIN-HASH-PEPPER-MISMATCH

### Status
Open

### Severity
High – Users cannot log in (hard auth failure) once condition is met.

### Summary
Signin requests return `401 Invalid email or password` even when the submitted password is correct. The failure occurs because the password hashing during signup (or during a hash upgrade) may use a **different pepper value** than the pepper used during verification at signin. The verification logic in `utils/hash.ts` ignores the optional `authPepper` configured via `initAuth()` and always applies the environment-driven pepper (`AUTHRIX_PASSWORD_PEPPER`). This creates a deterministic mismatch when these two peppers differ, making all password comparisons fail.

### Impact
- All accounts created (or rehashed) with a pepper supplied through `authConfig.authPepper` cannot authenticate unless that exact value matches `process.env.AUTHRIX_PASSWORD_PEPPER`.
- Silent failure pattern: Errors surface only as generic invalid credentials (no explicit pepper mismatch), increasing diagnosis time.
- Automatic hash upgrade (`verifyAndCheckRehash`) never triggers because verification never succeeds, so security posture cannot improve for affected users.

### Affected Components
- `src/core/signup.ts` (pepper override on hash)
- `src/core/signin.ts` (calls `verifyAndCheckRehash` which uses only security config pepper)
- `src/utils/hash.ts` (pepper sourcing + verification logic)
- `src/config/index.ts` (defines `authPepper` separate from security config)

### Relevant Code Excerpts
```
// signup.ts
const hashOptions: any = { ... };
if (authConfig.authPepper) {
  hashOptions.pepper = authConfig.authPepper; // <-- may differ from security config pepper
}
const hashedPassword = await hashPassword(password, hashOptions);

// utils/hash.ts (hashing)
const pepper = options.pepper || config.getPepper();

// utils/hash.ts (verify)
const pepper = config.getPepper(); // <-- DOES NOT consider options.pepper nor authConfig.authPepper
const pepperedPassword = this.applyPepper(password, pepper);

// signin.ts
const verifyResult = await verifyAndCheckRehash(password, user.password, { identifier: rateLimitId, updateHash: true });
```

### Root Cause
Two distinct pepper sources exist:
1. Environment-based pepper required by `SecurityConfig` (`AUTHRIX_PASSWORD_PEPPER`).
2. Runtime-configurable `authPepper` (optionally passed via `initAuth`).

During signup the hashing step prefers `authConfig.authPepper` if present, overriding the environment pepper. During signin the verification path **always** uses only the environment pepper (`config.getPepper()`) and never attempts `authConfig.authPepper`. If these values differ, the recomputed peppered password will not match the stored hash, causing verification to fail with an `UnauthorizedError`.

### Conditions to Trigger
Any of:
1. `initAuth({ authPepper: 'X' })` where `'X' !== process.env.AUTHRIX_PASSWORD_PEPPER`.
2. Pepper rotation attempt setting a new `authPepper` without updating `AUTHRIX_PASSWORD_PEPPER`.
3. Different environments (build vs runtime) injecting divergent pepper values.

### Not a Factor
- Algorithm difference (argon2id vs bcrypt) – detection works by hash prefix.
- Rehash logic – never reached because the initial verify fails.
- Rate limiting – failure occurs even on first attempt with correct credentials.

### Reproduction Steps
1. Set environment: `AUTHRIX_PASSWORD_PEPPER=AAAAAAAA...(>=32 chars)`.
2. Initialize auth:
   ```ts
   initAuth({ jwtSecret: 'secret', db, authPepper: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' });
   ```
3. Signup a user (password hashed with pepper `BBBB...`).
4. Attempt signin with the same credentials.
5. Observe 401 `Invalid email or password`.

### Diagnostics / How to Confirm
- Inspect a stored hash; compute a local verification using the signup pepper vs environment pepper.
- Temporarily patch `verify` to log first 16 bytes of the derived peppered input (never log the full password) and compare between signup & signin flows.
- Set `AUTHRIX_PASSWORD_PEPPER` to the same value as `authPepper` and retry signin – it will succeed.

### Proposed Fix Options
| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| A (Recommended) | Remove `authPepper` override usage in signup; always rely on `AUTHRIX_PASSWORD_PEPPER` (single source). | Simplifies mental model; fewer failure modes. | Breaking for deployments already using `authPepper` only. |
| B | Update verification logic to attempt both: primary pepper then (if fail) `authConfig.authPepper` (and rotation key). On success with secondary, rehash with primary. | Backward-compatible; smooth migration path. | Slight extra compute (second hash verify) and more complexity. |
| C | Encode pepper identifier/version into the stored hash (e.g. prefix tag) so verification can select correct pepper deterministically. | Future-proof; enables controlled rotation. | Requires migration logic; tag format decision. |
| D | Deprecate `authPepper` API; force using env var; add runtime warning if both differ. | Enforces consistency. | Requires communication; may disrupt existing setups. |

### Recommended Implementation (Hybrid: B → A Later)
1. Implement Option B now for immediate compatibility.
2. Emit a warning when `authPepper` !== `AUTHRIX_PASSWORD_PEPPER` explaining impending deprecation.
3. Document a migration path and set a future version to drop `authPepper` override.

### Patch Outline (Option B)
1. In `verify` (utils/hash.ts):
   - After failed primary pepper validation, if `authConfig.authPepper` is defined and different, retry verification using that pepper.
   - If succeeds, flag `needsRehash = true` so upgrade rehash uses canonical primary pepper.
2. In `hashPassword` remove passing of `authConfig.authPepper` (or keep until deprecation) and add warning if mismatch.
3. Add telemetry event `pepper_mismatch_recovered` when secondary pepper succeeds.
4. Update docs to clarify single canonical pepper.

### Validation Plan
1. Unit tests (new):
   - Hash with secondary pepper; verify with primary + fallback.
   - Ensure rehash migrates to primary pepper.
   - Ensure failure when neither pepper matches.
2. Regression: existing signup/signin tests pass with matching peppers.
3. Manual: simulate rotation by changing env pepper; confirm old accounts still login and are rehashed.

### Security Considerations
- Fallback attempt adds minimal brute-force surface (only one additional deterministic pepper trial).
- Ensure no timing side-channel: use constant-time comparison functions already in argon2/bcrypt libs; structure code to avoid large branching timing differences.

### Risks
- Silent acceptance of secondary pepper could mask misconfiguration if not logged; mitigate with structured warning.
- Deployments relying on differing peppers might delay consolidation if not alerted.

### Next Steps Checklist
- [ ] Implement fallback verification (Option B).
- [ ] Emit warning when dual peppers differ.
- [ ] Add tests for pepper mismatch + migration.
- [ ] Update README / docs about pepper management & rotation.
- [ ] Schedule deprecation notice for `authPepper` override.

### References
- Files: `core/signup.ts`, `core/signin.ts`, `utils/hash.ts`, `config/index.ts`.
- Function paths: `signupCore -> hashPassword`, `signinCore -> verifyAndCheckRehash -> hasher.verify`.

---
Prepared automatically to aid root-cause analysis and remediation planning.
