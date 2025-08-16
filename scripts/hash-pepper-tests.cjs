#!/usr/bin/env node
/*
 T-Hash-1: Signup → verify (current pepper) → should pass.
 T-Hash-2: Simulate pepper switch mid-process: set initial pepper, create hash; switch to new pepper; verify succeeds via previous pepper; rehash flagged.
 T-Hash-3: After rehash, verify with current pepper only passes.
*/
(async () => {
  try {
    // Ensure dev defaults and disable explicit peppers in env
    process.env.NODE_ENV = process.env.NODE_ENV || 'development';
    delete process.env.AUTHRIX_PASSWORD_PEPPER;
    process.env.AUTHRIX_ALLOW_PREV_PEPPER_FALLBACK = process.env.AUTHRIX_ALLOW_PREV_PEPPER_FALLBACK || 'true';

    // Import after env setup so SecurityConfig initializes accordingly
    const {
      hashPassword,
      verifyAndCheckRehash,
      initAuth,
      authConfig,
    } = require('../dist/index.cjs');

    const password = 'Str0ngP@ssw0rd!';

    // T-Hash-1: hash + verify with current (initial) pepper
    const hash1 = await hashPassword(password);
    const res1 = await verifyAndCheckRehash(password, hash1, { updateHash: true });
    if (!res1.valid) throw new Error('T-Hash-1 failed: initial verify should be valid');
    console.log('[T-Hash-1] PASS');

    // T-Hash-2: simulate pepper switch mid-process by setting jwtSecret now
    // (SecurityConfig will switch from dev-generated pepper to derived-from-jwt pepper
    // and record previous pepper for one-time fallback.)
    initAuth({
      jwtSecret: 'this-is-a-long-jwt-secret-for-derivation',
      db: {
        // minimal db adapter to satisfy initAuth, not used here
        createUser: async () => { throw new Error('not used'); },
        getUserByEmail: async () => null,
        findUserByEmail: async () => null,
        getUserById: async () => null,
        findUserById: async () => null,
        updateUser: async () => { throw new Error('not used'); },
        findUserByUsername: async () => null,
        storeTwoFactorCode: async () => { throw new Error('not used'); },
        getTwoFactorCode: async () => null,
        updateTwoFactorCode: async () => { throw new Error('not used'); },
        getUserTwoFactorCodes: async () => [],
        cleanupExpiredTwoFactorCodes: async () => 0,
      },
      // do not set authPepper here to trigger derived pepper path
      session: { rolling: { enabled: false } }
    });

    const res2 = await verifyAndCheckRehash(password, hash1, { updateHash: true });
    if (!res2.valid) throw new Error('T-Hash-2 failed: verify after pepper switch should be valid via previous pepper');
    if (!res2.needsRehash || !res2.newHash) throw new Error('T-Hash-2 failed: expected needsRehash and newHash to be set');
    console.log('[T-Hash-2] PASS');

    // T-Hash-3: After rehash, verifying with current pepper should pass
    const res3 = await verifyAndCheckRehash(password, res2.newHash, { updateHash: true });
    if (!res3.valid) throw new Error('T-Hash-3 failed: verify after rehash should be valid with current pepper');
    console.log('[T-Hash-3] PASS');

    console.log('All T-Hash tests passed');
    process.exit(0);
  } catch (err) {
    console.error(err && err.stack ? err.stack : err);
    process.exit(1);
  }
})();
