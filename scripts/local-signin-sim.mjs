// Quick local sign-in simulation
// - Generates a secure base64 pepper at runtime (not printed)
// - Initializes an in-memory DB
// - Creates a legacy (no-pepper) argon2 hash user and verifies sign-in triggers rehash
// - Creates a current (peppered) user and verifies sign-in works without rehash

// Ensure parameters within enforced bounds for local run
// Min bounds: BCRYPT_ROUNDS>=12, ARGON2_TIME_COST>=2, ARGON2_MEMORY_COST>=32768
process.env.AUTHRIX_ARGON2_TIME_COST = process.env.AUTHRIX_ARGON2_TIME_COST || '2';
process.env.AUTHRIX_ARGON2_MEMORY_COST = process.env.AUTHRIX_ARGON2_MEMORY_COST || '32768';
process.env.AUTHRIX_ARGON2_PARALLELISM = process.env.AUTHRIX_ARGON2_PARALLELISM || '1';
process.env.AUTHRIX_BCRYPT_ROUNDS = process.env.AUTHRIX_BCRYPT_ROUNDS || '12';

import crypto from 'crypto';
// Secure base64 pepper (>= 32 chars, base64 format)
process.env.AUTHRIX_PASSWORD_PEPPER = process.env.AUTHRIX_PASSWORD_PEPPER || crypto.randomBytes(48).toString('base64');

// Load libs after env is set
const { initAuth, auth, hashPassword } = await import('../dist/index.mjs');
import * as bcrypt from 'bcryptjs';

function createMemoryAdapter() {
  const users = new Map();
  const byEmail = new Map();
  return {
    async findUserByEmail(email) {
      return byEmail.get(email) || null;
    },
    async getUserByEmail(email) {
      return byEmail.get(email) || null;
    },
    async findUserById(id) {
      return users.get(id) || null;
    },
    async findUserByUsername(username) {
      for (const u of users.values()) {
        if (u.username === username) return u;
      }
      return null;
    },
    async createUser(data) {
      const id = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
      const user = { id, createdAt: new Date(), ...data };
      users.set(id, user);
      byEmail.set(user.email, user);
      return user;
    },
    async updateUser(id, patch) {
      const curr = users.get(id);
      if (!curr) throw new Error('User not found');
      const updated = { ...curr, ...patch };
      users.set(id, updated);
      byEmail.set(updated.email, updated);
      return updated;
    },
  };
}

function logResult(label, obj) {
  console.log(`\n[${label}]`);
  console.log(JSON.stringify(obj, null, 2));
}

async function run() {
  const db = createMemoryAdapter();
  initAuth({ jwtSecret: 'local-sim-secret-1234567890', db });

  // Case 1: Legacy (no-pepper) argon2 user
  const legacyEmail = 'legacy@example.com';
  const legacyPassword = 'S0me_Strong!Pass';
  const legacyHash = await bcrypt.hash(legacyPassword, 12);
  const legacyUser = await db.createUser({ email: legacyEmail, password: legacyHash, emailVerified: true });

  try {
    const res = await auth.actions.signin(legacyEmail, legacyPassword);
    const after = await db.findUserByEmail(legacyEmail);
    const upgraded = after && after.password !== legacyUser.password;
    logResult('Legacy user signin', {
      success: true,
      tokenPresent: !!res.token,
      upgraded,
      newHashAlgorithm: after?.password?.startsWith('$argon2') ? 'argon2' : (after?.password?.startsWith('$2') ? 'bcrypt' : 'unknown'),
    });
  } catch (e) {
    logResult('Legacy user signin', { success: false, error: e?.message || String(e) });
  }

  // Case 2: Current (peppered) user
  const currentEmail = 'current@example.com';
  const currentPassword = 'An0ther_Strong!Pass';
  const currentHash = await hashPassword(currentPassword);
  await db.createUser({ email: currentEmail, password: currentHash, emailVerified: true });

  try {
    const res = await auth.actions.signin(currentEmail, currentPassword);
    const after = await db.findUserByEmail(currentEmail);
    const rehashed = after && after.password !== currentHash; // typically should be false
    logResult('Current user signin', {
      success: true,
      tokenPresent: !!res.token,
      rehashed,
    });
  } catch (e) {
    logResult('Current user signin', { success: false, error: e?.message || String(e) });
  }

  // Case 3: Wrong password should fail
  try {
    await auth.actions.signin(currentEmail, 'WrongPassword!');
    logResult('Wrong password signin', { success: true, unexpected: true });
  } catch (e) {
    logResult('Wrong password signin', { success: false, error: e?.message || String(e) });
  }
}

run().catch((e) => {
  console.error('Simulation error:', e?.stack || e);
  process.exit(1);
});
