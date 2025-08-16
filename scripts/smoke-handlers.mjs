// Simple smoke test to ensure auth.handlers.* return a Response and set cookie
// Set env before dynamic import to keep hashing fast in local smoke
process.env.AUTHRIX_ARGON2_TIME_COST = process.env.AUTHRIX_ARGON2_TIME_COST || '2';
process.env.AUTHRIX_ARGON2_MEMORY_COST = process.env.AUTHRIX_ARGON2_MEMORY_COST || '2048';
process.env.AUTHRIX_PASSWORD_PEPPER = process.env.AUTHRIX_PASSWORD_PEPPER || 'dev-pepper-12345678901234567890-XXXX';

const { auth, initAuth } = await import('../dist/index.mjs');

// Minimal in-memory adapter
function createMemoryAdapter() {
  const users = new Map();
  const byEmail = new Map();
  const byUsername = new Map();
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
      return byUsername.get(username) || null;
    },
    async createUser(data) {
      const id = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
      const user = { id, createdAt: new Date(), ...data };
      users.set(id, user);
      byEmail.set(user.email, user);
      if (user.username) byUsername.set(user.username, user);
      return user;
    },
    async updateUser(id, patch) {
      const curr = users.get(id);
      if (!curr) throw new Error('not found');
      const updated = { ...curr, ...patch };
      users.set(id, updated);
      return updated;
    }
  };
}

async function run() {
  // Initialize auth
  initAuth({ jwtSecret: 'test-secret-12345-abc', db: createMemoryAdapter() });

  // Construct a Request for the logout handler (does not require DB or hashing)
  const req = new Request('http://localhost/api/auth/logout', { method: 'POST' });

  const res = await auth.handlers.logout(req);
  console.log('Status:', res.status);
  console.log('Content-Type:', res.headers.get('content-type'));
  console.log('Set-Cookie:', res.headers.get('set-cookie'));
  try {
    const json = await res.json();
    console.log('Body:', json);
  } catch (e) {
    console.log('Body not JSON');
  }
}

run().catch(err => {
  console.error('Smoke test error:', err);
  process.exit(1);
});
