# 🐛 Bug Report: Environment Variables Not Loading & Password Verification Failing

## Description

There are two critical issues observed while using **`authrix`** with the **MongoDB adapter**:

1. **Environment variables from `.env.local` are not being detected**, causing `createMongoAdapter` to throw an error about missing `MONGO_URI` and `DB_NAME`.  
   - Hardcoding the MongoDB URI and DB name into the adapter works as expected, but using `process.env.MONGO_URI` and `process.env.DB_NAME` fails.

2. **Sign-in fails due to incorrect password verification (hash mismatch)**, even when providing the correct email and password that were previously registered.

---

## 🔄 Steps to Reproduce

### Issue 1 — Env variables ignored in DB connection

1. Define `.env.local` with:
   ```env
   MONGO_URI=mongodb://127.0.0.1:27017
   DB_NAME=authrix_next
   JWT_SECRET=supersecret
   RESEND_API_KEY=fake_key
   RESEND_FROM_EMAIL=test@example.com
   RESEND_FROM_NAME=Authrix Test
   ```
2. Import and initialize auth as follows:
   ```ts
   const db = createMongoAdapter({
     uri: process.env.MONGO_URI!,
     dbName: process.env.DB_NAME,
   });
   ```
3. Run `signup`.

**Observed:**  
```
MongoDB connection failed: Missing required MongoDB configuration: MONGO_URI
```

**Expected:**  
The adapter should correctly pick up `MONGO_URI` and `DB_NAME` from `.env.local`.

---

### Issue 2 — Password verification fails on sign-in

1. Sign up with email + password (e.g., `test@example.com` + `password123`).
2. Attempt to sign in with the exact same user and password.
3. Error returned:  
   ```
   Invalid email or password
   ```

**Observed:**  
Even correct credentials fail, suggesting that the stored hash is not being properly compared during sign-in.

**Expected:**  
- User should be able to log in successfully with the correct email and password.  
- Hashing and verification should remain consistent across signup and signin.

---

## ✅ What Works

- Hardcoding MongoDB URI and DB name into `createMongoAdapter` works fine.
- The signup flow itself stores data in MongoDB as expected.

---

## ℹ️ Additional Details

- Env file used: `.env.local`  
- Framework: Next.js (assumption based on file naming and env behavior)  
- Affected library versions:  
  - `authrix`: (please confirm exact version)  
  - `authrix/adapters`: (please confirm exact version)  

---

## 📌 Possible Causes

1. **Environment vars loading** may not occur automatically at runtime. In Next.js, `.env.local` variables are only available if:
   - `dotenv` is explicitly imported in Node runtime code (server-side only).
   - Variables are prefixed with `NEXT_PUBLIC_` for client-side usage.  

   Suggestion: ensure that `dotenv.config()` (or equivalent) is called in `next.config.js` or server entrypoint.

2. **Password verification issue** could be due to:
   - An inconsistency in hashing algorithm (signup vs. signin).
   - Double-hashing or missing salt/rounds.
   - Mismatch between argon/bcrypt settings used.

---

## 💡 Proposed Fixes

- Ensure `authrix` loads env variables correctly at runtime (consider built-in `dotenv` integration).
- Review hashing/verification implementation in signin flow to confirm consistent use of the same algorithm and parameters.

---

## Severity

- **Blocking**: Prevents new developers from configuring auth without hardcoding secrets.  
- **High**: Login functionality is broken, rendering signup useless.