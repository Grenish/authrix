## Bug report: Unified API handler `auth.handlers.signup` returns no Response in Next.js App Router

- Area: Unified API (Next.js App Router handlers)
- Affects: `auth.handlers.signup` (likely others under `auth.handlers`)
- Severity: High (POST /api/auth/signup returns 500)

### Environment
- OS: Windows
- Runtime: Bun (bun dev)
- Framework: Next.js (App Router, app directory)
- Package: authrix 2.1.x
- DB adapter: Mongo (configured via `initAuth`)
- Email: Resend (configured)
- Project files involved:
  - authrix.ts (calls `initAuth` once)
  - route.ts (Next.js API route)

### Summary
Following the Authrix 2.1 docs to export the unified Next.js handler, the route intermittently fails with:
- Error: “No response is returned from route handler '[project]/app/api/auth/signup/route.ts'. Ensure you return a Response or a NextResponse in all branches of your handler.”
- HTTP 500 on POST /api/auth/signup

This occurs when the route uses the documented form:
- export const POST = auth.handlers.signup;

It also fails when mistakenly calling the handler:
- export const POST = auth.handlers.signup();

In both cases, Next.js reports that no Response was returned.

### Steps to reproduce
1. Initialize Authrix in authrix.ts (called once at import time):
   - jwtSecret from env, cookieName default `auth_token`
   - db adapter mongo
   - email provider Resend
2. Create Next.js App Router route route.ts:
   - import `"@/lib/authrix"`; import `{ auth }` from `authrix`
   - export `const POST = auth.handlers.signup;`
3. Start dev server (bun dev)
4. POST to `/api/auth/signup` with JSON:
   - { "email": "user@example.com", "password": "StrongPass123!" }

### Expected
- 201/200 with JSON containing user info
- Set-Cookie with the auth token

### Actual
- 500 with:
  - “[Error: No response is returned from route handler '[project]/app/api/auth/signup/route.ts'. Ensure you return a Response or a NextResponse in all branches of your handler.]”
- Occurs consistently unless a manual wrapper is used

### Logs / Observations
- Importing `"@/lib/authrix"` before exporting the handler does not resolve it.
- Attempting to invoke the handler (i.e., `auth.handlers.signup(req)`) is rejected by TypeScript in some setups (signature mismatch), and invoking at import time (`auth.handlers.signup()`) returns undefined at runtime.
- Replacing the export with a manual implementation using `signupCore` that always returns `NextResponse` fixes the 500, suggesting the unified handler sometimes resolves to a function that returns undefined (or is undefined) in this environment.

### Minimal failing route
- Failing (per docs):
  - `export const POST = auth.handlers.signup;`
- Also fails (incorrect usage but commonly tried): 
  - `export const POST = auth.handlers.signup();`

### Working workaround
- Wrapper that tries the unified handler and falls back to core, always returning a Response and setting the cookie:
- Parses body JSON, calls `signupCore(email, password)`, sets cookie, returns `NextResponse.json({ user })`.

### Hypothesis
- Unified handler resolution under Bun/Next.js may return a function that does not return a Response (or returns undefined) in some conditions (e.g., environment detection, lazy Next import, or missing request binding).
- Alternatively, `auth.handlers.signup` may be undefined depending on init timing or path resolution.

### What would help
- Clarify the exact callable contract of `auth.handlers.signup` (accepts `req`? zero-arg function? function reference for Next to invoke with `req`?).
- Ensure handler factory returns a function that always returns a `Response`.
- Provide a small runtime guard so exporting `auth.handlers.signup` as documented always yields a function with `(req: Request) => Promise<Response>`.
- Add type definitions that match the actual invocation pattern to avoid confusion (e.g., avoid cases where TS reports “Expected 0 arguments, but got 1.”).

### Workarounds used
- Use manual route implementation with `signupCore` and `NextResponse`, set cookie explicitly.
- Optional: Try a wrapper that first calls `auth.handlers.signup(req)` if present and falls back to core.

Happy to provide a minimal repro if needed.