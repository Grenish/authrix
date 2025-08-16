# Bug Fix Plan: `auth.handlers.signup` returns no Response in Next.js App Router

Goal: Ensure `auth.handlers.*` exports are valid Next.js App Router route handlers with the signature `(req: Request) => Promise<Response>`, eliminating cases where Next.js reports “No response is returned…”.

Root cause summary
- In `src/auth.ts`, `auth.handlers.signup` (and siblings) are zero-argument async factories that resolve to a handler (`() => resolveHandler('signup')`). When exported directly in a Next.js route (`export const POST = auth.handlers.signup;`), Next invokes it with `(req)`, but the function returns a Promise that resolves to a function instead of a Response. This mismatch leads to Next.js treating it as no-return.

Scope of change (code-only; no tests here)
- Primary: `src/auth.ts` (reshape `handlers` to expose request-bound wrappers)
- Optional resilience: `src/frameworks/nextjs.ts` (small utility for error response generation if dynamic import fails)
- Public API remains stable (still `auth.handlers.signup`), but now it is callable by Next as a route handler.

Implementation checklist
1) Update `auth.handlers` to expose request-bound handlers
	- Change each handler (signup, signin, logout, currentUser, validateToken) from a zero-arg factory to an async function with signature `(request: Request) => Promise<Response>` that:
	  - Resolves the underlying Next handler via `resolveHandler(name)`
	  - Invokes it with the incoming `request`

2) Add defensive fallback when Next.js modules are unavailable
	- Wrap `resolveHandler` usage so that if dynamic import fails (non-Next env), the wrapper returns a JSON Response with status 500 and an actionable error message (instead of throwing and causing undefined returns)

3) Ensure typings align with Next.js expectations
	- Annotate each `auth.handlers.*` property to type `(request: Request) => Promise<Response>`
	- Keep the object type stable within `export const auth` to avoid breaking consumers

4) Verify cookie setting works in the new path
	- Confirm `create*Handler` functions in `src/frameworks/nextjs.ts` still set `Set-Cookie` and that the wrapper doesn’t strip headers
	- No change required in the cookie utilities, just a sanity check after wiring

5) Build and smoke-check locally
	- Build the package and ensure TypeScript emits without errors
	- In a Next.js App Router sample, export `auth.handlers.signup` directly and POST with email/password to confirm a 200/201 and `Set-Cookie`

6) Documentation touch-up (inline JSDoc only)
	- Add a brief JSDoc above `handlers` in `src/auth.ts` clarifying the callable contract for App Router: function reference suitable for `export const GET/POST = auth.handlers.*`

Edge cases to cover
- Import timing: Handlers should work regardless of when `initAuth` is called (as long as configuration is available at request time)
- Non-Next usage: If someone mistakenly calls these outside Next, they should receive a clear 500 JSON response instead of an unhandled throw
- Bun runtime: Avoid relying on `require`; keep dynamic imports as-is

Risk assessment
- Low risk, contained to `src/auth.ts`. The change makes the API more correct for the intended Next usage without removing existing exports.

Acceptance criteria
- `export const POST = auth.handlers.signup;` returns a valid Response in App Router
- No thrown error about missing return; correct cookie set behavior remains
- TypeScript infers `(req: Request) => Promise<Response>` for each handler

Out-of-scope for this patch
- Pages Router helpers are already provided via `create*HandlerPages()` and are unaffected
- Test updates (can be added separately)
