# Step-by-step Fix Plan: Next.js unified handler returns no Response

Purpose: Implement a safe change in `src/` so `auth.handlers.*` are valid Next.js App Router route handlers that always return a `Response`.

- [x] 1) Update handler exports in `src/auth.ts`
  - [x] Replace zero-arg factories in `auth.handlers` with request-bound wrappers: `(req: Request) => Promise<Response>`.
  - [x] Apply for: `signup`, `signin`, `logout`, `currentUser`, `validateToken`.

- [x] 2) Add defensive fallback in `src/auth.ts`
  - [x] Wrap `resolveHandler(name)` in `try/catch` and, on failure, return `Response.json({ error: message }, { status: 500 })` instead of throwing.

- [x] 3) Preserve public API & types
  - [x] Type each handler property explicitly as `(request: Request) => Promise<Response>`.
  - [x] Keep `auth` namespace shape stable and all existing exports intact.

- [x] 4) Ensure cookie behavior remains intact
  - [x] Confirm underlying `create*Handler` in `src/frameworks/nextjs.ts` sets `Set-Cookie` and wrapper forwards headers unchanged.

- [x] 5) Check (verification)
  - [x] Build the package to confirm TypeScript emits cleanly and types match expectations.
  - [x] Local smoke check using built handlers: verified a valid Response from `auth.handlers.logout` with expected `Set-Cookie` clearing header; `signup` path now returns structured error if not initialized and will work with `initAuth` (see smoke script setup for init).

- [ ] 6) Minimal docs touch (inline only)
  - [ ] Add a brief JSDoc above `auth.handlers` explaining the App Router callable contract for direct export (`export const GET/POST = auth.handlers.*`).

Notes
- Focus only on files under `src/`. No changes to tests in this patch.
- Dynamic imports must remain ESM-only and Bun/Edge-friendly; avoid `require`.
