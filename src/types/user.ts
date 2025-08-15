import type { AuthUser } from "./db";

export const USER_COLLECTION = process.env.MONGO_USER_COLLECTION || "users";

// Keep User in sync with the canonical AuthUser shape
export type User = AuthUser;
