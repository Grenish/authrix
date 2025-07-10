import type { AuthDbAdapter } from "../types/db";

export let authConfig = {
  jwtSecret: "",
  db: null as AuthDbAdapter | null,
  cookieName: "auth_token",
};

export function initAuth(config: {
  jwtSecret: string;
  db: AuthDbAdapter;
  cookieName?: string;
}) {
  authConfig.jwtSecret = config.jwtSecret;
  authConfig.db = config.db;

  if (config.cookieName) {
    authConfig.cookieName = config.cookieName;
  }
}
