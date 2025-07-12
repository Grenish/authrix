import type { AuthDbAdapter } from "../types/db";

// Use a global symbol to ensure true singleton across module boundaries
const AUTHRIX_CONFIG_KEY = Symbol.for('authrix.config.singleton');

// Singleton pattern to ensure authConfig is shared across all modules
class AuthConfigSingleton {
  private _jwtSecret: string = "";
  private _db: AuthDbAdapter | null = null;
  private _cookieName: string = "auth_token";

  private constructor() {}

  public static getInstance(): AuthConfigSingleton {
    // Use global symbol to ensure singleton across module boundaries
    if (!(globalThis as any)[AUTHRIX_CONFIG_KEY]) {
      (globalThis as any)[AUTHRIX_CONFIG_KEY] = new AuthConfigSingleton();
    }
    return (globalThis as any)[AUTHRIX_CONFIG_KEY];
  }

  public get jwtSecret(): string {
    return this._jwtSecret;
  }

  public set jwtSecret(value: string) {
    this._jwtSecret = value;
  }

  public get db(): AuthDbAdapter | null {
    return this._db;
  }

  public set db(value: AuthDbAdapter | null) {
    this._db = value;
  }

  public get cookieName(): string {
    return this._cookieName;
  }

  public set cookieName(value: string) {
    this._cookieName = value;
  }

  public init(config: {
    jwtSecret: string;
    db: AuthDbAdapter;
    cookieName?: string;
  }) {
    this._jwtSecret = config.jwtSecret;
    this._db = config.db;
    
    if (config.cookieName) {
      this._cookieName = config.cookieName;
    }
  }
}

// Create a singleton instance
const authConfigInstance = AuthConfigSingleton.getInstance();

// Export a proxy object that maintains compatibility with existing code
export const authConfig = {
  get jwtSecret() {
    return authConfigInstance.jwtSecret;
  },
  set jwtSecret(value: string) {
    authConfigInstance.jwtSecret = value;
  },
  get db() {
    return authConfigInstance.db;
  },
  set db(value: AuthDbAdapter | null) {
    authConfigInstance.db = value;
  },
  get cookieName() {
    return authConfigInstance.cookieName;
  },
  set cookieName(value: string) {
    authConfigInstance.cookieName = value;
  }
};

export function initAuth(config: {
  jwtSecret: string;
  db: AuthDbAdapter;
  cookieName?: string;
}) {
  authConfigInstance.init(config);
}

/**
 * Check if Authrix is properly initialized
 * Useful for debugging configuration issues
 */
export function isAuthrixInitialized(): boolean {
  return !!(authConfigInstance.jwtSecret && authConfigInstance.db);
}

/**
 * Get the current initialization status for debugging
 */
export function getAuthrixStatus() {
  return {
    jwtSecret: authConfigInstance.jwtSecret ? "[PRESENT]" : "[MISSING]",
    db: authConfigInstance.db ? "[CONFIGURED]" : "[NOT CONFIGURED]",
    cookieName: authConfigInstance.cookieName
  };
}
