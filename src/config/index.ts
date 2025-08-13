import type { AuthDbAdapter } from "../types/db";

// Use a global symbol to ensure true singleton across module boundaries
const AUTHRIX_CONFIG_KEY = Symbol.for('authrix.config.singleton');

// Singleton pattern to ensure authConfig is shared across all modules
class AuthConfigSingleton {
  private _jwtSecret: string = "";
  private _db: AuthDbAdapter | null = null;
  private _cookieName: string = "auth_token";
  private _forceSecureCookies: boolean = false; // P2: allow forcing secure cookies in dev
  private _sessionMaxAgeMs: number = 1000 * 60 * 60 * 24 * 7; // default 7d
  private _rollingSessionEnabled: boolean = false;
  private _rollingSessionThresholdSeconds: number = 60 * 60 * 24; // 24h remaining triggers refresh by default

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

  public get forceSecureCookies(): boolean {
    return this._forceSecureCookies;
  }

  public set forceSecureCookies(value: boolean) {
    this._forceSecureCookies = value;
  }

  public get sessionMaxAgeMs(): number {
    return this._sessionMaxAgeMs;
  }

  public set sessionMaxAgeMs(value: number) {
    if (value > 0) this._sessionMaxAgeMs = value;
  }

  public get rollingSessionEnabled(): boolean {
    return this._rollingSessionEnabled;
  }

  public set rollingSessionEnabled(value: boolean) {
    this._rollingSessionEnabled = value;
  }

  public get rollingSessionThresholdSeconds(): number {
    return this._rollingSessionThresholdSeconds;
  }

  public set rollingSessionThresholdSeconds(value: number) {
    if (value > 0) this._rollingSessionThresholdSeconds = value;
  }

  public init(config: {
    jwtSecret: string;
    db: AuthDbAdapter;
    cookieName?: string;
    forceSecureCookies?: boolean;
    session?: {
      maxAgeMs?: number;
      rolling?: {
        enabled?: boolean;
        thresholdSeconds?: number;
      }
    };
  }) {
    this._jwtSecret = config.jwtSecret;
    this._db = config.db;
    
    if (config.cookieName) {
      this._cookieName = config.cookieName;
    }
    if (typeof config.forceSecureCookies === 'boolean') {
      this._forceSecureCookies = config.forceSecureCookies;
    }

    if (config.session) {
      if (typeof config.session.maxAgeMs === 'number') {
        this._sessionMaxAgeMs = config.session.maxAgeMs;
      }
      if (config.session.rolling) {
        if (typeof config.session.rolling.enabled === 'boolean') {
          this._rollingSessionEnabled = config.session.rolling.enabled;
        }
        if (typeof config.session.rolling.thresholdSeconds === 'number') {
          this._rollingSessionThresholdSeconds = config.session.rolling.thresholdSeconds;
        }
      }
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
  },
  get forceSecureCookies() {
    return authConfigInstance.forceSecureCookies;
  },
  set forceSecureCookies(value: boolean) {
    authConfigInstance.forceSecureCookies = value;
  },
  get sessionMaxAgeMs() {
    return authConfigInstance.sessionMaxAgeMs;
  },
  set sessionMaxAgeMs(value: number) {
    authConfigInstance.sessionMaxAgeMs = value;
  },
  get rollingSessionEnabled() {
    return authConfigInstance.rollingSessionEnabled;
  },
  set rollingSessionEnabled(value: boolean) {
    authConfigInstance.rollingSessionEnabled = value;
  },
  get rollingSessionThresholdSeconds() {
    return authConfigInstance.rollingSessionThresholdSeconds;
  },
  set rollingSessionThresholdSeconds(value: number) {
    authConfigInstance.rollingSessionThresholdSeconds = value;
  }
};

export function initAuth(config: {
  jwtSecret: string;
  db: AuthDbAdapter;
  cookieName?: string;
  forceSecureCookies?: boolean;
  session?: {
    maxAgeMs?: number;
    rolling?: {
      enabled?: boolean;
      thresholdSeconds?: number;
    }
  };
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
