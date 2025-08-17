import type { AuthDbAdapter } from "../types/db";
import { EmailServiceRegistry } from "../core/emailRegistry";

// Use a global symbol to ensure true singleton across module boundaries
const AUTHRIX_CONFIG_KEY = Symbol.for("authrix.config.singleton");

// Singleton pattern to ensure authConfig is shared across all modules
class AuthConfigSingleton {
  private _jwtSecret: string = "";
  private _db: AuthDbAdapter | null = null;
  private _cookieName: string = "auth_token";
  private _forceSecureCookies: boolean = false; // P2: allow forcing secure cookies in dev
  private _sessionMaxAgeMs: number = 1000 * 60 * 60 * 24 * 7; // default 7d
  private _rollingSessionEnabled: boolean = false;
  private _rollingSessionThresholdSeconds: number = 60 * 60 * 24; // 24h remaining triggers refresh by default
  private _authPepper?: string; // optional explicit password pepper override

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

  public get authPepper(): string | undefined {
    return this._authPepper;
  }

  public set authPepper(value: string | undefined) {
    this._authPepper = value;
  }

  public init(config: {
    jwtSecret: string;
    db: AuthDbAdapter;
    cookieName?: string;
    forceSecureCookies?: boolean;
    authPepper?: string;
    email?: {
      defaultService?: string;
      providers?: {
        resend?: any;
        sendgrid?: any;
        gmail?: any;
        smtp?: any;
        console?: any;
      };
      autoDetect?: boolean; // default true
    };
    session?: {
      maxAgeMs?: number;
      rolling?: {
        enabled?: boolean;
        thresholdSeconds?: number;
      };
    };
  }) {
    this._jwtSecret = config.jwtSecret;
    this._db = config.db;
    if (config.authPepper) {
      this._authPepper = config.authPepper;
    }

    if (config.cookieName) {
      this._cookieName = config.cookieName;
    }
    if (typeof config.forceSecureCookies === "boolean") {
      this._forceSecureCookies = config.forceSecureCookies;
    }

    if (config.session) {
      if (typeof config.session.maxAgeMs === "number") {
        this._sessionMaxAgeMs = config.session.maxAgeMs;
      }
      if (config.session.rolling) {
        if (typeof config.session.rolling.enabled === "boolean") {
          this._rollingSessionEnabled = config.session.rolling.enabled;
        }
        if (typeof config.session.rolling.thresholdSeconds === "number") {
          this._rollingSessionThresholdSeconds =
            config.session.rolling.thresholdSeconds;
        }
      }
    }

    // Optional: initialize email services explicitly based on config
    if (config.email) {
      // Fire-and-forget; email providers are registered asynchronously
      void initEmailServices(config.email);
    }

    // Minimal init validation & optional log to aid setup
    const isProd = process.env.NODE_ENV === "production";
    if (!this._jwtSecret || this._jwtSecret.length < 12) {
      // eslint-disable-next-line no-console
      console.warn(
        "[Authrix] jwtSecret is short or missing. Set a strong secret via initAuth()."
      );
    }
    if (isProd && !process.env.AUTHRIX_PASSWORD_PEPPER) {
      // eslint-disable-next-line no-console
      console.warn(
        "[Authrix] AUTHRIX_PASSWORD_PEPPER is required in production and is currently missing."
      );
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
  },
  get authPepper() {
    return authConfigInstance.authPepper;
  },
  set authPepper(value: string | undefined) {
    authConfigInstance.authPepper = value;
  },
};

export function initAuth(config: {
  jwtSecret: string;
  db: AuthDbAdapter;
  cookieName?: string;
  forceSecureCookies?: boolean;
  authPepper?: string;
  email?: {
    defaultService?: string;
    providers?: {
      resend?: any;
      sendgrid?: any;
      gmail?: any;
      smtp?: any;
      console?: any;
    };
    autoDetect?: boolean;
  };
  session?: {
    maxAgeMs?: number;
    rolling?: {
      enabled?: boolean;
      thresholdSeconds?: number;
    };
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
    cookieName: authConfigInstance.cookieName,
  };
}

/**
 * Explicit email services initialization (config-first with env fallback)
 */
export async function initEmailServices(config?: {
  defaultService?: string;
  defaultEmailService?: string; // alias
  providers?: {
    resend?: any;
    sendgrid?: any;
    gmail?: any;
    smtp?: any;
    console?: any;
  };
  autoDetect?: boolean;
}) {
  const autoDetect = config?.autoDetect !== false;

  // Always register console (dev-friendly)
  try {
    const mod = await import("../email/console");
    EmailServiceRegistry.register("console", new mod.ConsoleEmailService());
  } catch {}

  // Configured providers take precedence
  if (config?.providers?.resend) {
    try {
      const mod = await import("../email/resend");
      const svc = new mod.ResendEmailService(config.providers.resend);
      EmailServiceRegistry.register("resend", svc);
      if (svc.capabilities)
        EmailServiceRegistry.setCapabilities("resend", svc.capabilities);
    } catch {}
  }
  if (config?.providers?.sendgrid) {
    try {
      const mod = await import("../email/sendgrid");
      const svc = new mod.SendGridEmailService(config.providers.sendgrid);
      EmailServiceRegistry.register("sendgrid", svc);
      if (svc.capabilities)
        EmailServiceRegistry.setCapabilities("sendgrid", svc.capabilities);
    } catch {}
  }
  if (config?.providers?.gmail) {
    try {
      const mod = await import("../email/gmail");
      const svc = new mod.GmailEmailService(config.providers.gmail);
      EmailServiceRegistry.register("gmail", svc);
      if (svc.capabilities)
        EmailServiceRegistry.setCapabilities("gmail", svc.capabilities);
    } catch {}
  }
  if (config?.providers?.smtp) {
    try {
      const mod = await import("../email/customSMTP");
      const svc = new mod.SMTPEmailService(config.providers.smtp);
      EmailServiceRegistry.register("smtp", svc);
      if (svc.capabilities)
        EmailServiceRegistry.setCapabilities("smtp", svc.capabilities);
    } catch {}
  }

  // Env-based auto-detect if enabled
  if (autoDetect) {
    try {
      if (process.env.RESEND_API_KEY && !EmailServiceRegistry.get("resend")) {
        const mod = await import("../email/resend");
        const svc = new mod.ResendEmailService();
        EmailServiceRegistry.register("resend", svc);
        if (svc.capabilities)
          EmailServiceRegistry.setCapabilities("resend", svc.capabilities);
      }
    } catch {}
    try {
      if (
        process.env.SENDGRID_API_KEY &&
        !EmailServiceRegistry.get("sendgrid")
      ) {
        const mod = await import("../email/sendgrid");
        const svc = new mod.SendGridEmailService();
        EmailServiceRegistry.register("sendgrid", svc);
        if (svc.capabilities)
          EmailServiceRegistry.setCapabilities("sendgrid", svc.capabilities);
      }
    } catch {}
    try {
      if (
        process.env.GMAIL_USER &&
        process.env.GMAIL_APP_PASSWORD &&
        !EmailServiceRegistry.get("gmail")
      ) {
        const mod = await import("../email/gmail");
        const svc = new mod.GmailEmailService();
        EmailServiceRegistry.register("gmail", svc);
        if (svc.capabilities)
          EmailServiceRegistry.setCapabilities("gmail", svc.capabilities);
      }
    } catch {}
    try {
      if (
        process.env.SMTP_HOST &&
        process.env.SMTP_USER &&
        process.env.SMTP_PASS &&
        !EmailServiceRegistry.get("smtp")
      ) {
        const mod = await import("../email/customSMTP");
        const svc = new mod.SMTPEmailService();
        EmailServiceRegistry.register("smtp", svc);
        if (svc.capabilities)
          EmailServiceRegistry.setCapabilities("smtp", svc.capabilities);
      }
    } catch {}
  }

  // Set default service
  const explicit =
    config?.defaultService ||
    config?.defaultEmailService ||
    process.env.DEFAULT_EMAIL_SERVICE;
  const priority = ["resend", "sendgrid", "gmail", "smtp", "console"];
  if (explicit && EmailServiceRegistry.get(explicit)) {
    EmailServiceRegistry.setDefault(explicit);
  } else {
    for (const name of priority) {
      if (EmailServiceRegistry.get(name)) {
        EmailServiceRegistry.setDefault(name);
        break;
      }
    }
  }

  return {
    services: EmailServiceRegistry.list(),
    default: EmailServiceRegistry.getDefault() ? "set" : null,
  };
}
