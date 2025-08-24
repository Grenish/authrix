import { authConfig } from "../config";

// Types
export interface LogoutOptions {
  invalidateAllSessions?: boolean;
  clearRememberMe?: boolean;
  redirectUrl?: string;
  extraClear?: string[];
}

export interface LogoutResult {
  success: boolean;
  message: string;
  cookiesToClear: CookieConfig[];
  redirectUrl?: string;
}

interface CookieConfig {
  name: string;
  options: CookieOptions;
}

interface CookieOptions {
  httpOnly: boolean;
  secure: boolean;
  sameSite: "lax" | "strict" | "none";
  path: string;
  expires: Date;
  domain?: string;
}

// Constants
const DEFAULT_COOKIE_OPTIONS: Omit<CookieOptions, 'expires'> = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
  path: "/"
} as const;

const EXPIRED_DATE = new Date(0);

const MESSAGES = {
  LOGOUT_SUCCESS: "Logged out successfully",
  LOGOUT_ALL_SUCCESS: "Logged out from all devices",
  DB_NOT_CONFIGURED: "Database not configured for session management",
  SESSION_INVALIDATION_PENDING: "[AUTHRIX] Session invalidation requested but not yet implemented",
  LOGOUT_ALL_PENDING: (userId: string) => `[AUTHRIX] Logout all devices requested for user ${userId} - not yet implemented`
} as const;

// Helper functions
const createCookieConfig = (name: string, options: Partial<CookieOptions> = {}): CookieConfig => ({
  name,
  options: {
    ...DEFAULT_COOKIE_OPTIONS,
    expires: EXPIRED_DATE,
    ...options
  }
});

const isValidCookieName = (name: unknown): name is string => 
  typeof name === 'string' && name.trim().length > 0;

// Cache for cookie configurations
const cookieConfigCache = new Map<string, CookieConfig>();

function getCachedCookieConfig(name: string): CookieConfig {
  if (!cookieConfigCache.has(name)) {
    cookieConfigCache.set(name, createCookieConfig(name));
  }
  return cookieConfigCache.get(name)!;
}

/**
 * Framework-agnostic logout function with enhanced security features
 * Made async to match the expected return type
 */
export async function logoutCore(options: LogoutOptions = {}): Promise<LogoutResult> {
  const {
    invalidateAllSessions = false,
    clearRememberMe = true,
    redirectUrl,
    extraClear = []
  } = options;

  // Build cookies to clear
  const cookiesToClear: CookieConfig[] = [
    getCachedCookieConfig(authConfig.cookieName)
  ];

  // Add remember me cookie if needed
  if (clearRememberMe) {
    cookiesToClear.push(
      getCachedCookieConfig(`${authConfig.cookieName}_remember`)
    );
  }

  // Add extra cookies efficiently
  const validExtraCookies = extraClear
    .filter(isValidCookieName)
    .map(name => getCachedCookieConfig(name.trim()));
  
  cookiesToClear.push(...validExtraCookies);

  // Handle session invalidation
  if (invalidateAllSessions) {
    // TODO: Implement session invalidation in database
    if (process.env.NODE_ENV === 'development') {
      console.log(MESSAGES.SESSION_INVALIDATION_PENDING);
    }
    // In the future, this would be an async operation:
    // await invalidateUserSessions(userId);
  }

  return {
    success: true,
    message: MESSAGES.LOGOUT_SUCCESS,
    cookiesToClear,
    redirectUrl
  };
}

/**
 * Express.js specific logout function for backward compatibility
 * Made async to be consistent with core function
 */
export async function logout(res: any, options?: LogoutOptions): Promise<{
  success: boolean;
  message: string;
  redirectUrl?: string;
}> {
  const result = await logoutCore(options);

  // Clear cookies if response object has clearCookie method
  if (res?.clearCookie) {
    const cookieOptionsMap = new Map<string, any>();
    
    result.cookiesToClear.forEach(({ name, options: cookieOptions }) => {
      // Cache cookie options for reuse
      const key = JSON.stringify(cookieOptions);
      if (!cookieOptionsMap.has(key)) {
        cookieOptionsMap.set(key, {
          httpOnly: cookieOptions.httpOnly,
          secure: cookieOptions.secure,
          sameSite: cookieOptions.sameSite,
          path: cookieOptions.path,
          ...(cookieOptions.domain && { domain: cookieOptions.domain })
        });
      }
      
      res.clearCookie(name, cookieOptionsMap.get(key));
    });
  }

  return {
    success: result.success,
    message: result.message,
    redirectUrl: result.redirectUrl
  };
}

/**
 * Logout from all devices (requires session management implementation)
 */
export async function logoutAllDevices(
  userId: string
): Promise<{
  success: boolean;
  message: string;
  sessionsInvalidated: number;
}> {
  if (!userId || typeof userId !== 'string') {
    throw new TypeError('Invalid userId provided');
  }

  const db = authConfig.db;
  if (!db) {
    throw new Error(MESSAGES.DB_NOT_CONFIGURED);
  }

  // TODO: Implement when session management is added
  // This would involve:
  // 1. Invalidating all JWT tokens for the user (requires token blacklisting)
  // 2. Clearing all active sessions from database
  // 3. Updating user's token version/salt to invalidate existing JWTs
  
  if (process.env.NODE_ENV === 'development') {
    console.log(MESSAGES.LOGOUT_ALL_PENDING(userId));
  }

  // Placeholder for future implementation
  // const sessionsInvalidated = await db.sessions.invalidateAll(userId);

  return {
    success: true,
    message: MESSAGES.LOGOUT_ALL_SUCCESS,
    sessionsInvalidated: 0 // Would be actual count when implemented
  };
}

// Export a synchronous version if needed for backward compatibility
export function logoutCoreSync(options: LogoutOptions = {}): LogoutResult {
  const {
    invalidateAllSessions = false,
    clearRememberMe = true,
    redirectUrl,
    extraClear = []
  } = options;

  const cookiesToClear: CookieConfig[] = [
    getCachedCookieConfig(authConfig.cookieName)
  ];

  if (clearRememberMe) {
    cookiesToClear.push(
      getCachedCookieConfig(`${authConfig.cookieName}_remember`)
    );
  }

  const validExtraCookies = extraClear
    .filter(isValidCookieName)
    .map(name => getCachedCookieConfig(name.trim()));
  
  cookiesToClear.push(...validExtraCookies);

  if (invalidateAllSessions && process.env.NODE_ENV === 'development') {
    console.log(MESSAGES.SESSION_INVALIDATION_PENDING);
  }

  return {
    success: true,
    message: MESSAGES.LOGOUT_SUCCESS,
    cookiesToClear,
    redirectUrl
  };
}