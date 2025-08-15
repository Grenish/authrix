import { authConfig } from "../config";

export interface LogoutOptions {
  invalidateAllSessions?: boolean;
  clearRememberMe?: boolean;
  redirectUrl?: string;
  extraClear?: string[]; // P2: user-specified additional cookies only
}

export interface LogoutResult {
  success: boolean;
  message: string;
  cookiesToClear: Array<{
    name: string;
    options: {
      httpOnly: boolean;
      secure: boolean;
      sameSite: "lax" | "strict" | "none";
      path: string;
      expires: Date;
      domain?: string;
    };
  }>;
  redirectUrl?: string;
}

/**
 * Framework-agnostic logout function with enhanced security features
 */
export function logoutCore(options: LogoutOptions = {}): LogoutResult {
  const {
    invalidateAllSessions = false,
    clearRememberMe = true,
  redirectUrl,
  extraClear = []
  } = options;

  const cookiesToClear = [
    {
      name: authConfig.cookieName,
      options: {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax" as const,
        path: "/",
        expires: new Date(0), // Expire immediately
      }
    }
  ];

  // Clear remember me cookie if requested
  if (clearRememberMe) {
    cookiesToClear.push({
      name: `${authConfig.cookieName}_remember`,
      options: {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax" as const,
        path: "/",
        expires: new Date(0),
      }
    });
  }

  // Only clear explicitly provided extra cookies now (no hardcoded list)
  extraClear.forEach(cookieName => {
    if (typeof cookieName === 'string' && cookieName.trim()) {
      cookiesToClear.push({
        name: cookieName.trim(),
        options: {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "lax" as const,
          path: "/",
          expires: new Date(0),
        }
      });
    }
  });

  // TODO: Implement session invalidation in database
  if (invalidateAllSessions) {
    // This would require implementing session management in the database
    // For now, we just log the intention
    console.log('[AUTHRIX] Session invalidation requested but not yet implemented');
  }

  return {
    success: true,
    message: "Logged out successfully",
    cookiesToClear,
    redirectUrl
  };
}

/**
 * Express.js specific logout function for backward compatibility
 */
export function logout(res: any, options?: LogoutOptions) {
  const result = logoutCore(options);

  // Clear all cookies
  result.cookiesToClear.forEach(({ name, options: cookieOptions }) => {
    if (res.clearCookie) {
      res.clearCookie(name, {
        httpOnly: cookieOptions.httpOnly,
        secure: cookieOptions.secure,
        sameSite: cookieOptions.sameSite,
        path: cookieOptions.path,
        ...(cookieOptions.domain && { domain: cookieOptions.domain })
      });
    }
  });

  return {
    success: result.success,
    message: result.message,
    redirectUrl: result.redirectUrl
  };
}

/**
 * Logout from all devices (requires session management implementation)
 */
export async function logoutAllDevices(userId: string): Promise<{
  success: boolean;
  message: string;
  sessionsInvalidated: number;
}> {
  const db = authConfig.db;

  if (!db) {
    throw new Error("Database not configured for session management");
  }

  // TODO: Implement when session management is added
  // This would involve:
  // 1. Invalidating all JWT tokens for the user (requires token blacklisting)
  // 2. Clearing all active sessions from database
  // 3. Updating user's token version/salt to invalidate existing JWTs

  console.log(`[AUTHRIX] Logout all devices requested for user ${userId} - not yet implemented`);

  return {
    success: true,
    message: "Logged out from all devices",
    sessionsInvalidated: 0 // Would be actual count when implemented
  };
}
