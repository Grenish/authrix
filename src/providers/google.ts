// Types
interface GoogleOAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

interface GoogleTokenResponse {
  access_token: string;
  expires_in: number;
  refresh_token?: string;
  scope: string;
  token_type: string;
  id_token: string;
}

interface GoogleUserInfo {
  sub: string;
  email: string;
  email_verified: boolean;
  name?: string;
  picture?: string;
  given_name?: string;
  family_name?: string;
  locale?: string;
  aud: string;
  iss: string;
  exp: number;
  iat: number;
}

interface OAuthUser {
  id: string;
  email: string;
  name?: string;
  avatar?: string;
  provider: "google";
  emailVerified: boolean;
  metadata?: {
    givenName?: string;
    familyName?: string;
    locale?: string;
  };
}

// Constants
const GOOGLE_OAUTH_ENDPOINTS = {
  AUTH: "https://accounts.google.com/o/oauth2/v2/auth",
  TOKEN: "https://oauth2.googleapis.com/token",
  USER_INFO: "https://www.googleapis.com/oauth2/v3/userinfo",
  TOKEN_INFO: "https://oauth2.googleapis.com/tokeninfo",
  REVOKE: "https://oauth2.googleapis.com/revoke",
} as const;

const DEFAULT_SCOPES = ["openid", "profile", "email"] as const;

// Configuration cache
let configCache: GoogleOAuthConfig | null = null;

// Environment variable loader with caching
function getGoogleOAuthConfig(): GoogleOAuthConfig {
  // Return cached config if available
  if (configCache) {
    return configCache;
  }

  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri =
    process.env.GOOGLE_REDIRECT_URI || process.env.GOOGLE_OAUTH_REDIRECT_URI;

  if (!clientId || !clientSecret || !redirectUri) {
    const missing = [];
    if (!clientId) missing.push("GOOGLE_CLIENT_ID");
    if (!clientSecret) missing.push("GOOGLE_CLIENT_SECRET");
    if (!redirectUri) missing.push("GOOGLE_REDIRECT_URI");

    throw new Error(
      `Missing Google OAuth environment variables: ${missing.join(", ")}. ` +
      `These are required when using Google OAuth functionality. ` +
      `Visit https://console.cloud.google.com/apis/credentials to obtain these values.`
    );
  }

  // Cache the configuration
  configCache = {
    clientId,
    clientSecret,
    redirectUri,
  };

  return configCache;
}

// JWT decoder for id_token (basic, no crypto validation)
function decodeJWT(token: string): any {
  try {
    const [, payload] = token.split(".");
    if (!payload) return null;

    const padded = payload + "=".repeat((4 - (payload.length % 4)) % 4);
    const decoded = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

// Main OAuth functions
export function getGoogleOAuthURL(
  options: {
    state?: string;
    scopes?: string[];
    loginHint?: string;
    prompt?: "none" | "consent" | "select_account";
    accessType?: "online" | "offline";
    includeGrantedScopes?: boolean;
    redirectUri?: string;
  } = {}
): string {
  const config = getGoogleOAuthConfig();

  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: options.redirectUri || config.redirectUri,
    response_type: "code",
    scope: (options.scopes || DEFAULT_SCOPES).join(" "),
    access_type: options.accessType || "online",
    prompt: options.prompt || "select_account",
    include_granted_scopes: String(options.includeGrantedScopes ?? true),
  });

  // Add optional parameters
  if (options.state) params.set("state", options.state);
  if (options.loginHint) params.set("login_hint", options.loginHint);

  return `${GOOGLE_OAUTH_ENDPOINTS.AUTH}?${params.toString()}`;
}

export async function handleGoogleCallback(
  code: string,
  options: {
    skipEmailVerification?: boolean;
    redirectUri?: string;
    includeTokens?: boolean;
  } = {}
): Promise<
  OAuthUser & { tokens?: { access: string; refresh?: string; idToken: string } }
> {
  const config = getGoogleOAuthConfig();

  try {
    // Exchange code for tokens
    const tokenResponse = await fetch(GOOGLE_OAUTH_ENDPOINTS.TOKEN, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: new URLSearchParams({
        code,
        client_id: config.clientId,
        client_secret: config.clientSecret,
        redirect_uri: options.redirectUri || config.redirectUri,
        grant_type: "authorization_code",
      }).toString(),
    });

    if (!tokenResponse.ok) {
      const error = await tokenResponse.text();
      throw new Error(
        `Token exchange failed: ${tokenResponse.status} - ${error}`
      );
    }

    const tokenData: GoogleTokenResponse = await tokenResponse.json();

    if (!tokenData.id_token) {
      throw new Error("No ID token received from Google");
    }

    // Decode and validate ID token (basic validation)
    const decodedToken = decodeJWT(tokenData.id_token);
    if (!decodedToken) {
      throw new Error("Failed to decode ID token");
    }

    // Validate token claims
    if (decodedToken.aud !== config.clientId) {
      throw new Error("Token audience mismatch");
    }

    if (
      decodedToken.iss !== "https://accounts.google.com" &&
      decodedToken.iss !== "accounts.google.com"
    ) {
      throw new Error("Invalid token issuer");
    }

    // Check token expiration
    const now = Math.floor(Date.now() / 1000);
    if (decodedToken.exp < now) {
      throw new Error("ID token has expired");
    }

    // For enhanced security, fetch user info from Google's API
    // This provides an additional verification layer
    let userInfo: GoogleUserInfo;

    if (tokenData.access_token) {
      // Use access token to fetch user info (more secure)
      const userResponse = await fetch(GOOGLE_OAUTH_ENDPOINTS.USER_INFO, {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
          Accept: "application/json",
        },
      });

      if (userResponse.ok) {
        userInfo = await userResponse.json();
      } else {
        // Fallback to decoded token data
        userInfo = decodedToken as GoogleUserInfo;
      }
    } else {
      // Use decoded token data
      userInfo = decodedToken as GoogleUserInfo;
    }

    // Validate email verification
    if (!options.skipEmailVerification && userInfo.email_verified !== true) {
      throw new Error("Email address is not verified");
    }

    // Build user object
    const user: OAuthUser = {
      id: userInfo.sub,
      email: userInfo.email,
      name: userInfo.name,
      avatar: userInfo.picture,
      provider: "google",
      emailVerified: userInfo.email_verified,
      metadata: {
        givenName: userInfo.given_name,
        familyName: userInfo.family_name,
        locale: userInfo.locale,
      },
    };

    // Include tokens if requested
    if (options.includeTokens) {
      return {
        ...user,
        tokens: {
          access: tokenData.access_token,
          refresh: tokenData.refresh_token,
          idToken: tokenData.id_token,
        },
      };
    }

    return user;
  } catch (error) {
    // Log error for debugging but return sanitized message
    console.error("[Google OAuth Error]:", error);

    if (error instanceof Error) {
      // Check for common errors and provide helpful messages
      if (error.message.includes("fetch")) {
        throw new Error(
          "Network error during Google authentication. Please try again."
        );
      }
      if (
        error.message.includes("audience") ||
        error.message.includes("issuer")
      ) {
        throw new Error("Security validation failed. Please try again.");
      }
      throw new Error(`Google authentication failed: ${error.message}`);
    }

    throw new Error(
      "An unexpected error occurred during Google authentication."
    );
  }
}

// Additional utility functions

/**
 * Revoke Google OAuth tokens
 */
export async function revokeGoogleTokens(token: string): Promise<boolean> {
  try {
    const response = await fetch(GOOGLE_OAUTH_ENDPOINTS.REVOKE, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ token }).toString(),
    });

    return response.ok;
  } catch (error) {
    console.error("[Google OAuth Revoke Error]:", error);
    return false;
  }
}

/**
 * Validate Google ID token (lightweight, no external dependencies)
 */
export async function validateGoogleIdToken(
  idToken: string
): Promise<GoogleUserInfo | null> {
  try {
    const response = await fetch(
      `${GOOGLE_OAUTH_ENDPOINTS.TOKEN_INFO}?id_token=${idToken}`
    );

    if (!response.ok) {
      return null;
    }

    const data: GoogleUserInfo = await response.json();
    const config = getGoogleOAuthConfig();

    // Validate audience
    if (data.aud !== config.clientId) {
      return null;
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (data.exp < now) {
      return null;
    }

    return data;
  } catch {
    return null;
  }
}

/**
 * Generate a secure state parameter for CSRF protection
 */
export function generateOAuthState(data?: any): string {
  const randomBytes = crypto.getRandomValues(new Uint8Array(32));
  const randomString = Array.from(randomBytes, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");

  if (data) {
    // Include custom data in state
    const json = JSON.stringify(data);
    const encoded = btoa(json)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
    return `${randomString}.${encoded}`;
  }

  return randomString;
}

/**
 * Parse OAuth state parameter
 */
export function parseOAuthState(state: string): { token: string; data?: any } {
  const parts = state.split(".");

  if (parts.length === 1) {
    return { token: parts[0] };
  }

  try {
    const encoded = parts[1];
    const padded = encoded + "=".repeat((4 - (encoded.length % 4)) % 4);
    const json = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
    const data = JSON.parse(json);

    return { token: parts[0], data };
  } catch {
    return { token: parts[0] };
  }
}

/**
 * Reset cached configuration (useful for testing)
 */
export function resetGoogleOAuthConfig(): void {
  configCache = null;
}
