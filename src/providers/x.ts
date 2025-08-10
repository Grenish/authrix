// Types
interface XOAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

interface XTokenResponse {
  token_type: string;
  expires_in: number;
  access_token: string;
  scope: string;
  refresh_token?: string;
}

interface XUserResponse {
  data: {
    id: string;
    name: string;
    username: string;
    created_at: string;
    description?: string;
    location?: string;
    url?: string;
    verified: boolean;
    verified_type?: "blue" | "business" | "government" | "none";
    profile_image_url?: string;
    public_metrics?: {
      followers_count: number;
      following_count: number;
      tweet_count: number;
      listed_count: number;
      like_count: number;
    };
    protected: boolean;
  };
  includes?: {
    tweets?: Array<any>;
  };
}

interface XEmailResponse {
  email: string;
  verified: boolean;
}

interface OAuthUser {
  id: string;
  email?: string;
  username: string;
  name: string;
  avatar?: string;
  provider: "x" | "twitter";
  emailVerified: boolean;
  metadata?: {
    description?: string;
    location?: string;
    url?: string;
    verified: boolean;
    verifiedType?: string;
    protected: boolean;
    followersCount?: number;
    followingCount?: number;
    tweetCount?: number;
    likeCount?: number;
    createdAt?: string;
  };
}

interface PKCEChallenge {
  codeVerifier: string;
  codeChallenge: string;
  state: string;
}

// Constants
const X_OAUTH_ENDPOINTS = {
  AUTHORIZE: "https://twitter.com/i/oauth2/authorize",
  TOKEN: "https://api.twitter.com/2/oauth2/token",
  REVOKE: "https://api.twitter.com/2/oauth2/revoke",
  USER: "https://api.twitter.com/2/users/me",
  USER_BY_ID: (id: string) => `https://api.twitter.com/2/users/${id}`,
} as const;

const DEFAULT_SCOPES = ["tweet.read", "users.read", "offline.access"] as const;

const USER_FIELDS = [
  "id",
  "name",
  "username",
  "created_at",
  "description",
  "location",
  "url",
  "verified",
  "verified_type",
  "profile_image_url",
  "public_metrics",
  "protected",
] as const;

// Configuration cache
let configCache: XOAuthConfig | null = null;

// PKCE storage (in production, use a proper cache like Redis)
const pkceStorage = new Map<string, PKCEChallenge>();

// Environment variable loader with caching
function getXOAuthConfig(): XOAuthConfig {
  if (configCache) {
    return configCache;
  }

  const clientId = process.env.X_CLIENT_ID || process.env.TWITTER_CLIENT_ID;
  const clientSecret =
    process.env.X_CLIENT_SECRET || process.env.TWITTER_CLIENT_SECRET;
  const redirectUri =
    process.env.X_REDIRECT_URI || process.env.TWITTER_REDIRECT_URI;

  if (!clientId || !clientSecret || !redirectUri) {
    const missing = [];
    if (!clientId) missing.push("X_CLIENT_ID or TWITTER_CLIENT_ID");
    if (!clientSecret) missing.push("X_CLIENT_SECRET or TWITTER_CLIENT_SECRET");
    if (!redirectUri) missing.push("X_REDIRECT_URI or TWITTER_REDIRECT_URI");

    throw new Error(
      `Missing X/Twitter OAuth environment variables: ${missing.join(", ")}. ` +
        `These are required when using X/Twitter OAuth functionality. ` +
        `Visit https://developer.twitter.com/en/portal/dashboard to obtain these values.`
    );
  }

  configCache = {
    clientId,
    clientSecret,
    redirectUri,
  };

  return configCache;
}

// PKCE (Proof Key for Code Exchange) utilities
class PKCEUtils {
  static generateCodeVerifier(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return this.base64URLEncode(array);
  }

  static async generateCodeChallenge(verifier: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);

    // Use Web Crypto API if available, otherwise use Node.js crypto
    if (typeof globalThis.crypto?.subtle !== "undefined") {
      const hash = await crypto.subtle.digest("SHA-256", data);
      return this.base64URLEncode(new Uint8Array(hash));
    } else {
      // Node.js fallback
      const crypto = require("crypto");
      const hash = crypto.createHash("sha256").update(verifier).digest();
      return this.base64URLEncode(hash);
    }
  }

  static base64URLEncode(buffer: Uint8Array | Buffer): string {
    const base64 = btoa(String.fromCharCode(...buffer));
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }

  static generateState(): string {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return this.base64URLEncode(array);
  }
}

// API request helper
async function xApiRequest<T>(
  url: string,
  accessToken: string,
  options: RequestInit = {}
): Promise<T> {
  const response = await fetch(url, {
    ...options,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    let errorMessage = `X API request failed: ${response.status}`;

    try {
      const errorJson = JSON.parse(errorText);
      errorMessage = errorJson.detail || errorJson.error || errorMessage;
    } catch {}

    throw new Error(errorMessage);
  }

  return response.json();
}

// Main OAuth functions
export async function getXOAuthURL(
  options: {
    state?: string;
    scopes?: string[];
    redirectUri?: string;
    prompt?: "none" | "consent";
    accessType?: "online" | "offline";
  } = {}
): Promise<{ url: string; state: string; codeVerifier: string }> {
  const config = getXOAuthConfig();

  // Generate PKCE challenge
  const codeVerifier = PKCEUtils.generateCodeVerifier();
  const codeChallenge = await PKCEUtils.generateCodeChallenge(codeVerifier);
  const state = options.state || PKCEUtils.generateState();

  // Store PKCE challenge (in production, use Redis or similar)
  pkceStorage.set(state, {
    codeVerifier,
    codeChallenge,
    state,
  });

  // Clean up old challenges (older than 10 minutes)
  setTimeout(
    () => {
      pkceStorage.delete(state);
    },
    10 * 60 * 1000
  );

  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: options.redirectUri || config.redirectUri,
    response_type: "code",
    scope: (options.scopes || DEFAULT_SCOPES).join(" "),
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });

  // Add optional parameters
  if (options.prompt) params.set("prompt", options.prompt);
  if (options.accessType === "offline") {
    params.set("access_type", "offline");
  }

  return {
    url: `${X_OAUTH_ENDPOINTS.AUTHORIZE}?${params.toString()}`,
    state,
    codeVerifier,
  };
}

export async function handleXCallback(
  code: string,
  state: string,
  options: {
    codeVerifier?: string;
    redirectUri?: string;
    includeToken?: boolean;
    includeEmail?: boolean;
  } = {}
): Promise<OAuthUser & { token?: string; refreshToken?: string }> {
  const config = getXOAuthConfig();

  try {
    // Get PKCE verifier from storage or options
    let codeVerifier = options.codeVerifier;

    if (!codeVerifier) {
      const pkceData = pkceStorage.get(state);
      if (!pkceData) {
        throw new Error("PKCE challenge not found. Session may have expired.");
      }
      codeVerifier = pkceData.codeVerifier;
      pkceStorage.delete(state); // Clean up after use
    }

    // Exchange code for access token
    const tokenParams = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: config.clientId,
      code,
      redirect_uri: options.redirectUri || config.redirectUri,
      code_verifier: codeVerifier,
    });

    // Add client secret for confidential clients
    const authHeader = btoa(`${config.clientId}:${config.clientSecret}`);

    const tokenResponse = await fetch(X_OAUTH_ENDPOINTS.TOKEN, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${authHeader}`,
      },
      body: tokenParams.toString(),
    });

    if (!tokenResponse.ok) {
      const error = await tokenResponse.text();
      throw new Error(
        `Token exchange failed: ${tokenResponse.status} - ${error}`
      );
    }

    const tokenData: XTokenResponse = await tokenResponse.json();

    if (!tokenData.access_token) {
      throw new Error("No access token received from X");
    }

    // Fetch user data with specified fields
    const userUrl = new URL(X_OAUTH_ENDPOINTS.USER);
    userUrl.searchParams.set("user.fields", USER_FIELDS.join(","));

    const userData = await xApiRequest<XUserResponse>(
      userUrl.toString(),
      tokenData.access_token
    );

    if (!userData.data) {
      throw new Error("No user data received from X");
    }

    const user = userData.data;

    // Build user object
    const oauthUser: OAuthUser = {
      id: user.id,
      username: user.username,
      name: user.name,
      avatar: user.profile_image_url?.replace("_normal", "_400x400"), // Get higher res image
      provider: "x",
      emailVerified: false, // X doesn't provide email
      metadata: {
        description: user.description,
        location: user.location,
        url: user.url,
        verified: user.verified,
        verifiedType: user.verified_type,
        protected: user.protected,
        followersCount: user.public_metrics?.followers_count,
        followingCount: user.public_metrics?.following_count,
        tweetCount: user.public_metrics?.tweet_count,
        likeCount: user.public_metrics?.like_count,
        createdAt: user.created_at,
      },
    };

    // Note: X API v2 doesn't provide email
    // Need to apply for elevated access to get email
    if (options.includeEmail) {
      // This would require additional API permissions
      oauthUser.email = undefined; // Email not available in standard v2 API
      console.warn(
        "Email access requires elevated API permissions from X/Twitter"
      );
    }

    // Include tokens if requested
    if (options.includeToken) {
      return {
        ...oauthUser,
        token: tokenData.access_token,
        refreshToken: tokenData.refresh_token,
      };
    }

    return oauthUser;
  } catch (error) {
    console.error("[X OAuth Error]:", error);

    if (error instanceof Error) {
      if (error.message.includes("fetch")) {
        throw new Error(
          "Network error during X authentication. Please try again."
        );
      }
      if (error.message.includes("401") || error.message.includes("403")) {
        throw new Error("X authentication failed. Please try again.");
      }
      throw new Error(`X authentication failed: ${error.message}`);
    }

    throw new Error("An unexpected error occurred during X authentication.");
  }
}

// Additional utility functions

/**
 * Refresh X OAuth token
 */
export async function refreshXToken(
  refreshToken: string
): Promise<{ accessToken: string; refreshToken?: string }> {
  const config = getXOAuthConfig();

  try {
    const authHeader = btoa(`${config.clientId}:${config.clientSecret}`);

    const response = await fetch(X_OAUTH_ENDPOINTS.TOKEN, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${authHeader}`,
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: config.clientId,
      }).toString(),
    });

    if (!response.ok) {
      throw new Error("Token refresh failed");
    }

    const data: XTokenResponse = await response.json();

    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
    };
  } catch (error) {
    console.error("[X OAuth Refresh Error]:", error);
    throw new Error("Failed to refresh X authentication token");
  }
}

/**
 * Revoke X OAuth token
 */
export async function revokeXToken(
  token: string,
  tokenType: "access_token" | "refresh_token" = "access_token"
): Promise<boolean> {
  const config = getXOAuthConfig();

  try {
    const authHeader = btoa(`${config.clientId}:${config.clientSecret}`);

    const response = await fetch(X_OAUTH_ENDPOINTS.REVOKE, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${authHeader}`,
      },
      body: new URLSearchParams({
        token,
        token_type_hint: tokenType,
        client_id: config.clientId,
      }).toString(),
    });

    return response.ok;
  } catch (error) {
    console.error("[X OAuth Revoke Error]:", error);
    return false;
  }
}

/**
 * Get X user by ID
 */
export async function getXUserById(
  userId: string,
  accessToken: string
): Promise<XUserResponse | null> {
  try {
    const url = new URL(X_OAUTH_ENDPOINTS.USER_BY_ID(userId));
    url.searchParams.set("user.fields", USER_FIELDS.join(","));

    return await xApiRequest<XUserResponse>(url.toString(), accessToken);
  } catch (error) {
    console.error("[X User Fetch Error]:", error);
    return null;
  }
}

/**
 * Validate X access token
 */
export async function validateXToken(token: string): Promise<boolean> {
  try {
    const url = new URL(X_OAUTH_ENDPOINTS.USER);
    url.searchParams.set("user.fields", "id");

    const response = await fetch(url.toString(), {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    return response.ok;
  } catch {
    return false;
  }
}

/**
 * Generate state with custom data
 */
export function generateOAuthState(data?: any): string {
  const randomString = PKCEUtils.generateState();

  if (data) {
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
 * Clean up PKCE storage (for production, this would be in Redis/cache)
 */
export function cleanupPKCEStorage(): void {
  pkceStorage.clear();
}

/**
 * Reset cached configuration (useful for testing)
 */
export function resetXOAuthConfig(): void {
  configCache = null;
}

// Export PKCE utilities for external use
export { PKCEUtils };
