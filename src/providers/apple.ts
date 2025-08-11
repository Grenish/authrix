// Types
interface AppleOAuthConfig {
  clientId: string;
  teamId: string;
  keyId: string;
  privateKey: string;
  redirectUri: string;
}

interface AppleTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token: string;
}

interface AppleIdTokenPayload {
  iss: string;
  aud: string;
  exp: number;
  iat: number;
  sub: string;
  at_hash?: string;
  email?: string;
  email_verified?: string | boolean;
  auth_time?: number;
  nonce_supported?: boolean;
  real_user_status?: number;
}

interface AppleAuthorizationResponse {
  code: string;
  state?: string;
  user?: {
    name?: {
      firstName?: string;
      lastName?: string;
    };
    email?: string;
  };
}

interface AppleOAuthUser {
  id: string;
  email?: string;
  name?: string;
  provider: "apple";
  emailVerified: boolean;
  metadata?: {
    firstName?: string;
    lastName?: string;
    realUserStatus?: number;
  };
}

// Constants
const APPLE_OAUTH_ENDPOINTS = {
  AUTH: "https://appleid.apple.com/auth/authorize",
  TOKEN: "https://appleid.apple.com/auth/token",
  REVOKE: "https://appleid.apple.com/auth/revoke",
} as const;

const DEFAULT_SCOPES = ["name", "email"] as const;

// Configuration cache
let appleConfigCache: AppleOAuthConfig | null = null;
let clientSecretCache: { secret: string; expiresAt: number } | null = null;

// Environment variable loader with caching
function getAppleOAuthConfig(): AppleOAuthConfig {
  // Return cached config if available
  if (appleConfigCache) {
    return appleConfigCache;
  }

  const clientId = process.env.APPLE_CLIENT_ID || process.env.APPLE_SERVICE_ID;
  const teamId = process.env.APPLE_TEAM_ID;
  const keyId = process.env.APPLE_KEY_ID;
  const privateKey = process.env.APPLE_PRIVATE_KEY;
  const redirectUri =
    process.env.APPLE_REDIRECT_URI || process.env.APPLE_OAUTH_REDIRECT_URI;

  if (!clientId || !teamId || !keyId || !privateKey || !redirectUri) {
    const missing = [];
    if (!clientId) missing.push("APPLE_CLIENT_ID");
    if (!teamId) missing.push("APPLE_TEAM_ID");
    if (!keyId) missing.push("APPLE_KEY_ID");
    if (!privateKey) missing.push("APPLE_PRIVATE_KEY");
    if (!redirectUri) missing.push("APPLE_REDIRECT_URI");

    throw new Error(
      `Missing Apple OAuth environment variables: ${missing.join(", ")}. ` +
        `These are required when using Apple OAuth functionality. ` +
        `Visit https://developer.apple.com/account/resources to configure Sign in with Apple.`
    );
  }

  // Cache the configuration
  appleConfigCache = {
    clientId,
    teamId,
    keyId,
    privateKey: privateKey.replace(/\\n/g, "\n"), // Handle escaped newlines
    redirectUri,
  };

  return appleConfigCache;
}

// Generate client secret (JWT) for Apple
function generateAppleClientSecret(): string {
  const config = getAppleOAuthConfig();

  // Check if we have a valid cached secret
  if (clientSecretCache && clientSecretCache.expiresAt > Date.now()) {
    return clientSecretCache.secret;
  }

  const now = Math.floor(Date.now() / 1000);
  const expiresIn = 3600 * 24 * 180; // 180 days (maximum allowed by Apple)
  const expiresAt = now + expiresIn;

  // Create JWT header
  const header = {
    alg: "ES256",
    kid: config.keyId,
    typ: "JWT",
  };

  // Create JWT payload
  const payload = {
    iss: config.teamId,
    iat: now,
    exp: expiresAt,
    aud: "https://appleid.apple.com",
    sub: config.clientId,
  };

  // Base64URL encode
  const base64URLEncode = (str: string): string => {
    return Buffer.from(str)
      .toString("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
  };

  const headerEncoded = base64URLEncode(JSON.stringify(header));
  const payloadEncoded = base64URLEncode(JSON.stringify(payload));
  const message = `${headerEncoded}.${payloadEncoded}`;

  // Sign with ES256 (simplified - in production, use a proper crypto library)
  // This is a placeholder - you'll need to implement proper ES256 signing
  // Consider using libraries like 'jsonwebtoken' or 'jose'
  const signature = base64URLEncode(
    createES256Signature(message, config.privateKey)
  );

  const clientSecret = `${message}.${signature}`;

  // Cache the secret
  clientSecretCache = {
    secret: clientSecret,
    expiresAt: (expiresAt - 60) * 1000, // Expire 1 minute before actual expiry
  };

  return clientSecret;
}

// ES256 signature creation (placeholder - implement with proper crypto)
function createES256Signature(message: string, privateKey: string): string {
  // This is a simplified placeholder
  // In production, use crypto.sign with ES256 algorithm
  // Example with Node.js crypto:
  /*
  const crypto = require('crypto');
  const sign = crypto.createSign('SHA256');
  sign.update(message);
  sign.end();
  return sign.sign(privateKey);
  */

  // For now, return a placeholder
  // You must implement proper ES256 signing for production
  return "signature_placeholder";
}

// JWT decoder for id_token (basic, no crypto validation)
function decodeAppleJWT(token: string): any {
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
export function getAppleOAuthURL(
  options: {
    state?: string;
    scopes?: string[];
    responseMode?: "query" | "fragment" | "form_post" | "web_message";
    nonce?: string;
    redirectUri?: string;
  } = {}
): string {
  const config = getAppleOAuthConfig();

  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: options.redirectUri || config.redirectUri,
    response_type: "code id_token",
    response_mode: options.responseMode || "form_post",
    scope: (options.scopes || DEFAULT_SCOPES).join(" "),
  });

  // Add optional parameters
  if (options.state) params.set("state", options.state);
  if (options.nonce) params.set("nonce", options.nonce);

  return `${APPLE_OAUTH_ENDPOINTS.AUTH}?${params.toString()}`;
}

export async function handleAppleCallback(
  code: string,
  options: {
    user?:
      | string
      | { name?: { firstName?: string; lastName?: string }; email?: string };
    state?: string;
    skipEmailVerification?: boolean;
    redirectUri?: string;
    includeTokens?: boolean;
  } = {}
): Promise<
  AppleOAuthUser & {
    tokens?: { access: string; refresh?: string; idToken: string };
  }
> {
  const config = getAppleOAuthConfig();

  try {
    // Generate client secret
    const clientSecret = generateAppleClientSecret();

    // Exchange code for tokens
    const tokenResponse = await fetch(APPLE_OAUTH_ENDPOINTS.TOKEN, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: new URLSearchParams({
        client_id: config.clientId,
        client_secret: clientSecret,
        code,
        grant_type: "authorization_code",
        redirect_uri: options.redirectUri || config.redirectUri,
      }).toString(),
    });

    if (!tokenResponse.ok) {
      const error = await tokenResponse.text();
      throw new Error(
        `Token exchange failed: ${tokenResponse.status} - ${error}`
      );
    }

    const tokenData: AppleTokenResponse = await tokenResponse.json();

    if (!tokenData.id_token) {
      throw new Error("No ID token received from Apple");
    }

    // Decode and validate ID token
    const decodedToken = decodeAppleJWT(
      tokenData.id_token
    ) as AppleIdTokenPayload;
    if (!decodedToken) {
      throw new Error("Failed to decode ID token");
    }

    // Validate token claims
    if (decodedToken.aud !== config.clientId) {
      throw new Error("Token audience mismatch");
    }

    if (decodedToken.iss !== "https://appleid.apple.com") {
      throw new Error("Invalid token issuer");
    }

    // Check token expiration
    const now = Math.floor(Date.now() / 1000);
    if (decodedToken.exp < now) {
      throw new Error("ID token has expired");
    }

    // Parse user data (Apple only sends this on first authorization)
    let userData: { firstName?: string; lastName?: string; email?: string } =
      {};

    if (options.user) {
      if (typeof options.user === "string") {
        // User data was sent as JSON string (form_post mode)
        try {
          const parsed = JSON.parse(options.user);
          userData = {
            firstName: parsed.name?.firstName,
            lastName: parsed.name?.lastName,
            email: parsed.email,
          };
        } catch {
          // Invalid JSON, ignore
        }
      } else if (typeof options.user === "object") {
        // User data was sent as object
        userData = {
          firstName: options.user.name?.firstName,
          lastName: options.user.name?.lastName,
          email: options.user.email,
        };
      }
    }

    // Get email from ID token or user data
    const email = decodedToken.email || userData.email;
    const emailVerified =
      decodedToken.email_verified === "true" ||
      decodedToken.email_verified === true;

    // Validate email verification if required
    if (!options.skipEmailVerification && email && !emailVerified) {
      throw new Error("Email address is not verified");
    }

    // Build user object
    const user: AppleOAuthUser = {
      id: decodedToken.sub,
      email: email,
      name:
        userData.firstName && userData.lastName
          ? `${userData.firstName} ${userData.lastName}`.trim()
          : userData.firstName || userData.lastName || undefined,
      provider: "apple",
      emailVerified: emailVerified,
      metadata: {
        firstName: userData.firstName,
        lastName: userData.lastName,
        realUserStatus: decodedToken.real_user_status,
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
    console.error("[Apple OAuth Error]:", error);

    if (error instanceof Error) {
      // Check for common errors and provide helpful messages
      if (error.message.includes("fetch")) {
        throw new Error(
          "Network error during Apple authentication. Please try again."
        );
      }
      if (
        error.message.includes("audience") ||
        error.message.includes("issuer")
      ) {
        throw new Error("Security validation failed. Please try again.");
      }
      throw new Error(`Apple authentication failed: ${error.message}`);
    }

    throw new Error(
      "An unexpected error occurred during Apple authentication."
    );
  }
}

// Additional utility functions

/**
 * Revoke Apple OAuth tokens
 */
export async function revokeAppleTokens(
  token: string,
  tokenType: "access_token" | "refresh_token" = "access_token"
): Promise<boolean> {
  try {
    const config = getAppleOAuthConfig();
    const clientSecret = generateAppleClientSecret();

    const response = await fetch(APPLE_OAUTH_ENDPOINTS.REVOKE, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        client_id: config.clientId,
        client_secret: clientSecret,
        token,
        token_type_hint: tokenType,
      }).toString(),
    });

    return response.ok;
  } catch (error) {
    console.error("[Apple OAuth Revoke Error]:", error);
    return false;
  }
}

/**
 * Refresh Apple access token
 */
export async function refreshAppleAccessToken(
  refreshToken: string
): Promise<AppleTokenResponse | null> {
  try {
    const config = getAppleOAuthConfig();
    const clientSecret = generateAppleClientSecret();

    const response = await fetch(APPLE_OAUTH_ENDPOINTS.TOKEN, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: new URLSearchParams({
        client_id: config.clientId,
        client_secret: clientSecret,
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      }).toString(),
    });

    if (!response.ok) {
      return null;
    }

    return await response.json();
  } catch {
    return null;
  }
}

/**
 * Validate Apple ID token
 */
export async function validateAppleIdToken(
  idToken: string
): Promise<AppleIdTokenPayload | null> {
  try {
    const decodedToken = decodeAppleJWT(idToken) as AppleIdTokenPayload;
    if (!decodedToken) {
      return null;
    }

    const config = getAppleOAuthConfig();

    // Validate audience
    if (decodedToken.aud !== config.clientId) {
      return null;
    }

    // Validate issuer
    if (decodedToken.iss !== "https://appleid.apple.com") {
      return null;
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (decodedToken.exp < now) {
      return null;
    }

    return decodedToken;
  } catch {
    return null;
  }
}

/**
 * Generate a secure state parameter for CSRF protection
 */
export function generateAppleOAuthState(data?: any): string {
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
 * Parse Apple OAuth state parameter
 */
export function parseAppleOAuthState(state: string): {
  token: string;
  data?: any;
} {
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
 * Generate nonce for Apple OAuth
 */
export function generateAppleNonce(): string {
  const randomBytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(randomBytes, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

/**
 * Reset cached configuration (useful for testing)
 */
export function resetAppleOAuthConfig(): void {
  appleConfigCache = null;
  clientSecretCache = null;
}

// Helper to properly implement ES256 signing using Web Crypto API or Node crypto
export async function signWithES256(
  message: string,
  privateKey: string
): Promise<string> {
  // For Node.js environment
  if (typeof globalThis.crypto === "undefined") {
    const crypto = await import("crypto");
    const sign = crypto.createSign("SHA256");
    sign.update(message);
    sign.end();
    const signature = sign.sign({
      key: privateKey,
      format: "pem",
      type: "pkcs8",
    });
    return signature
      .toString("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
  }

  // For browser environment (Web Crypto API)
  // Note: This is more complex and requires converting the PEM key to CryptoKey
  // Implementation would depend on your runtime environment
  throw new Error(
    "Web Crypto API implementation for ES256 signing not provided"
  );
}
