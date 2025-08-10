import * as jwt from "jsonwebtoken";
import { JWK, JWS } from "node-jose";

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
  refresh_token: string;
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
  is_private_email?: boolean;
  auth_time?: number;
  nonce_supported?: boolean;
  real_user_status?: number;
}

interface AppleUserInfo {
  name?: {
    firstName?: string;
    lastName?: string;
  };
  email?: string;
}

interface ApplePublicKey {
  kty: string;
  kid: string;
  use: string;
  alg: string;
  n: string;
  e: string;
}

interface OAuthUser {
  id: string;
  email?: string;
  name?: string;
  provider: "apple";
  emailVerified: boolean;
  isPrivateEmail: boolean;
  metadata?: {
    firstName?: string;
    lastName?: string;
    realUserStatus?: "likely_real" | "unknown" | "suspicious";
    authTime?: number;
  };
}

// Constants
const APPLE_OAUTH_ENDPOINTS = {
  AUTHORIZE: "https://appleid.apple.com/auth/authorize",
  TOKEN: "https://appleid.apple.com/auth/token",
  KEYS: "https://appleid.apple.com/auth/keys",
  REVOKE: "https://appleid.apple.com/auth/revoke",
} as const;

const DEFAULT_SCOPES = ["email", "name"] as const;

// Cache for Apple's public keys
let publicKeysCache: {
  keys: ApplePublicKey[];
  timestamp: number;
} | null = null;

const PUBLIC_KEYS_CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours

// Configuration cache
let configCache: AppleOAuthConfig | null = null;

// Environment variable loader with caching
function getAppleOAuthConfig(): AppleOAuthConfig {
  if (configCache) {
    return configCache;
  }

  const clientId = process.env.APPLE_CLIENT_ID || process.env.APPLE_SERVICE_ID;
  const teamId = process.env.APPLE_TEAM_ID;
  const keyId = process.env.APPLE_KEY_ID;
  const privateKey = process.env.APPLE_PRIVATE_KEY;
  const redirectUri = process.env.APPLE_REDIRECT_URI;

  if (!clientId || !teamId || !keyId || !privateKey || !redirectUri) {
    const missing = [];
    if (!clientId) missing.push("APPLE_CLIENT_ID or APPLE_SERVICE_ID");
    if (!teamId) missing.push("APPLE_TEAM_ID");
    if (!keyId) missing.push("APPLE_KEY_ID");
    if (!privateKey) missing.push("APPLE_PRIVATE_KEY");
    if (!redirectUri) missing.push("APPLE_REDIRECT_URI");

    throw new Error(
      `Missing Apple Sign In environment variables: ${missing.join(", ")}. ` +
        `These are required when using Apple Sign In functionality. ` +
        `Visit https://developer.apple.com/account/resources/identifiers/list/serviceId to configure.`
    );
  }

  // Process private key (handle both inline and multiline formats)
  const processedPrivateKey = privateKey.replace(/\\n/g, "\n").trim();

  // Ensure proper PEM format
  const formattedPrivateKey = processedPrivateKey.includes("BEGIN PRIVATE KEY")
    ? processedPrivateKey
    : `-----BEGIN PRIVATE KEY-----\n${processedPrivateKey}\n-----END PRIVATE KEY-----`;

  configCache = {
    clientId,
    teamId,
    keyId,
    privateKey: formattedPrivateKey,
    redirectUri,
  };

  return configCache;
}

// Generate client secret for Apple Sign In
async function generateClientSecret(
  config?: Partial<AppleOAuthConfig>,
  expiresIn: string = "6m"
): Promise<string> {
  const oauthConfig = config
    ? { ...getAppleOAuthConfig(), ...config }
    : getAppleOAuthConfig();

  const now = Math.floor(Date.now() / 1000);

  const claims = {
    iss: oauthConfig.teamId,
    iat: now,
    exp: now + 6 * 30 * 24 * 60 * 60, // 6 months max
    aud: "https://appleid.apple.com",
    sub: oauthConfig.clientId,
  };

  try {
    return jwt.sign(claims, oauthConfig.privateKey, {
      algorithm: "ES256",
      keyid: oauthConfig.keyId,
    });
  } catch (error) {
    throw new Error(
      `Failed to generate Apple client secret: ${error instanceof Error ? error.message : "Unknown error"}`
    );
  }
}

// Fetch and cache Apple's public keys
async function getApplePublicKeys(): Promise<ApplePublicKey[]> {
  const now = Date.now();

  // Return cached keys if still valid
  if (
    publicKeysCache &&
    now - publicKeysCache.timestamp < PUBLIC_KEYS_CACHE_DURATION
  ) {
    return publicKeysCache.keys;
  }

  try {
    const response = await fetch(APPLE_OAUTH_ENDPOINTS.KEYS);

    if (!response.ok) {
      throw new Error(`Failed to fetch Apple public keys: ${response.status}`);
    }

    const data = await response.json();

    publicKeysCache = {
      keys: data.keys,
      timestamp: now,
    };

    return data.keys;
  } catch (error) {
    // If we have cached keys and fetch fails, return cached keys
    if (publicKeysCache) {
      return publicKeysCache.keys;
    }
    throw error;
  }
}

// Verify Apple ID token
async function verifyAppleIdToken(
  idToken: string,
  clientId?: string
): Promise<AppleIdTokenPayload> {
  const config = getAppleOAuthConfig();
  const audience = clientId || config.clientId;

  // Decode token header to get key ID
  const decoded = jwt.decode(idToken, { complete: true });
  if (!decoded || typeof decoded === "string") {
    throw new Error("Invalid ID token format");
  }

  const { kid, alg } = decoded.header;
  if (!kid || alg !== "RS256") {
    throw new Error("Invalid token header");
  }

  // Get Apple's public keys
  const publicKeys = await getApplePublicKeys();
  const publicKey = publicKeys.find((key) => key.kid === kid);

  if (!publicKey) {
    throw new Error("Public key not found for token");
  }

  // Convert JWK to PEM format for verification
  const keyStore = await JWK.asKeyStore({ keys: [publicKey] });
  const key = keyStore.get(kid);

  if (!key) {
    throw new Error("Failed to load public key");
  }

  // Verify the token
  try {
    const verifier = JWS.createVerify(key);
    const result = await verifier.verify(idToken);
    const payload = JSON.parse(result.payload.toString());

    // Validate claims
    if (payload.iss !== "https://appleid.apple.com") {
      throw new Error("Invalid token issuer");
    }

    if (payload.aud !== audience) {
      throw new Error("Invalid token audience");
    }

    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) {
      throw new Error("Token has expired");
    }

    return payload as AppleIdTokenPayload;
  } catch (error) {
    throw new Error(
      `Token verification failed: ${error instanceof Error ? error.message : "Unknown error"}`
    );
  }
}

// Main OAuth functions
export function getAppleOAuthURL(
  options: {
    state?: string;
    scopes?: string[];
    redirectUri?: string;
    responseMode?: "query" | "fragment" | "form_post";
    nonce?: string;
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

  return `${APPLE_OAUTH_ENDPOINTS.AUTHORIZE}?${params.toString()}`;
}

export async function handleAppleCallback(
  code: string,
  options: {
    idToken?: string;
    user?: string; // Apple sends user info only on first authorization
    state?: string;
    redirectUri?: string;
    includeTokens?: boolean;
    clientSecret?: string;
  } = {}
): Promise<
  OAuthUser & { tokens?: { access: string; refresh: string; idToken: string } }
> {
  const config = getAppleOAuthConfig();

  try {
    // Generate client secret if not provided
    const clientSecret = options.clientSecret || (await generateClientSecret());

    // Exchange code for tokens
    const tokenParams = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: options.redirectUri || config.redirectUri,
      client_id: config.clientId,
      client_secret: clientSecret,
    });

    const tokenResponse = await fetch(APPLE_OAUTH_ENDPOINTS.TOKEN, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: tokenParams.toString(),
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

    // Verify and decode ID token
    const idTokenPayload = await verifyAppleIdToken(tokenData.id_token);

    // Parse user info if provided (only sent on first authorization)
    let userInfo: AppleUserInfo = {};
    if (options.user) {
      try {
        userInfo = JSON.parse(options.user);
      } catch {
        // Invalid user data, ignore
      }
    }

    // Determine real user status
    let realUserStatus: "likely_real" | "unknown" | "suspicious" = "unknown";
    if (idTokenPayload.real_user_status !== undefined) {
      switch (idTokenPayload.real_user_status) {
        case 2:
          realUserStatus = "likely_real";
          break;
        case 1:
          realUserStatus = "unknown";
          break;
        case 0:
          realUserStatus = "suspicious";
          break;
      }
    }

    // Build user object
    const user: OAuthUser = {
      id: idTokenPayload.sub,
      email: idTokenPayload.email || userInfo.email,
      name: userInfo.name
        ? `${userInfo.name.firstName || ""} ${userInfo.name.lastName || ""}`.trim()
        : undefined,
      provider: "apple",
      emailVerified:
        idTokenPayload.email_verified === "true" ||
        idTokenPayload.email_verified === true,
      isPrivateEmail: idTokenPayload.is_private_email || false,
      metadata: {
        firstName: userInfo.name?.firstName,
        lastName: userInfo.name?.lastName,
        realUserStatus,
        authTime: idTokenPayload.auth_time,
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
    console.error("[Apple OAuth Error]:", error);

    if (error instanceof Error) {
      if (error.message.includes("fetch")) {
        throw new Error(
          "Network error during Apple authentication. Please try again."
        );
      }
      if (error.message.includes("verification")) {
        throw new Error(
          "Apple ID token verification failed. Please try again."
        );
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
 * Refresh Apple OAuth token
 */
export async function refreshAppleToken(
  refreshToken: string,
  clientSecret?: string
): Promise<{ accessToken: string; idToken?: string }> {
  const config = getAppleOAuthConfig();

  try {
    const secret = clientSecret || (await generateClientSecret());

    const response = await fetch(APPLE_OAUTH_ENDPOINTS.TOKEN, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: config.clientId,
        client_secret: secret,
      }).toString(),
    });

    if (!response.ok) {
      throw new Error("Token refresh failed");
    }

    const data: AppleTokenResponse = await response.json();

    return {
      accessToken: data.access_token,
      idToken: data.id_token,
    };
  } catch (error) {
    console.error("[Apple OAuth Refresh Error]:", error);
    throw new Error("Failed to refresh Apple authentication token");
  }
}

/**
 * Revoke Apple OAuth token
 */
export async function revokeAppleToken(
  token: string,
  tokenType: "access_token" | "refresh_token" = "refresh_token",
  clientSecret?: string
): Promise<boolean> {
  const config = getAppleOAuthConfig();

  try {
    const secret = clientSecret || (await generateClientSecret());

    const response = await fetch(APPLE_OAUTH_ENDPOINTS.REVOKE, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        token,
        token_type_hint: tokenType,
        client_id: config.clientId,
        client_secret: secret,
      }).toString(),
    });

    return response.ok;
  } catch (error) {
    console.error("[Apple OAuth Revoke Error]:", error);
    return false;
  }
}

/**
 * Validate Apple refresh token
 */
export async function validateAppleRefreshToken(
  refreshToken: string,
  clientSecret?: string
): Promise<boolean> {
  try {
    const result = await refreshAppleToken(refreshToken, clientSecret);
    return !!result.accessToken;
  } catch {
    return false;
  }
}

/**
 * Generate nonce for enhanced security
 */
export function generateNonce(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join(
    ""
  );
}

/**
 * Generate state parameter with custom data
 */
export function generateOAuthState(data?: any): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  const randomString = Array.from(array, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");

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
 * Handle form_post response mode (for server-side handling)
 */
export function parseAppleFormPost(body: Record<string, any>): {
  code?: string;
  idToken?: string;
  user?: any;
  state?: string;
  error?: string;
} {
  const { code, id_token, user, state, error, error_description } = body;

  if (error) {
    throw new Error(`Apple Sign In error: ${error_description || error}`);
  }

  return {
    code,
    idToken: id_token,
    user: user ? JSON.parse(user) : undefined,
    state,
  };
}

/**
 * Reset cached configuration (useful for testing)
 */
export function resetAppleOAuthConfig(): void {
  configCache = null;
  publicKeysCache = null;
}

/**
 * Generate client secret with custom expiration
 */
export async function generateAppleClientSecret(
  expiresInSeconds: number = 15777000 // 6 months
): Promise<{ secret: string; expiresAt: Date }> {
  const secret = await generateClientSecret(undefined, `${expiresInSeconds}s`);
  const expiresAt = new Date(Date.now() + expiresInSeconds * 1000);

  return { secret, expiresAt };
}
