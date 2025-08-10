// Types
interface FacebookOAuthConfig {
  appId: string;
  appSecret: string;
  redirectUri: string;
  apiVersion?: string;
}

interface FacebookTokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
}

interface FacebookLongLivedTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

interface FacebookUser {
  id: string;
  name?: string;
  first_name?: string;
  last_name?: string;
  middle_name?: string;
  email?: string;
  picture?: {
    data: {
      height: number;
      is_silhouette: boolean;
      url: string;
      width: number;
    };
  };
  birthday?: string;
  gender?: string;
  location?: {
    id: string;
    name: string;
  };
  hometown?: {
    id: string;
    name: string;
  };
  languages?: Array<{
    id: string;
    name: string;
  }>;
  link?: string;
  locale?: string;
  timezone?: number;
  updated_time?: string;
  verified?: boolean;
  age_range?: {
    min?: number;
    max?: number;
  };
}

interface FacebookTokenDebugInfo {
  data: {
    app_id: string;
    type: string;
    application: string;
    data_access_expires_at: number;
    expires_at: number;
    is_valid: boolean;
    scopes: string[];
    user_id: string;
    metadata?: {
      auth_type?: string;
      sso?: string;
    };
  };
}

interface FacebookPermissions {
  data: Array<{
    permission: string;
    status: "granted" | "declined" | "expired";
  }>;
}

interface OAuthUser {
  id: string;
  email?: string;
  username?: string;
  name?: string;
  avatar?: string;
  provider: "facebook";
  emailVerified: boolean;
  metadata?: {
    firstName?: string;
    lastName?: string;
    middleName?: string;
    birthday?: string;
    gender?: string;
    location?: string;
    hometown?: string;
    languages?: string[];
    profileLink?: string;
    locale?: string;
    timezone?: number;
    ageRange?: {
      min?: number;
      max?: number;
    };
    updatedAt?: string;
    permissions?: string[];
  };
}

// Constants
const FACEBOOK_API_VERSION = "v18.0";
const FACEBOOK_GRAPH_API = "https://graph.facebook.com";
const FACEBOOK_OAUTH_ENDPOINTS = {
  AUTHORIZE: "https://www.facebook.com/v18.0/dialog/oauth",
  TOKEN: `${FACEBOOK_GRAPH_API}/v18.0/oauth/access_token`,
  DEBUG_TOKEN: `${FACEBOOK_GRAPH_API}/debug_token`,
  ME: `${FACEBOOK_GRAPH_API}/v18.0/me`,
  PERMISSIONS: `${FACEBOOK_GRAPH_API}/v18.0/me/permissions`,
  DEAUTHORIZE: `${FACEBOOK_GRAPH_API}/v18.0/me/permissions`,
} as const;

const DEFAULT_SCOPES = ["email", "public_profile"] as const;

const USER_FIELDS = [
  "id",
  "name",
  "first_name",
  "last_name",
  "middle_name",
  "email",
  "picture.width(400).height(400)",
  "birthday",
  "gender",
  "location",
  "hometown",
  "languages",
  "link",
  "locale",
  "timezone",
  "updated_time",
  "verified",
  "age_range",
] as const;

// Configuration cache
let configCache: FacebookOAuthConfig | null = null;

// Environment variable loader with caching
function getFacebookOAuthConfig(): FacebookOAuthConfig {
  if (configCache) {
    return configCache;
  }

  const appId = process.env.FACEBOOK_APP_ID || process.env.FB_APP_ID;
  const appSecret =
    process.env.FACEBOOK_APP_SECRET || process.env.FB_APP_SECRET;
  const redirectUri =
    process.env.FACEBOOK_REDIRECT_URI || process.env.FB_REDIRECT_URI;
  const apiVersion = process.env.FACEBOOK_API_VERSION || FACEBOOK_API_VERSION;

  if (!appId || !appSecret || !redirectUri) {
    const missing = [];
    if (!appId) missing.push("FACEBOOK_APP_ID or FB_APP_ID");
    if (!appSecret) missing.push("FACEBOOK_APP_SECRET or FB_APP_SECRET");
    if (!redirectUri) missing.push("FACEBOOK_REDIRECT_URI or FB_REDIRECT_URI");

    throw new Error(
      `Missing Facebook OAuth environment variables: ${missing.join(", ")}. ` +
        `These are required when using Facebook OAuth functionality. ` +
        `Visit https://developers.facebook.com/apps to create an app and obtain these values.`
    );
  }

  configCache = {
    appId,
    appSecret,
    redirectUri,
    apiVersion,
  };

  return configCache;
}

// API request helper
async function facebookApiRequest<T>(
  url: string,
  accessToken: string,
  options: RequestInit = {}
): Promise<T> {
  const urlWithToken = new URL(url);
  urlWithToken.searchParams.set("access_token", accessToken);

  const response = await fetch(urlWithToken.toString(), {
    ...options,
    headers: {
      Accept: "application/json",
      ...options.headers,
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    let errorMessage = `Facebook API request failed: ${response.status}`;

    try {
      const errorJson = JSON.parse(errorText);
      errorMessage =
        errorJson.error?.message || errorJson.error_description || errorMessage;

      // Handle specific Facebook errors
      if (errorJson.error?.code === 190) {
        throw new Error("Invalid or expired access token");
      }
      if (errorJson.error?.code === 200) {
        throw new Error("Permission denied");
      }
    } catch (e) {
      if (e instanceof Error && e.message.includes("token")) {
        throw e;
      }
    }

    throw new Error(errorMessage);
  }

  return response.json();
}

// Helper functions
function generateProofKey(accessToken: string, appSecret: string): string {
  const crypto = require("crypto");
  const hmac = crypto.createHmac("sha256", appSecret);
  hmac.update(accessToken);
  return hmac.digest("hex");
}

// Main OAuth functions
export function getFacebookOAuthURL(
  options: {
    state?: string;
    scopes?: string[];
    redirectUri?: string;
    display?: "page" | "popup" | "touch";
    authType?: "rerequest" | "reauthenticate";
    responseType?: "code" | "token" | "code token";
  } = {}
): string {
  const config = getFacebookOAuthConfig();

  const params = new URLSearchParams({
    client_id: config.appId,
    redirect_uri: options.redirectUri || config.redirectUri,
    response_type: options.responseType || "code",
    scope: (options.scopes || DEFAULT_SCOPES).join(","),
  });

  // Add optional parameters
  if (options.state) params.set("state", options.state);
  if (options.display) params.set("display", options.display);
  if (options.authType) params.set("auth_type", options.authType);

  const baseUrl = FACEBOOK_OAUTH_ENDPOINTS.AUTHORIZE.replace(
    "v18.0",
    config.apiVersion || "v18.0"
  );
  return `${baseUrl}?${params.toString()}`;
}

export async function handleFacebookCallback(
  code: string,
  options: {
    state?: string;
    redirectUri?: string;
    includeTokens?: boolean;
    fetchPermissions?: boolean;
    exchangeForLongLived?: boolean;
  } = {}
): Promise<
  OAuthUser & {
    tokens?: {
      access: string;
      expiresIn?: number;
      type: string;
      scopes?: string[];
    };
  }
> {
  const config = getFacebookOAuthConfig();

  try {
    // Exchange code for access token
    const tokenUrl = new URL(
      FACEBOOK_OAUTH_ENDPOINTS.TOKEN.replace(
        "v18.0",
        config.apiVersion || "v18.0"
      )
    );
    tokenUrl.searchParams.set("client_id", config.appId);
    tokenUrl.searchParams.set("client_secret", config.appSecret);
    tokenUrl.searchParams.set("code", code);
    tokenUrl.searchParams.set(
      "redirect_uri",
      options.redirectUri || config.redirectUri
    );

    const tokenResponse = await fetch(tokenUrl.toString());

    if (!tokenResponse.ok) {
      const error = await tokenResponse.text();
      throw new Error(
        `Token exchange failed: ${tokenResponse.status} - ${error}`
      );
    }

    const tokenData: FacebookTokenResponse = await tokenResponse.json();

    if (!tokenData.access_token) {
      throw new Error("No access token received from Facebook");
    }

    let finalToken = tokenData.access_token;
    let expiresIn = tokenData.expires_in;

    // Exchange for long-lived token if requested
    if (options.exchangeForLongLived) {
      try {
        const longLivedToken = await exchangeForLongLivedToken(
          tokenData.access_token
        );
        finalToken = longLivedToken.access_token;
        expiresIn = longLivedToken.expires_in;
      } catch (error) {
        console.error("[Facebook Long-Lived Token Error]:", error);
        // Continue with short-lived token
      }
    }

    // Fetch user data with specified fields
    const userUrl = new URL(
      FACEBOOK_OAUTH_ENDPOINTS.ME.replace("v18.0", config.apiVersion || "v18.0")
    );
    userUrl.searchParams.set("fields", USER_FIELDS.join(","));

    const userData = await facebookApiRequest<FacebookUser>(
      userUrl.toString(),
      finalToken
    );

    // Build user object
    const user: OAuthUser = {
      id: userData.id,
      email: userData.email,
      username: undefined, // Facebook doesn't provide usernames anymore
      name: userData.name,
      avatar: userData.picture?.data?.url,
      provider: "facebook",
      emailVerified: userData.verified || false,
      metadata: {
        firstName: userData.first_name,
        lastName: userData.last_name,
        middleName: userData.middle_name,
        birthday: userData.birthday,
        gender: userData.gender,
        location: userData.location?.name,
        hometown: userData.hometown?.name,
        languages: userData.languages?.map((lang) => lang.name),
        profileLink: userData.link,
        locale: userData.locale,
        timezone: userData.timezone,
        ageRange: userData.age_range,
        updatedAt: userData.updated_time,
      },
    };

    // Fetch permissions if requested
    if (options.fetchPermissions) {
      try {
        const permissions = await getUserPermissions(finalToken);
        user.metadata!.permissions = permissions;
      } catch (error) {
        console.error("[Facebook Permissions Fetch Error]:", error);
      }
    }

    // Include tokens if requested
    if (options.includeTokens) {
      // Debug token to get scopes
      let scopes: string[] = [];
      try {
        const debugInfo = await debugToken(finalToken);
        scopes = debugInfo.data.scopes;
      } catch {}

      return {
        ...user,
        tokens: {
          access: finalToken,
          expiresIn,
          type: tokenData.token_type,
          scopes,
        },
      };
    }

    return user;
  } catch (error) {
    console.error("[Facebook OAuth Error]:", error);

    if (error instanceof Error) {
      if (error.message.includes("fetch")) {
        throw new Error(
          "Network error during Facebook authentication. Please try again."
        );
      }
      if (error.message.includes("token")) {
        throw new Error("Facebook authentication failed. Please try again.");
      }
      throw new Error(`Facebook authentication failed: ${error.message}`);
    }

    throw new Error(
      "An unexpected error occurred during Facebook authentication."
    );
  }
}

// Additional utility functions

/**
 * Exchange short-lived token for long-lived token
 */
export async function exchangeForLongLivedToken(
  shortLivedToken: string
): Promise<FacebookLongLivedTokenResponse> {
  const config = getFacebookOAuthConfig();

  const url = new URL(`${FACEBOOK_GRAPH_API}/oauth/access_token`);
  url.searchParams.set("grant_type", "fb_exchange_token");
  url.searchParams.set("client_id", config.appId);
  url.searchParams.set("client_secret", config.appSecret);
  url.searchParams.set("fb_exchange_token", shortLivedToken);

  const response = await fetch(url.toString());

  if (!response.ok) {
    throw new Error("Failed to exchange for long-lived token");
  }

  return response.json();
}

/**
 * Debug and validate Facebook access token
 */
export async function debugToken(
  token: string,
  appAccessToken?: string
): Promise<FacebookTokenDebugInfo> {
  const config = getFacebookOAuthConfig();
  const accessToken = appAccessToken || `${config.appId}|${config.appSecret}`;

  const url = new URL(FACEBOOK_OAUTH_ENDPOINTS.DEBUG_TOKEN);
  url.searchParams.set("input_token", token);
  url.searchParams.set("access_token", accessToken);

  const response = await fetch(url.toString());

  if (!response.ok) {
    throw new Error("Failed to debug token");
  }

  return response.json();
}

/**
 * Get user's granted permissions
 */
export async function getUserPermissions(
  accessToken: string
): Promise<string[]> {
  const config = getFacebookOAuthConfig();

  try {
    const permissions = await facebookApiRequest<FacebookPermissions>(
      FACEBOOK_OAUTH_ENDPOINTS.PERMISSIONS.replace(
        "v18.0",
        config.apiVersion || "v18.0"
      ),
      accessToken
    );

    return permissions.data
      .filter((perm) => perm.status === "granted")
      .map((perm) => perm.permission);
  } catch (error) {
    console.error("[Facebook Permissions Error]:", error);
    return [];
  }
}

/**
 * Revoke specific permission or all permissions
 */
export async function revokeFacebookPermission(
  accessToken: string,
  permission?: string
): Promise<boolean> {
  const config = getFacebookOAuthConfig();

  try {
    let url = FACEBOOK_OAUTH_ENDPOINTS.DEAUTHORIZE.replace(
      "v18.0",
      config.apiVersion || "v18.0"
    );
    if (permission) {
      url += `/${permission}`;
    }

    const urlWithToken = new URL(url);
    urlWithToken.searchParams.set("access_token", accessToken);

    const response = await fetch(urlWithToken.toString(), {
      method: "DELETE",
    });

    return response.ok;
  } catch (error) {
    console.error("[Facebook Revoke Error]:", error);
    return false;
  }
}

/**
 * Get Facebook user by ID
 */
export async function getFacebookUserById(
  userId: string,
  accessToken: string,
  fields?: string[]
): Promise<FacebookUser | null> {
  const config = getFacebookOAuthConfig();

  try {
    const url = new URL(
      `${FACEBOOK_GRAPH_API}/${config.apiVersion || "v18.0"}/${userId}`
    );
    url.searchParams.set("fields", (fields || USER_FIELDS).join(","));

    return await facebookApiRequest<FacebookUser>(url.toString(), accessToken);
  } catch (error) {
    console.error("[Facebook User Fetch Error]:", error);
    return null;
  }
}

/**
 * Validate Facebook access token
 */
export async function validateFacebookToken(token: string): Promise<boolean> {
  try {
    const debugInfo = await debugToken(token);
    return debugInfo.data.is_valid;
  } catch {
    return false;
  }
}

/**
 * Get app access token (for server-to-server calls)
 */
export function getAppAccessToken(): string {
  const config = getFacebookOAuthConfig();
  return `${config.appId}|${config.appSecret}`;
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
 * Delete user data (GDPR compliance)
 */
export async function deleteFacebookUserData(
  userId: string,
  confirmationCode?: string
): Promise<{ url: string; confirmation_code: string }> {
  const config = getFacebookOAuthConfig();
  const appAccessToken = getAppAccessToken();

  const url = new URL(`${FACEBOOK_GRAPH_API}/${userId}/deletions`);
  url.searchParams.set("access_token", appAccessToken);

  const response = await fetch(url.toString(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      confirmation_code: confirmationCode,
    }),
  });

  if (!response.ok) {
    throw new Error("Failed to initiate user data deletion");
  }

  return response.json();
}

/**
 * Reset cached configuration (useful for testing)
 */
export function resetFacebookOAuthConfig(): void {
  configCache = null;
}

/**
 * Get Facebook login status URL for JS SDK
 */
export function getFacebookLoginStatusURL(appId?: string): string {
  const config = getFacebookOAuthConfig();
  return `https://www.facebook.com/v${config.apiVersion || "18.0"}/dialog/oauth/status?client_id=${appId || config.appId}`;
}

/**
 * Verify webhook signature (for Facebook webhooks)
 */
export function verifyFacebookWebhookSignature(
  signature: string,
  body: string,
  appSecret?: string
): boolean {
  const config = getFacebookOAuthConfig();
  const secret = appSecret || config.appSecret;

  const crypto = require("crypto");
  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(body)
    .digest("hex");

  return `sha256=${expectedSignature}` === signature;
}
