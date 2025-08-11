// Types
interface LinkedInOAuthConfig {
    clientId: string;
    clientSecret: string;
    redirectUri: string;
}

interface LinkedInTokenResponse {
    access_token: string;
    expires_in: number;
    refresh_token?: string;
    refresh_token_expires_in?: number;
    scope?: string;
    token_type: string;
    id_token?: string;
}

interface LinkedInUserInfo {
    sub: string;
    email: string;
    email_verified: boolean;
    name: string;
    picture?: string;
    given_name?: string;
    family_name?: string;
    locale?: {
        country: string;
        language: string;
    };
}

interface LinkedInOAuthUser {
    id: string;
    email: string;
    name?: string;
    avatar?: string;
    provider: "linkedin";
    emailVerified: boolean;
    metadata?: {
        givenName?: string;
        familyName?: string;
        locale?: {
            country: string;
            language: string;
        };
    };
}

// Constants
const LINKEDIN_OAUTH_ENDPOINTS = {
    AUTH: "https://www.linkedin.com/oauth/v2/authorization",
    TOKEN: "https://www.linkedin.com/oauth/v2/accessToken",
    USER_INFO: "https://api.linkedin.com/v2/userinfo",
    INTROSPECT: "https://www.linkedin.com/oauth/v2/introspectToken",
    REVOKE: "https://www.linkedin.com/oauth/v2/revoke",
} as const;

const DEFAULT_LINKEDIN_SCOPES = ["openid", "profile", "email"] as const;

// Configuration cache
let linkedInConfigCache: LinkedInOAuthConfig | null = null;

// Environment variable loader with caching
function getLinkedInOAuthConfig(): LinkedInOAuthConfig {
    // Return cached config if available
    if (linkedInConfigCache) {
        return linkedInConfigCache;
    }

    const clientId = process.env.LINKEDIN_CLIENT_ID;
    const clientSecret = process.env.LINKEDIN_CLIENT_SECRET;
    const redirectUri =
        process.env.LINKEDIN_REDIRECT_URI || process.env.LINKEDIN_OAUTH_REDIRECT_URI;

    if (!clientId || !clientSecret || !redirectUri) {
        const missing = [];
        if (!clientId) missing.push("LINKEDIN_CLIENT_ID");
        if (!clientSecret) missing.push("LINKEDIN_CLIENT_SECRET");
        if (!redirectUri) missing.push("LINKEDIN_REDIRECT_URI");

        throw new Error(
            `Missing LinkedIn OAuth environment variables: ${missing.join(", ")}. ` +
            `These are required when using LinkedIn OAuth functionality. ` +
            `Visit https://www.linkedin.com/developers/apps to obtain these values.`
        );
    }

    // Cache the configuration
    linkedInConfigCache = {
        clientId,
        clientSecret,
        redirectUri,
    };

    return linkedInConfigCache;
}

// JWT decoder for id_token (basic, no crypto validation)
function decodeLinkedInJWT(token: string): any {
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
export function getLinkedInOAuthURL(
    options: {
        state?: string;
        scopes?: string[];
        loginHint?: string;
        prompt?: "consent" | "select_account";
        redirectUri?: string;
    } = {}
): string {
    const config = getLinkedInOAuthConfig();

    const params = new URLSearchParams({
        response_type: "code",
        client_id: config.clientId,
        redirect_uri: options.redirectUri || config.redirectUri,
        scope: (options.scopes || DEFAULT_LINKEDIN_SCOPES).join(" "),
    });

    // Add optional parameters
    if (options.state) params.set("state", options.state);
    if (options.loginHint) params.set("login_hint", options.loginHint);
    if (options.prompt) params.set("prompt", options.prompt);

    return `${LINKEDIN_OAUTH_ENDPOINTS.AUTH}?${params.toString()}`;
}

export async function handleLinkedInCallback(
    code: string,
    options: {
        skipEmailVerification?: boolean;
        redirectUri?: string;
        includeTokens?: boolean;
        state?: string;
    } = {}
): Promise<
    LinkedInOAuthUser & { tokens?: { access: string; refresh?: string; idToken?: string } }
> {
    const config = getLinkedInOAuthConfig();

    try {
        // Exchange code for tokens
        const tokenResponse = await fetch(LINKEDIN_OAUTH_ENDPOINTS.TOKEN, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                Accept: "application/json",
            },
            body: new URLSearchParams({
                grant_type: "authorization_code",
                code,
                client_id: config.clientId,
                client_secret: config.clientSecret,
                redirect_uri: options.redirectUri || config.redirectUri,
            }).toString(),
        });

        if (!tokenResponse.ok) {
            const error = await tokenResponse.text();
            throw new Error(
                `Token exchange failed: ${tokenResponse.status} - ${error}`
            );
        }

        const tokenData: LinkedInTokenResponse = await tokenResponse.json();

        // LinkedIn may or may not return an ID token depending on scopes
        let userInfo: LinkedInUserInfo;

        if (tokenData.id_token) {
            // Decode and validate ID token if available
            const decodedToken = decodeLinkedInJWT(tokenData.id_token);
            if (!decodedToken) {
                throw new Error("Failed to decode ID token");
            }

            // Validate token claims
            if (decodedToken.aud !== config.clientId) {
                throw new Error("Token audience mismatch");
            }

            if (decodedToken.iss !== "https://www.linkedin.com") {
                throw new Error("Invalid token issuer");
            }

            // Check token expiration
            const now = Math.floor(Date.now() / 1000);
            if (decodedToken.exp < now) {
                throw new Error("ID token has expired");
            }

            userInfo = decodedToken as LinkedInUserInfo;
        }

        // Always fetch fresh user info from LinkedIn's API for most accurate data
        if (tokenData.access_token) {
            const userResponse = await fetch(LINKEDIN_OAUTH_ENDPOINTS.USER_INFO, {
                headers: {
                    Authorization: `Bearer ${tokenData.access_token}`,
                    Accept: "application/json",
                },
            });

            if (userResponse.ok) {
                const apiUserInfo = await userResponse.json();
                // Merge with decoded token data if available, preferring API data
                userInfo = tokenData.id_token
                    ? { ...userInfo!, ...apiUserInfo }
                    : apiUserInfo;
            } else if (!tokenData.id_token) {
                // If no ID token and API call failed, we have no user data
                throw new Error("Failed to fetch user information from LinkedIn");
            }
        } else if (!tokenData.id_token) {
            throw new Error("No access token or ID token received from LinkedIn");
        }

        // Validate email verification
        if (!options.skipEmailVerification && userInfo!.email_verified !== true) {
            throw new Error("Email address is not verified");
        }

        // Build user object
        const user: LinkedInOAuthUser = {
            id: userInfo!.sub,
            email: userInfo!.email,
            name: userInfo!.name,
            avatar: userInfo!.picture,
            provider: "linkedin",
            emailVerified: userInfo!.email_verified,
            metadata: {
                givenName: userInfo!.given_name,
                familyName: userInfo!.family_name,
                locale: userInfo!.locale,
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
        console.error("[LinkedIn OAuth Error]:", error);

        if (error instanceof Error) {
            // Check for common errors and provide helpful messages
            if (error.message.includes("fetch")) {
                throw new Error(
                    "Network error during LinkedIn authentication. Please try again."
                );
            }
            if (
                error.message.includes("audience") ||
                error.message.includes("issuer")
            ) {
                throw new Error("Security validation failed. Please try again.");
            }
            throw new Error(`LinkedIn authentication failed: ${error.message}`);
        }

        throw new Error(
            "An unexpected error occurred during LinkedIn authentication."
        );
    }
}

// Additional utility functions

/**
 * Revoke LinkedIn OAuth tokens
 */
export async function revokeLinkedInTokens(token: string): Promise<boolean> {
    try {
        const config = getLinkedInOAuthConfig();

        const response = await fetch(LINKEDIN_OAUTH_ENDPOINTS.REVOKE, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body: new URLSearchParams({
                token,
                client_id: config.clientId,
                client_secret: config.clientSecret,
            }).toString(),
        });

        return response.ok;
    } catch (error) {
        console.error("[LinkedIn OAuth Revoke Error]:", error);
        return false;
    }
}

/**
 * Introspect LinkedIn OAuth token
 */
export async function introspectLinkedInToken(
    token: string
): Promise<any | null> {
    try {
        const config = getLinkedInOAuthConfig();

        const response = await fetch(LINKEDIN_OAUTH_ENDPOINTS.INTROSPECT, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                Accept: "application/json",
            },
            body: new URLSearchParams({
                token,
                client_id: config.clientId,
                client_secret: config.clientSecret,
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
 * Refresh LinkedIn access token
 */
export async function refreshLinkedInAccessToken(
    refreshToken: string
): Promise<LinkedInTokenResponse | null> {
    try {
        const config = getLinkedInOAuthConfig();

        const response = await fetch(LINKEDIN_OAUTH_ENDPOINTS.TOKEN, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                Accept: "application/json",
            },
            body: new URLSearchParams({
                grant_type: "refresh_token",
                refresh_token: refreshToken,
                client_id: config.clientId,
                client_secret: config.clientSecret,
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
 * Validate LinkedIn ID token (lightweight, no external dependencies)
 */
export async function validateLinkedInIdToken(
    idToken: string
): Promise<LinkedInUserInfo | null> {
    try {
        const decodedToken = decodeLinkedInJWT(idToken);
        if (!decodedToken) {
            return null;
        }

        const config = getLinkedInOAuthConfig();

        // Validate audience
        if (decodedToken.aud !== config.clientId) {
            return null;
        }

        // Validate issuer
        if (decodedToken.iss !== "https://www.linkedin.com") {
            return null;
        }

        // Check expiration
        const now = Math.floor(Date.now() / 1000);
        if (decodedToken.exp < now) {
            return null;
        }

        return decodedToken as LinkedInUserInfo;
    } catch {
        return null;
    }
}

/**
 * Generate a secure state parameter for CSRF protection
 */
export function generateLinkedInOAuthState(data?: any): string {
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
 * Parse LinkedIn OAuth state parameter
 */
export function parseLinkedInOAuthState(state: string): { token: string; data?: any } {
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
export function resetLinkedInOAuthConfig(): void {
    linkedInConfigCache = null;
}