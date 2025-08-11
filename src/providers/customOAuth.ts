// Types
export interface OAuthProviderConfig {
    name: string;
    clientId: string;
    clientSecret: string;
    redirectUri: string;
    endpoints: {
        authorization: string;
        token: string;
        userInfo?: string;
        revoke?: string;
    };
    scopes?: string[];
    authorizationParams?: Record<string, string>;
    tokenParams?: Record<string, string>;
    userInfoHeaders?: Record<string, string>;
    userProfileMapping?: UserProfileMapping;
    pkce?: boolean; // Support for PKCE flow
    state?: boolean; // Enable state parameter for CSRF protection
}

export interface UserProfileMapping {
    id: string | ((data: any) => string);
    email: string | ((data: any) => string);
    name?: string | ((data: any) => string | undefined);
    avatar?: string | ((data: any) => string | undefined);
    emailVerified?: string | ((data: any) => boolean);
    metadata?: Record<string, string | ((data: any) => any)>;
}

export interface TokenResponse {
    access_token: string;
    token_type: string;
    expires_in?: number;
    refresh_token?: string;
    scope?: string;
    id_token?: string;
    [key: string]: any;
}

export interface OAuthUser {
    id: string;
    email: string;
    name?: string;
    avatar?: string;
    provider: string;
    emailVerified?: boolean;
    metadata?: Record<string, any>;
    raw?: any; // Raw response from provider
}

export interface OAuthTokens {
    access: string;
    refresh?: string;
    idToken?: string;
    expiresIn?: number;
    tokenType: string;
}

export interface OAuthCallbackResult {
    user: OAuthUser;
    tokens?: OAuthTokens;
}

export interface AuthorizationURLOptions {
    state?: string;
    scopes?: string[];
    loginHint?: string;
    prompt?: string;
    accessType?: string;
    additionalParams?: Record<string, string>;
}

export interface CallbackOptions {
    state?: string;
    includeTokens?: boolean;
    includeRawResponse?: boolean;
    skipEmailVerification?: boolean;
}

// PKCE Helper
class PKCEChallenge {
    private static base64URLEncode(input: ArrayBuffer | Uint8Array): string {
        const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
        let str = '';
        for (let i = 0; i < bytes.length; i++) {
            str += String.fromCharCode(bytes[i]);
        }
        return btoa(str)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    static async generateChallenge(): Promise<{ verifier: string; challenge: string }> {
    const verifier = PKCEChallenge.base64URLEncode(crypto.getRandomValues(new Uint8Array(32)));

        const encoder = new TextEncoder();
        const data = encoder.encode(verifier);
        const hash = await crypto.subtle.digest('SHA-256', data);
        const challenge = PKCEChallenge.base64URLEncode(hash);

        return { verifier, challenge };
    }
}

// Custom OAuth Provider Class
export class CustomOAuthProvider {
    private config: OAuthProviderConfig;
    private pkceStore: Map<string, string> = new Map(); // Store PKCE verifiers

    constructor(config: OAuthProviderConfig) {
        this.validateConfig(config);
        this.config = this.normalizeConfig(config);
    }

    private validateConfig(config: OAuthProviderConfig): void {
        const required = ['name', 'clientId', 'clientSecret', 'redirectUri', 'endpoints'];
        const missing = required.filter(field => !config[field as keyof OAuthProviderConfig]);

        if (missing.length > 0) {
            throw new Error(`Missing required OAuth configuration: ${missing.join(', ')}`);
        }

        if (!config.endpoints.authorization || !config.endpoints.token) {
            throw new Error('Authorization and token endpoints are required');
        }

        // Validate URL formats
        try {
            new URL(config.endpoints.authorization);
            new URL(config.endpoints.token);
            if (config.endpoints.userInfo) new URL(config.endpoints.userInfo);
            if (config.endpoints.revoke) new URL(config.endpoints.revoke);
        } catch (error) {
            throw new Error('Invalid endpoint URL format');
        }
    }

    private normalizeConfig(config: OAuthProviderConfig): OAuthProviderConfig {
        return {
            ...config,
            scopes: config.scopes || ['openid', 'profile', 'email'],
            authorizationParams: config.authorizationParams || {},
            tokenParams: config.tokenParams || {},
            userInfoHeaders: config.userInfoHeaders || {},
            state: config.state !== false, // Enable state by default
            userProfileMapping: config.userProfileMapping || {
                id: 'sub',
                email: 'email',
                name: 'name',
                avatar: 'picture',
                emailVerified: 'email_verified'
            }
        };
    }

    /**
     * Generate OAuth Authorization URL
     */
    async getAuthorizationURL(options: AuthorizationURLOptions = {}): Promise<string> {
        const params = new URLSearchParams({
            client_id: this.config.clientId,
            redirect_uri: this.config.redirectUri,
            response_type: 'code',
            scope: (options.scopes || this.config.scopes || []).join(' '),
            ...this.config.authorizationParams,
            ...options.additionalParams
        });

        // Add state for CSRF protection
        if (this.config.state) {
            const state = options.state || this.generateState();
            params.set('state', state);
        }

        // Add PKCE parameters if enabled
        if (this.config.pkce) {
            const { verifier, challenge } = await PKCEChallenge.generateChallenge();
            const stateKey = options.state || params.get('state') || this.generateState();

            this.pkceStore.set(stateKey, verifier);
            params.set('code_challenge', challenge);
            params.set('code_challenge_method', 'S256');

            if (!params.has('state')) {
                params.set('state', stateKey);
            }
        }

        // Add optional parameters
        if (options.loginHint) params.set('login_hint', options.loginHint);
        if (options.prompt) params.set('prompt', options.prompt);
        if (options.accessType) params.set('access_type', options.accessType);

        return `${this.config.endpoints.authorization}?${params.toString()}`;
    }

    /**
     * Handle OAuth Callback
     */
    async handleCallback(code: string, options: CallbackOptions = {}): Promise<OAuthCallbackResult> {
        try {
            // Exchange code for tokens
            const tokens = await this.exchangeCodeForTokens(code, options.state);

            // Get user profile
            let userProfile: any = {};

            // Try to decode ID token if available
            if (tokens.id_token) {
                const decodedToken = this.decodeJWT(tokens.id_token);
                if (decodedToken) {
                    userProfile = decodedToken;
                }
            }

            // Fetch user info from API if endpoint is configured
            if (this.config.endpoints.userInfo && tokens.access_token) {
                try {
                    const apiProfile = await this.fetchUserInfo(tokens.access_token);
                    userProfile = { ...userProfile, ...apiProfile };
                } catch (error) {
                    console.warn(`Failed to fetch user info from ${this.config.name}:`, error);
                    // Continue with ID token data if available
                    if (!tokens.id_token) {
                        throw error;
                    }
                }
            }

            // Ensure we have user data
            if (!userProfile || Object.keys(userProfile).length === 0) {
                throw new Error('No user profile data available');
            }

            // Map user profile to standard format
            const user = this.mapUserProfile(userProfile);

            // Validate email verification if required
            if (!options.skipEmailVerification && user.emailVerified === false) {
                throw new Error('Email address is not verified');
            }

            // Include raw response if requested
            if (options.includeRawResponse) {
                user.raw = userProfile;
            }

            const result: OAuthCallbackResult = { user };

            // Include tokens if requested
            if (options.includeTokens) {
                result.tokens = {
                    access: tokens.access_token,
                    refresh: tokens.refresh_token,
                    idToken: tokens.id_token,
                    expiresIn: tokens.expires_in,
                    tokenType: tokens.token_type
                };
            }

            // Clean up PKCE verifier if used
            if (this.config.pkce && options.state) {
                this.pkceStore.delete(options.state);
            }

            return result;
        } catch (error) {
            // Clean up PKCE verifier on error
            if (this.config.pkce && options.state) {
                this.pkceStore.delete(options.state);
            }

            console.error(`[${this.config.name} OAuth Error]:`, error);

            if (error instanceof Error) {
                throw new Error(`${this.config.name} authentication failed: ${error.message}`);
            }

            throw new Error(`An unexpected error occurred during ${this.config.name} authentication`);
        }
    }

    /**
     * Exchange authorization code for tokens
     */
    private async exchangeCodeForTokens(code: string, state?: string): Promise<TokenResponse> {
        const params = new URLSearchParams({
            code,
            client_id: this.config.clientId,
            client_secret: this.config.clientSecret,
            redirect_uri: this.config.redirectUri,
            grant_type: 'authorization_code',
            ...this.config.tokenParams
        });

        // Add PKCE verifier if enabled
        if (this.config.pkce && state) {
            const verifier = this.pkceStore.get(state);
            if (verifier) {
                params.set('code_verifier', verifier);
            } else {
                throw new Error('PKCE verifier not found for state');
            }
        }

        const response = await fetch(this.config.endpoints.token, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            },
            body: params.toString()
        });

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Token exchange failed: ${response.status} - ${error}`);
        }

        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return await response.json();
        }

        // Some providers return URL-encoded responses
        const text = await response.text();
        const tokenData: any = {};
        const urlParams = new URLSearchParams(text);
        urlParams.forEach((value, key) => {
            tokenData[key] = value;
        });
        return tokenData as TokenResponse;
    }

    /**
     * Fetch user information from provider's API
     */
    private async fetchUserInfo(accessToken: string): Promise<any> {
        if (!this.config.endpoints.userInfo) {
            return null;
        }

        const headers = {
            'Authorization': `Bearer ${accessToken}`,
            'Accept': 'application/json',
            ...this.config.userInfoHeaders
        };

        const response = await fetch(this.config.endpoints.userInfo, { headers });

        if (!response.ok) {
            throw new Error(`Failed to fetch user info: ${response.status}`);
        }

        return await response.json();
    }

    /**
     * Map provider-specific user profile to standard format
     */
    private mapUserProfile(data: any): OAuthUser {
        const mapping = this.config.userProfileMapping!;

        const getValue = (mapper: string | ((data: any) => any) | undefined, defaultValue?: any): any => {
            if (!mapper) return defaultValue;

            if (typeof mapper === 'function') {
                try {
                    return mapper(data) || defaultValue;
                } catch (error) {
                    console.warn(`Error mapping user profile field:`, error);
                    return defaultValue;
                }
            }

            // Support nested property access (e.g., "user.email")
            const keys = mapper.split('.');
            let value = data;

            for (const key of keys) {
                value = value?.[key];
                if (value === undefined) return defaultValue;
            }

            return value || defaultValue;
        };

        const user: OAuthUser = {
            id: getValue(mapping.id, ''),
            email: getValue(mapping.email, ''),
            name: getValue(mapping.name),
            avatar: getValue(mapping.avatar),
            provider: this.config.name,
            emailVerified: getValue(mapping.emailVerified)
        };

        // Map additional metadata
        if (mapping.metadata) {
            user.metadata = {};
            for (const [key, mapper] of Object.entries(mapping.metadata)) {
                const value = getValue(mapper);
                if (value !== undefined) {
                    user.metadata[key] = value;
                }
            }
        }

        return user;
    }

    /**
     * Revoke OAuth tokens
     */
    async revokeTokens(token: string, tokenType: 'access_token' | 'refresh_token' = 'access_token'): Promise<boolean> {
        if (!this.config.endpoints.revoke) {
            console.warn(`No revoke endpoint configured for ${this.config.name}`);
            return false;
        }

        try {
            const params = new URLSearchParams({
                token,
                token_type_hint: tokenType,
                client_id: this.config.clientId,
                client_secret: this.config.clientSecret
            });

            const response = await fetch(this.config.endpoints.revoke, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: params.toString()
            });

            return response.ok;
        } catch (error) {
            console.error(`[${this.config.name} Revoke Error]:`, error);
            return false;
        }
    }

    /**
     * Refresh access token
     */
    async refreshAccessToken(refreshToken: string): Promise<TokenResponse> {
        const params = new URLSearchParams({
            refresh_token: refreshToken,
            client_id: this.config.clientId,
            client_secret: this.config.clientSecret,
            grant_type: 'refresh_token'
        });

        const response = await fetch(this.config.endpoints.token, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            },
            body: params.toString()
        });

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Token refresh failed: ${response.status} - ${error}`);
        }

        return await response.json();
    }

    /**
     * Validate ID token (basic validation without crypto)
     */
    async validateIdToken(idToken: string): Promise<any | null> {
        try {
            const decoded = this.decodeJWT(idToken);
            if (!decoded) return null;

            // Check expiration
            const now = Math.floor(Date.now() / 1000);
            if (decoded.exp && decoded.exp < now) {
                return null;
            }

            // Check audience if available
            if (decoded.aud && decoded.aud !== this.config.clientId) {
                return null;
            }

            return decoded;
        } catch {
            return null;
        }
    }

    /**
     * Decode JWT token
     */
    private decodeJWT(token: string): any {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) return null;

            const payload = parts[1];
            const padded = payload + '='.repeat((4 - (payload.length % 4)) % 4);
            const decoded = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
            return JSON.parse(decoded);
        } catch (error) {
            console.warn('Failed to decode JWT:', error);
            return null;
        }
    }

    /**
     * Generate state parameter for CSRF protection
     */
    generateState(data?: any): string {
        const randomBytes = crypto.getRandomValues(new Uint8Array(32));
        const randomString = Array.from(randomBytes, byte =>
            byte.toString(16).padStart(2, '0')
        ).join('');

        if (data) {
            const json = JSON.stringify(data);
            const encoded = btoa(json)
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=/g, '');
            return `${randomString}.${encoded}`;
        }

        return randomString;
    }

    /**
     * Parse state parameter
     */
    parseState(state: string): { token: string; data?: any } {
        const parts = state.split('.');

        if (parts.length === 1) {
            return { token: parts[0] };
        }

        try {
            const encoded = parts[1];
            const padded = encoded + '='.repeat((4 - (encoded.length % 4)) % 4);
            const json = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
            const data = JSON.parse(json);

            return { token: parts[0], data };
        } catch {
            return { token: parts[0] };
        }
    }

    /**
     * Get provider configuration
     */
    getConfig(): Readonly<OAuthProviderConfig> {
        return { ...this.config };
    }

    /**
     * Update provider configuration
     */
    updateConfig(updates: Partial<OAuthProviderConfig>): void {
        // Don't allow changing critical fields
        const { name, endpoints, ...allowedUpdates } = updates;

        if (name || endpoints) {
            throw new Error('Cannot update provider name or endpoints after initialization');
        }

        this.config = {
            ...this.config,
            ...allowedUpdates
        };
    }

    /**
     * Clear PKCE store (for cleanup)
     */
    clearPKCEStore(): void {
        this.pkceStore.clear();
    }
}

// OAuth Provider Manager for handling multiple providers
export class OAuthProviderManager {
    private providers: Map<string, CustomOAuthProvider> = new Map();

    /**
     * Register a new OAuth provider
     */
    register(config: OAuthProviderConfig): CustomOAuthProvider {
        if (this.providers.has(config.name)) {
            throw new Error(`Provider "${config.name}" is already registered`);
        }

        const provider = new CustomOAuthProvider(config);
        this.providers.set(config.name, provider);
        return provider;
    }

    /**
     * Get a registered provider
     */
    get(name: string): CustomOAuthProvider | undefined {
        return this.providers.get(name);
    }

    /**
     * Remove a provider
     */
    remove(name: string): boolean {
        const provider = this.providers.get(name);
        if (provider) {
            provider.clearPKCEStore(); // Clean up before removing
        }
        return this.providers.delete(name);
    }

    /**
     * List all registered providers
     */
    list(): string[] {
        return Array.from(this.providers.keys());
    }

    /**
     * Check if a provider is registered
     */
    has(name: string): boolean {
        return this.providers.has(name);
    }

    /**
     * Clear all providers
     */
    clear(): void {
        this.providers.forEach(provider => provider.clearPKCEStore());
        this.providers.clear();
    }
}

// Create a singleton instance for global use
export const oAuthManager = new OAuthProviderManager();

// Example usage:
/*
// 1. Create a custom OAuth provider
const provider = new CustomOAuthProvider({
  name: 'my-custom-provider',
  clientId: process.env.CUSTOM_CLIENT_ID!,
  clientSecret: process.env.CUSTOM_CLIENT_SECRET!,
  redirectUri: 'http://localhost:3000/api/auth/callback/custom',
  endpoints: {
    authorization: 'https://provider.com/oauth/authorize',
    token: 'https://provider.com/oauth/token',
    userInfo: 'https://provider.com/api/user',
    revoke: 'https://provider.com/oauth/revoke'
  },
  scopes: ['user', 'email'],
  pkce: true, // Enable PKCE for enhanced security
  userProfileMapping: {
    id: 'user_id',
    email: 'email_address',
    name: 'display_name',
    avatar: 'profile_picture_url',
    emailVerified: 'email_confirmed',
    metadata: {
      username: 'username',
      bio: 'biography',
      createdAt: 'account_created'
    }
  }
});
 
// 2. Generate authorization URL
const authUrl = await provider.getAuthorizationURL({
  state: 'random-state-123',
  scopes: ['user', 'email', 'profile']
});
 
// 3. Handle OAuth callback
const result = await provider.handleCallback(authorizationCode, {
  state: 'random-state-123',
  includeTokens: true,
  includeRawResponse: true
});
 
console.log('User:', result.user);
console.log('Tokens:', result.tokens);
 
// 4. Refresh access token
if (result.tokens?.refresh) {
  const newTokens = await provider.refreshAccessToken(result.tokens.refresh);
  console.log('New access token:', newTokens.access_token);
}
 
// 5. Revoke tokens when done
await provider.revokeTokens(result.tokens?.access || '');
*/