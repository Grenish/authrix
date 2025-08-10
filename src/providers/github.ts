// Types
interface GitHubOAuthConfig {
    clientId: string;
    clientSecret: string;
    redirectUri: string;
  }
  
  interface GitHubTokenResponse {
    access_token: string;
    token_type: string;
    scope: string;
    error?: string;
    error_description?: string;
    error_uri?: string;
  }
  
  interface GitHubUser {
    id: number;
    login: string;
    name: string | null;
    email: string | null;
    avatar_url: string;
    bio: string | null;
    company: string | null;
    location: string | null;
    blog: string | null;
    twitter_username: string | null;
    public_repos: number;
    followers: number;
    following: number;
    created_at: string;
    updated_at: string;
    two_factor_authentication: boolean;
    plan?: {
      name: string;
      space: number;
      collaborators: number;
      private_repos: number;
    };
  }
  
  interface GitHubEmail {
    email: string;
    primary: boolean;
    verified: boolean;
    visibility: string | null;
  }
  
  interface OAuthUser {
    id: string;
    email: string;
    username: string;
    name?: string;
    avatar?: string;
    provider: 'github';
    emailVerified: boolean;
    metadata?: {
      bio?: string;
      company?: string;
      location?: string;
      blog?: string;
      twitterUsername?: string;
      publicRepos?: number;
      followers?: number;
      following?: number;
      createdAt?: string;
      twoFactorEnabled?: boolean;
      emails?: Array<{
        email: string;
        verified: boolean;
        primary: boolean;
      }>;
    };
  }
  
  // Constants
  const GITHUB_API_BASE = 'https://api.github.com';
  const GITHUB_OAUTH_ENDPOINTS = {
    AUTHORIZE: 'https://github.com/login/oauth/authorize',
    TOKEN: 'https://github.com/login/oauth/access_token',
    USER: `${GITHUB_API_BASE}/user`,
    EMAILS: `${GITHUB_API_BASE}/user/emails`,
    REVOKE: (clientId: string, token: string) => 
      `${GITHUB_API_BASE}/applications/${clientId}/token`,
  } as const;
  
  const DEFAULT_SCOPES = ['read:user', 'user:email'] as const;
  
  // Configuration cache
  let configCache: GitHubOAuthConfig | null = null;
  
  // Environment variable loader with caching
  function getGitHubOAuthConfig(): GitHubOAuthConfig {
    if (configCache) {
      return configCache;
    }
  
    const clientId = process.env.GITHUB_CLIENT_ID;
    const clientSecret = process.env.GITHUB_CLIENT_SECRET;
    const redirectUri = process.env.GITHUB_REDIRECT_URI || process.env.GITHUB_OAUTH_REDIRECT_URI;
  
    if (!clientId || !clientSecret || !redirectUri) {
      const missing = [];
      if (!clientId) missing.push('GITHUB_CLIENT_ID');
      if (!clientSecret) missing.push('GITHUB_CLIENT_SECRET');
      if (!redirectUri) missing.push('GITHUB_REDIRECT_URI');
      
      throw new Error(
        `Missing GitHub OAuth environment variables: ${missing.join(', ')}. ` +
        `These are required when using GitHub OAuth functionality. ` +
        `Visit https://github.com/settings/developers to create an OAuth App and obtain these values.`
      );
    }
  
    configCache = {
      clientId,
      clientSecret,
      redirectUri
    };
  
    return configCache;
  }
  
  // API request helper with error handling
  async function gitHubApiRequest<T>(
    url: string,
    accessToken: string,
    options: RequestInit = {}
  ): Promise<T> {
    const response = await fetch(url, {
      ...options,
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/vnd.github.v3+json',
        'X-GitHub-Api-Version': '2022-11-28',
        ...options.headers,
      },
    });
  
    if (!response.ok) {
      const errorText = await response.text();
      let errorMessage = `GitHub API request failed: ${response.status}`;
      
      try {
        const errorJson = JSON.parse(errorText);
        errorMessage = errorJson.message || errorMessage;
      } catch {}
      
      throw new Error(errorMessage);
    }
  
    return response.json();
  }
  
  // Main OAuth functions
  export function getGitHubOAuthURL(options: {
    state?: string;
    scopes?: string[];
    allowSignup?: boolean;
    login?: string;
    redirectUri?: string;
  } = {}): string {
    const config = getGitHubOAuthConfig();
    
    const params = new URLSearchParams({
      client_id: config.clientId,
      redirect_uri: options.redirectUri || config.redirectUri,
      scope: (options.scopes || DEFAULT_SCOPES).join(' '),
    });
  
    // Add optional parameters
    if (options.state) params.set('state', options.state);
    if (options.login) params.set('login', options.login);
    if (options.allowSignup !== undefined) {
      params.set('allow_signup', String(options.allowSignup));
    }
  
    return `${GITHUB_OAUTH_ENDPOINTS.AUTHORIZE}?${params.toString()}`;
  }
  
  export async function handleGitHubCallback(
    code: string,
    options: {
      state?: string;
      skipEmailVerification?: boolean;
      redirectUri?: string;
      includeToken?: boolean;
      fetchAllEmails?: boolean;
    } = {}
  ): Promise<OAuthUser & { token?: string }> {
    const config = getGitHubOAuthConfig();
    
    try {
      // Exchange code for access token
      const tokenResponse = await fetch(GITHUB_OAUTH_ENDPOINTS.TOKEN, {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          client_id: config.clientId,
          client_secret: config.clientSecret,
          code,
          redirect_uri: options.redirectUri || config.redirectUri,
          ...(options.state && { state: options.state }),
        }),
      });
  
      if (!tokenResponse.ok) {
        const error = await tokenResponse.text();
        throw new Error(`Token exchange failed: ${tokenResponse.status} - ${error}`);
      }
  
      const tokenData: GitHubTokenResponse = await tokenResponse.json();
      
      if (tokenData.error) {
        throw new Error(`GitHub OAuth error: ${tokenData.error_description || tokenData.error}`);
      }
  
      if (!tokenData.access_token) {
        throw new Error('No access token received from GitHub');
      }
  
      // Fetch user data and emails in parallel
      const [userData, emailData] = await Promise.all([
        gitHubApiRequest<GitHubUser>(GITHUB_OAUTH_ENDPOINTS.USER, tokenData.access_token),
        gitHubApiRequest<GitHubEmail[]>(GITHUB_OAUTH_ENDPOINTS.EMAILS, tokenData.access_token),
      ]);
  
      // Find primary verified email
      const primaryEmail = emailData.find(e => e.primary && e.verified);
      const verifiedEmails = emailData.filter(e => e.verified);
      
      if (!primaryEmail && !options.skipEmailVerification) {
        throw new Error('No verified primary email found. Please verify your email on GitHub.');
      }
  
      // Use the best available email
      const userEmail = primaryEmail?.email || 
                        verifiedEmails[0]?.email || 
                        userData.email || 
                        emailData[0]?.email;
  
      if (!userEmail) {
        throw new Error('No email address found for this GitHub account.');
      }
  
      // Build user object with rich metadata
      const user: OAuthUser = {
        id: userData.id.toString(),
        email: userEmail,
        username: userData.login,
        name: userData.name || userData.login,
        avatar: userData.avatar_url,
        provider: 'github',
        emailVerified: primaryEmail?.verified || false,
        metadata: {
          bio: userData.bio || undefined,
          company: userData.company || undefined,
          location: userData.location || undefined,
          blog: userData.blog || undefined,
          twitterUsername: userData.twitter_username || undefined,
          publicRepos: userData.public_repos,
          followers: userData.followers,
          following: userData.following,
          createdAt: userData.created_at,
          twoFactorEnabled: userData.two_factor_authentication,
          ...(options.fetchAllEmails && {
            emails: emailData.map(e => ({
              email: e.email,
              verified: e.verified,
              primary: e.primary,
            })),
          }),
        },
      };
  
      // Include token if requested
      if (options.includeToken) {
        return { ...user, token: tokenData.access_token };
      }
  
      return user;
    } catch (error) {
      console.error('[GitHub OAuth Error]:', error);
      
      if (error instanceof Error) {
        // Provide user-friendly error messages
        if (error.message.includes('fetch')) {
          throw new Error('Network error during GitHub authentication. Please try again.');
        }
        if (error.message.includes('401') || error.message.includes('403')) {
          throw new Error('GitHub authentication failed. Please try again.');
        }
        if (error.message.includes('rate limit')) {
          throw new Error('Too many requests. Please try again later.');
        }
        throw new Error(`GitHub authentication failed: ${error.message}`);
      }
      
      throw new Error('An unexpected error occurred during GitHub authentication.');
    }
  }
  
  // Additional utility functions
  
  /**
   * Revoke GitHub OAuth token
   */
  export async function revokeGitHubToken(
    token: string,
    clientId?: string,
    clientSecret?: string
  ): Promise<boolean> {
    try {
      const config = clientId && clientSecret 
        ? { clientId, clientSecret, redirectUri: '' }
        : getGitHubOAuthConfig();
      
      const response = await fetch(
        GITHUB_OAUTH_ENDPOINTS.REVOKE(config.clientId, token),
        {
          method: 'DELETE',
          headers: {
            'Accept': 'application/vnd.github.v3+json',
            'Authorization': `Basic ${btoa(`${config.clientId}:${config.clientSecret}`)}`,
          },
        }
      );
  
      return response.status === 204;
    } catch (error) {
      console.error('[GitHub OAuth Revoke Error]:', error);
      return false;
    }
  }
  
  /**
   * Validate GitHub access token
   */
  export async function validateGitHubToken(token: string): Promise<GitHubUser | null> {
    try {
      const user = await gitHubApiRequest<GitHubUser>(
        GITHUB_OAUTH_ENDPOINTS.USER,
        token
      );
      return user;
    } catch {
      return null;
    }
  }
  
  /**
   * Get GitHub user organizations
   */
  export async function getGitHubUserOrganizations(
    token: string
  ): Promise<Array<{ login: string; id: number; avatar_url: string }>> {
    try {
      return await gitHubApiRequest(
        `${GITHUB_API_BASE}/user/orgs`,
        token
      );
    } catch (error) {
      console.error('[GitHub Orgs Error]:', error);
      return [];
    }
  }
  
  /**
   * Check if user is member of a specific organization
   */
  export async function checkGitHubOrgMembership(
    token: string,
    org: string
  ): Promise<boolean> {
    try {
      const orgs = await getGitHubUserOrganizations(token);
      return orgs.some(o => o.login.toLowerCase() === org.toLowerCase());
    } catch {
      return false;
    }
  }
  
  /**
   * Generate a secure state parameter for CSRF protection
   */
  export function generateOAuthState(data?: any): string {
    const randomBytes = crypto.getRandomValues(new Uint8Array(32));
    const randomString = Array.from(randomBytes, byte => 
      byte.toString(16).padStart(2, '0')
    ).join('');
    
    if (data) {
      const json = JSON.stringify(data);
      const encoded = btoa(json).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      return `${randomString}.${encoded}`;
    }
    
    return randomString;
  }
  
  /**
   * Parse OAuth state parameter
   */
  export function parseOAuthState(state: string): { token: string; data?: any } {
    const parts = state.split('.');
    
    if (parts.length === 1) {
      return { token: parts[0] };
    }
    
    try {
      const encoded = parts[1];
      const padded = encoded + '='.repeat((4 - encoded.length % 4) % 4);
      const json = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
      const data = JSON.parse(json);
      
      return { token: parts[0], data };
    } catch {
      return { token: parts[0] };
    }
  }
  
  /**
   * Reset cached configuration (useful for testing)
   */
  export function resetGitHubOAuthConfig(): void {
    configCache = null;
  }
  
  /**
   * Get rate limit status for authenticated user
   */
  export async function getGitHubRateLimit(token: string): Promise<{
    limit: number;
    remaining: number;
    reset: Date;
  }> {
    try {
      const data = await gitHubApiRequest<any>(
        `${GITHUB_API_BASE}/rate_limit`,
        token
      );
      
      return {
        limit: data.rate.limit,
        remaining: data.rate.remaining,
        reset: new Date(data.rate.reset * 1000),
      };
    } catch (error) {
      console.error('[GitHub Rate Limit Error]:', error);
      return {
        limit: 0,
        remaining: 0,
        reset: new Date(),
      };
    }
  }