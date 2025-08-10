// Types
interface DiscordOAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  botToken?: string; // Optional: for bot-related operations
}

interface DiscordTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
  scope: string;
  webhook?: {
    id: string;
    type: number;
    guild_id?: string;
    channel_id?: string;
    name?: string;
    avatar?: string;
    token?: string;
    application_id: string;
  };
  guild?: {
    id: string;
    name?: string;
    icon?: string;
    owner?: boolean;
    permissions?: string;
  };
}

interface DiscordUser {
  id: string;
  username: string;
  discriminator: string;
  global_name?: string | null;
  avatar?: string | null;
  bot?: boolean;
  system?: boolean;
  mfa_enabled?: boolean;
  banner?: string | null;
  accent_color?: number | null;
  locale?: string;
  verified?: boolean;
  email?: string | null;
  flags?: number;
  premium_type?: number;
  public_flags?: number;
  avatar_decoration?: string | null;
}

interface DiscordGuild {
  id: string;
  name: string;
  icon?: string | null;
  owner?: boolean;
  permissions?: string;
  features: string[];
}

interface DiscordConnection {
  id: string;
  name: string;
  type: string;
  verified: boolean;
  friend_sync: boolean;
  show_activity: boolean;
  two_way_link: boolean;
  visibility: number;
}

interface OAuthUser {
  id: string;
  email?: string;
  username: string;
  displayName: string;
  avatar?: string;
  provider: "discord";
  emailVerified: boolean;
  metadata?: {
    discriminator?: string;
    globalName?: string;
    banner?: string;
    accentColor?: number;
    locale?: string;
    mfaEnabled?: boolean;
    premiumType?: "none" | "nitro_classic" | "nitro" | "nitro_basic";
    flags?: number;
    publicFlags?: number;
    bot?: boolean;
    system?: boolean;
    guilds?: Array<{
      id: string;
      name: string;
      icon?: string;
      owner?: boolean;
    }>;
    connections?: Array<{
      type: string;
      name: string;
      verified: boolean;
    }>;
  };
}

// Constants
const DISCORD_API_BASE = "https://discord.com/api/v10";
const DISCORD_CDN = "https://cdn.discordapp.com";
const DISCORD_OAUTH_ENDPOINTS = {
  AUTHORIZE: "https://discord.com/oauth2/authorize",
  TOKEN: `${DISCORD_API_BASE}/oauth2/token`,
  REVOKE: `${DISCORD_API_BASE}/oauth2/token/revoke`,
  USER: `${DISCORD_API_BASE}/users/@me`,
  GUILDS: `${DISCORD_API_BASE}/users/@me/guilds`,
  CONNECTIONS: `${DISCORD_API_BASE}/users/@me/connections`,
  GUILD_MEMBER: (guildId: string) =>
    `${DISCORD_API_BASE}/users/@me/guilds/${guildId}/member`,
} as const;

const DEFAULT_SCOPES = ["identify", "email"] as const;

const PREMIUM_TYPES = {
  0: "none",
  1: "nitro_classic",
  2: "nitro",
  3: "nitro_basic",
} as const;

// Permission flags (for bot invites)
export const DiscordPermissions = {
  CREATE_INSTANT_INVITE: 1n << 0n,
  KICK_MEMBERS: 1n << 1n,
  BAN_MEMBERS: 1n << 2n,
  ADMINISTRATOR: 1n << 3n,
  MANAGE_CHANNELS: 1n << 4n,
  MANAGE_GUILD: 1n << 5n,
  ADD_REACTIONS: 1n << 6n,
  VIEW_AUDIT_LOG: 1n << 7n,
  PRIORITY_SPEAKER: 1n << 8n,
  STREAM: 1n << 9n,
  VIEW_CHANNEL: 1n << 10n,
  SEND_MESSAGES: 1n << 11n,
  SEND_TTS_MESSAGES: 1n << 12n,
  MANAGE_MESSAGES: 1n << 13n,
  EMBED_LINKS: 1n << 14n,
  ATTACH_FILES: 1n << 15n,
  READ_MESSAGE_HISTORY: 1n << 16n,
  MENTION_EVERYONE: 1n << 17n,
  USE_EXTERNAL_EMOJIS: 1n << 18n,
  VIEW_GUILD_INSIGHTS: 1n << 19n,
  CONNECT: 1n << 20n,
  SPEAK: 1n << 21n,
  MUTE_MEMBERS: 1n << 22n,
  DEAFEN_MEMBERS: 1n << 23n,
  MOVE_MEMBERS: 1n << 24n,
  USE_VAD: 1n << 25n,
  CHANGE_NICKNAME: 1n << 26n,
  MANAGE_NICKNAMES: 1n << 27n,
  MANAGE_ROLES: 1n << 28n,
  MANAGE_WEBHOOKS: 1n << 29n,
  MANAGE_GUILD_EXPRESSIONS: 1n << 30n,
  USE_APPLICATION_COMMANDS: 1n << 31n,
  REQUEST_TO_SPEAK: 1n << 32n,
  MANAGE_EVENTS: 1n << 33n,
  MANAGE_THREADS: 1n << 34n,
  CREATE_PUBLIC_THREADS: 1n << 35n,
  CREATE_PRIVATE_THREADS: 1n << 36n,
  USE_EXTERNAL_STICKERS: 1n << 37n,
  SEND_MESSAGES_IN_THREADS: 1n << 38n,
  USE_EMBEDDED_ACTIVITIES: 1n << 39n,
  MODERATE_MEMBERS: 1n << 40n,
} as const;

// Configuration cache
let configCache: DiscordOAuthConfig | null = null;

// Environment variable loader with caching
function getDiscordOAuthConfig(): DiscordOAuthConfig {
  if (configCache) {
    return configCache;
  }

  const clientId =
    process.env.DISCORD_CLIENT_ID || process.env.DISCORD_APPLICATION_ID;
  const clientSecret = process.env.DISCORD_CLIENT_SECRET;
  const redirectUri =
    process.env.DISCORD_REDIRECT_URI || process.env.DISCORD_OAUTH_REDIRECT_URI;
  const botToken = process.env.DISCORD_BOT_TOKEN;

  if (!clientId || !clientSecret || !redirectUri) {
    const missing = [];
    if (!clientId) missing.push("DISCORD_CLIENT_ID or DISCORD_APPLICATION_ID");
    if (!clientSecret) missing.push("DISCORD_CLIENT_SECRET");
    if (!redirectUri) missing.push("DISCORD_REDIRECT_URI");

    throw new Error(
      `Missing Discord OAuth environment variables: ${missing.join(", ")}. ` +
        `These are required when using Discord OAuth functionality. ` +
        `Visit https://discord.com/developers/applications to create an application and obtain these values.`
    );
  }

  configCache = {
    clientId,
    clientSecret,
    redirectUri,
    botToken,
  };

  return configCache;
}

// API request helper
async function discordApiRequest<T>(
  url: string,
  accessToken: string,
  options: RequestInit = {}
): Promise<T> {
  const response = await fetch(url, {
    ...options,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      Accept: "application/json",
      ...options.headers,
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    let errorMessage = `Discord API request failed: ${response.status}`;

    try {
      const errorJson = JSON.parse(errorText);
      errorMessage = errorJson.message || errorJson.error || errorMessage;
    } catch {}

    // Handle rate limiting
    if (response.status === 429) {
      const retryAfter = response.headers.get("X-RateLimit-Reset-After");
      throw new Error(`Rate limited. Retry after ${retryAfter} seconds.`);
    }

    throw new Error(errorMessage);
  }

  return response.json();
}

// Helper functions
function buildAvatarUrl(user: DiscordUser): string | undefined {
  if (!user.avatar) return undefined;

  const format = user.avatar.startsWith("a_") ? "gif" : "png";
  return `${DISCORD_CDN}/avatars/${user.id}/${user.avatar}.${format}?size=512`;
}

function buildGuildIconUrl(guild: DiscordGuild): string | undefined {
  if (!guild.icon) return undefined;

  const format = guild.icon.startsWith("a_") ? "gif" : "png";
  return `${DISCORD_CDN}/icons/${guild.id}/${guild.icon}.${format}`;
}

// Main OAuth functions
export function getDiscordOAuthURL(
  options: {
    state?: string;
    scopes?: string[];
    permissions?: bigint;
    guildId?: string;
    disableGuildSelect?: boolean;
    prompt?: "none" | "consent";
    redirectUri?: string;
    responseType?: "code" | "token";
  } = {}
): string {
  const config = getDiscordOAuthConfig();

  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: options.redirectUri || config.redirectUri,
    response_type: options.responseType || "code",
    scope: (options.scopes || DEFAULT_SCOPES).join(" "),
  });

  // Add optional parameters
  if (options.state) params.set("state", options.state);
  if (options.prompt) params.set("prompt", options.prompt);
  if (options.permissions !== undefined) {
    params.set("permissions", options.permissions.toString());
  }
  if (options.guildId) {
    params.set("guild_id", options.guildId);
  }
  if (options.disableGuildSelect) {
    params.set("disable_guild_select", "true");
  }

  return `${DISCORD_OAUTH_ENDPOINTS.AUTHORIZE}?${params.toString()}`;
}

export async function handleDiscordCallback(
  code: string,
  options: {
    state?: string;
    redirectUri?: string;
    includeTokens?: boolean;
    fetchGuilds?: boolean;
    fetchConnections?: boolean;
  } = {}
): Promise<
  OAuthUser & { tokens?: { access: string; refresh: string; expiresAt: Date } }
> {
  const config = getDiscordOAuthConfig();

  try {
    // Exchange code for tokens
    const tokenParams = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: options.redirectUri || config.redirectUri,
    });

    const authHeader = btoa(`${config.clientId}:${config.clientSecret}`);

    const tokenResponse = await fetch(DISCORD_OAUTH_ENDPOINTS.TOKEN, {
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

    const tokenData: DiscordTokenResponse = await tokenResponse.json();

    if (!tokenData.access_token) {
      throw new Error("No access token received from Discord");
    }

    // Fetch user data
    const userData = await discordApiRequest<DiscordUser>(
      DISCORD_OAUTH_ENDPOINTS.USER,
      tokenData.access_token
    );

    // Build user object
    const user: OAuthUser = {
      id: userData.id,
      email: userData.email || undefined,
      username: userData.username,
      displayName: userData.global_name || userData.username,
      avatar: buildAvatarUrl(userData),
      provider: "discord",
      emailVerified: userData.verified || false,
      metadata: {
        discriminator:
          userData.discriminator !== "0" ? userData.discriminator : undefined,
        globalName: userData.global_name || undefined,
        banner: userData.banner || undefined,
        accentColor: userData.accent_color || undefined,
        locale: userData.locale,
        mfaEnabled: userData.mfa_enabled,
        premiumType:
          userData.premium_type !== undefined
            ? PREMIUM_TYPES[userData.premium_type as keyof typeof PREMIUM_TYPES]
            : "none",
        flags: userData.flags,
        publicFlags: userData.public_flags,
        bot: userData.bot,
        system: userData.system,
      },
    };

    // Fetch guilds if requested
    if (options.fetchGuilds) {
      try {
        const guilds = await discordApiRequest<DiscordGuild[]>(
          DISCORD_OAUTH_ENDPOINTS.GUILDS,
          tokenData.access_token
        );

        user.metadata!.guilds = guilds.map((guild) => ({
          id: guild.id,
          name: guild.name,
          icon: buildGuildIconUrl(guild),
          owner: guild.owner,
        }));
      } catch (error) {
        console.error("[Discord Guilds Fetch Error]:", error);
      }
    }

    // Fetch connections if requested
    if (options.fetchConnections) {
      try {
        const connections = await discordApiRequest<DiscordConnection[]>(
          DISCORD_OAUTH_ENDPOINTS.CONNECTIONS,
          tokenData.access_token
        );

        user.metadata!.connections = connections.map((conn) => ({
          type: conn.type,
          name: conn.name,
          verified: conn.verified,
        }));
      } catch (error) {
        console.error("[Discord Connections Fetch Error]:", error);
      }
    }

    // Include tokens if requested
    if (options.includeTokens) {
      const expiresAt = new Date(Date.now() + tokenData.expires_in * 1000);

      return {
        ...user,
        tokens: {
          access: tokenData.access_token,
          refresh: tokenData.refresh_token,
          expiresAt,
        },
      };
    }

    return user;
  } catch (error) {
    console.error("[Discord OAuth Error]:", error);

    if (error instanceof Error) {
      if (error.message.includes("fetch")) {
        throw new Error(
          "Network error during Discord authentication. Please try again."
        );
      }
      if (error.message.includes("401") || error.message.includes("403")) {
        throw new Error("Discord authentication failed. Please try again.");
      }
      if (error.message.includes("Rate limited")) {
        throw error; // Pass through rate limit errors
      }
      throw new Error(`Discord authentication failed: ${error.message}`);
    }

    throw new Error(
      "An unexpected error occurred during Discord authentication."
    );
  }
}

// Additional utility functions

/**
 * Refresh Discord OAuth token
 */
export async function refreshDiscordToken(
  refreshToken: string
): Promise<{ accessToken: string; refreshToken: string; expiresAt: Date }> {
  const config = getDiscordOAuthConfig();

  try {
    const authHeader = btoa(`${config.clientId}:${config.clientSecret}`);

    const response = await fetch(DISCORD_OAUTH_ENDPOINTS.TOKEN, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${authHeader}`,
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      }).toString(),
    });

    if (!response.ok) {
      throw new Error("Token refresh failed");
    }

    const data: DiscordTokenResponse = await response.json();

    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresAt: new Date(Date.now() + data.expires_in * 1000),
    };
  } catch (error) {
    console.error("[Discord OAuth Refresh Error]:", error);
    throw new Error("Failed to refresh Discord authentication token");
  }
}

/**
 * Revoke Discord OAuth token
 */
export async function revokeDiscordToken(
  token: string,
  tokenType: "access_token" | "refresh_token" = "access_token"
): Promise<boolean> {
  const config = getDiscordOAuthConfig();

  try {
    const authHeader = btoa(`${config.clientId}:${config.clientSecret}`);

    const response = await fetch(DISCORD_OAUTH_ENDPOINTS.REVOKE, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${authHeader}`,
      },
      body: new URLSearchParams({
        token,
        token_type_hint: tokenType,
      }).toString(),
    });

    return response.ok;
  } catch (error) {
    console.error("[Discord OAuth Revoke Error]:", error);
    return false;
  }
}

/**
 * Get Discord user by ID (requires bot token)
 */
export async function getDiscordUserById(
  userId: string,
  botToken?: string
): Promise<DiscordUser | null> {
  const config = getDiscordOAuthConfig();
  const token = botToken || config.botToken;

  if (!token) {
    throw new Error("Bot token required for this operation");
  }

  try {
    const response = await fetch(`${DISCORD_API_BASE}/users/${userId}`, {
      headers: {
        Authorization: `Bot ${token}`,
      },
    });

    if (!response.ok) {
      return null;
    }

    return response.json();
  } catch (error) {
    console.error("[Discord User Fetch Error]:", error);
    return null;
  }
}

/**
 * Check if user is in a specific guild
 */
export async function checkGuildMembership(
  accessToken: string,
  guildId: string
): Promise<boolean> {
  try {
    const response = await fetch(
      DISCORD_OAUTH_ENDPOINTS.GUILD_MEMBER(guildId),
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    );

    return response.ok;
  } catch {
    return false;
  }
}

/**
 * Get user's roles in a guild (requires appropriate scopes)
 */
export async function getGuildMemberRoles(
  accessToken: string,
  guildId: string
): Promise<string[] | null> {
  try {
    const member = await discordApiRequest<{ roles: string[] }>(
      DISCORD_OAUTH_ENDPOINTS.GUILD_MEMBER(guildId),
      accessToken
    );

    return member.roles;
  } catch {
    return null;
  }
}

/**
 * Validate Discord access token
 */
export async function validateDiscordToken(token: string): Promise<boolean> {
  try {
    const response = await fetch(DISCORD_OAUTH_ENDPOINTS.USER, {
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
 * Generate bot invite URL
 */
export function getDiscordBotInviteURL(
  options: {
    clientId?: string;
    permissions?: bigint;
    scopes?: string[];
    guildId?: string;
    disableGuildSelect?: boolean;
  } = {}
): string {
  const config = getDiscordOAuthConfig();
  const clientId = options.clientId || config.clientId;

  const params = new URLSearchParams({
    client_id: clientId,
    scope: (options.scopes || ["bot", "applications.commands"]).join(" "),
  });

  if (options.permissions !== undefined) {
    params.set("permissions", options.permissions.toString());
  }
  if (options.guildId) {
    params.set("guild_id", options.guildId);
  }
  if (options.disableGuildSelect) {
    params.set("disable_guild_select", "true");
  }

  return `${DISCORD_OAUTH_ENDPOINTS.AUTHORIZE}?${params.toString()}`;
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
 * Reset cached configuration (useful for testing)
 */
export function resetDiscordOAuthConfig(): void {
  configCache = null;
}

/**
 * Calculate permission integer from permission names
 */
export function calculatePermissions(
  permissions: (keyof typeof DiscordPermissions)[]
): bigint {
  return permissions.reduce((acc, perm) => acc | DiscordPermissions[perm], 0n);
}
