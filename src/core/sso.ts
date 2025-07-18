import { randomBytes, randomUUID } from "crypto";
import { authConfig } from "../config";
import { createToken } from "../tokens/createToken";
import { generateSecurePassword } from "../utils/hash";

export interface SSOUser {
  id: string;
  email: string;
  name?: string;
  firstName?: string;
  lastName?: string;
  avatar?: string;
  provider: string;
  verified?: boolean;
  locale?: string;
  [key: string]: any;
}

export interface SSOOptions {
  autoCreateUser?: boolean;
  updateExistingUser?: boolean;
  requireVerifiedEmail?: boolean;
  mergeUserData?: boolean;
  customUserMapping?: (ssoUser: SSOUser) => Partial<any>;
}

export interface SSOResult {
  user: {
    id: string;
    email: string;
    username?: string;
    firstName?: string;
    lastName?: string;
  };
  token: string;
  cookieOptions: {
    httpOnly: boolean;
    secure: boolean;
    maxAge: number;
    sameSite: "lax" | "strict" | "none";
    path: string;
  };
  isNewUser: boolean;
  provider: string;
}

/**
 * Process SSO authentication and create/update user
 */
export async function processSSOAuthentication(
  ssoUser: SSOUser,
  options: SSOOptions = {}
): Promise<SSOResult> {
  const db = authConfig.db;
  
  if (!db) {
    throw new Error("Database not configured. Make sure initAuth() is called before using SSO functions.");
  }

  const {
    autoCreateUser = true,
    updateExistingUser = false,
    requireVerifiedEmail = true,
    mergeUserData = true,
    customUserMapping
  } = options;

  // Validate SSO user data
  if (!ssoUser.email) {
    throw new Error(`${ssoUser.provider} SSO did not provide email address`);
  }

  if (!ssoUser.id) {
    throw new Error(`${ssoUser.provider} SSO did not provide user ID`);
  }

  if (requireVerifiedEmail && ssoUser.verified === false) {
    throw new Error(`${ssoUser.provider} SSO email is not verified`);
  }

  const normalizedEmail = ssoUser.email.toLowerCase().trim();
  
  // Check if user already exists
  let existingUser = await db.findUserByEmail(normalizedEmail);
  let isNewUser = false;

  if (existingUser) {
    // User exists - update if allowed
    if (updateExistingUser && mergeUserData) {
      const updateData: any = {};
      
      // Apply custom mapping if provided
      if (customUserMapping) {
        Object.assign(updateData, customUserMapping(ssoUser));
      } else {
        // Default mapping
        if (ssoUser.name && !existingUser.firstName && !existingUser.lastName) {
          const nameParts = ssoUser.name.split(' ');
          updateData.firstName = nameParts[0];
          if (nameParts.length > 1) {
            updateData.lastName = nameParts.slice(1).join(' ');
          }
        }
        
        if (ssoUser.firstName && !existingUser.firstName) {
          updateData.firstName = ssoUser.firstName;
        }
        
        if (ssoUser.lastName && !existingUser.lastName) {
          updateData.lastName = ssoUser.lastName;
        }

        // Generate username from email if not exists and provider supports it
        if (!existingUser.username && ssoUser.email) {
          const emailUsername = ssoUser.email.split('@')[0];
          // Make username unique if needed
          const baseUsername = emailUsername.toLowerCase().replace(/[^a-z0-9]/g, '');
          try {
            // Check if username exists
            const usernameExists = db.findUserByUsername && await db.findUserByUsername(baseUsername);
            if (!usernameExists) {
              updateData.username = baseUsername;
            } else {
              updateData.username = `${baseUsername}${Math.floor(Math.random() * 1000)}`;
            }
          } catch {
            // If findUserByUsername not implemented, skip username
          }
        }
      }

      if (Object.keys(updateData).length > 0 && db.updateUser) {
        existingUser = await db.updateUser(existingUser.id, updateData);
        if (!existingUser) {
          throw new Error('Failed to update user with SSO data');
        }
      }
    }
  } else {
    // User doesn't exist - create if allowed
    if (!autoCreateUser) {
      throw new Error(`No account found for ${normalizedEmail}. Please create an account first.`);
    }

    // Prepare user data for creation
    const userData: any = {
      email: normalizedEmail,
      password: generateSecurePassword(32), // Generate secure random password for SSO users
      emailVerified: requireVerifiedEmail ? (ssoUser.verified !== false) : true,
      emailVerifiedAt: requireVerifiedEmail && ssoUser.verified !== false ? new Date() : undefined,
    };

    // Apply custom mapping if provided
    if (customUserMapping) {
      Object.assign(userData, customUserMapping(ssoUser));
    } else {
      // Default mapping
      if (ssoUser.name) {
        const nameParts = ssoUser.name.split(' ');
        userData.firstName = nameParts[0];
        if (nameParts.length > 1) {
          userData.lastName = nameParts.slice(1).join(' ');
        }
      }

      if (ssoUser.firstName) {
        userData.firstName = ssoUser.firstName;
      }

      if (ssoUser.lastName) {
        userData.lastName = ssoUser.lastName;
      }

      // Generate username from email
      if (ssoUser.email) {
        const emailUsername = ssoUser.email.split('@')[0];
        const baseUsername = emailUsername.toLowerCase().replace(/[^a-z0-9]/g, '');
        try {
          // Check if username exists
          const usernameExists = db.findUserByUsername && await db.findUserByUsername(baseUsername);
          if (!usernameExists) {
            userData.username = baseUsername;
          } else {
            userData.username = `${baseUsername}${Math.floor(Math.random() * 1000)}`;
          }
        } catch {
          // If findUserByUsername not implemented, skip username
        }
      }
    }

    try {
      existingUser = await db.createUser(userData);
      isNewUser = true;
    } catch (error) {
      if (error instanceof Error && error.message.includes('already exists')) {
        // Race condition - user was created between our check and create
        existingUser = await db.findUserByEmail(normalizedEmail);
        if (!existingUser) {
          throw new Error('Failed to create or find user after SSO authentication');
        }
      } else {
        throw new Error(`Failed to create user: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
  }

  // Generate JWT token
  const tokenPayload: any = {
    id: existingUser.id,
    email: existingUser.email,
    provider: ssoUser.provider
  };

  // Add additional claims if available
  if (existingUser.username) {
    tokenPayload.username = existingUser.username;
  }

  const token = createToken(tokenPayload);

  return {
    user: {
      id: existingUser.id,
      email: existingUser.email,
      username: existingUser.username,
      firstName: existingUser.firstName,
      lastName: existingUser.lastName,
    },
    token,
    cookieOptions: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
      sameSite: "lax" as const,
      path: "/",
    },
    isNewUser,
    provider: ssoUser.provider
  };
}

/**
 * Handle Google OAuth authentication
 */
export async function handleGoogleSSO(
  code: string,
  options: SSOOptions = {}
): Promise<SSOResult> {
  try {
    // Dynamic import to avoid requiring OAuth dependencies
    const { handleGoogleCallback } = await import('../providers/google');
    const googleUser = await handleGoogleCallback(code);
    
    const ssoUser: SSOUser = {
      id: googleUser.id,
      email: googleUser.email,
      name: googleUser.name,
      avatar: googleUser.avatar,
      provider: 'google',
      verified: true // Google emails are always verified
    };

    return processSSOAuthentication(ssoUser, options);
  } catch (error) {
    throw new Error(`Google SSO failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Handle GitHub OAuth authentication
 */
export async function handleGitHubSSO(
  code: string,
  options: SSOOptions = {}
): Promise<SSOResult> {
  try {
    // Dynamic import to avoid requiring OAuth dependencies
    const { handleGitHubCallback } = await import('../providers/github');
    const githubUser = await handleGitHubCallback(code);
    
    const ssoUser: SSOUser = {
      id: githubUser.id,
      email: githubUser.email,
      name: githubUser.name,
      avatar: githubUser.avatar,
      provider: 'github',
      verified: true // GitHub emails are verified in the callback
    };

    return processSSOAuthentication(ssoUser, options);
  } catch (error) {
    throw new Error(`GitHub SSO failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Generic SSO handler for custom providers
 */
export async function handleCustomSSO(
  provider: string,
  userData: SSOUser,
  options: SSOOptions = {}
): Promise<SSOResult> {
  const ssoUser: SSOUser = {
    ...userData,
    provider
  };

  return processSSOAuthentication(ssoUser, options);
}

/**
 * Generate SSO state parameter for security
 */
export function generateSSOState(data?: any): string {
  const stateData = {
    timestamp: Date.now(),
    nonce: randomUUID(),
    ...data
  };

  return Buffer.from(JSON.stringify(stateData)).toString('base64url');
}

/**
 * Verify SSO state parameter
 */
export function verifySSOState(state: string, maxAge: number = 300000): any {
  try {
    const stateData = JSON.parse(Buffer.from(state, 'base64url').toString());
    
    if (!stateData.timestamp || !stateData.nonce) {
      throw new Error('Invalid state format');
    }

    if (Date.now() - stateData.timestamp > maxAge) {
      throw new Error('State has expired');
    }

    return stateData;
  } catch (error) {
    throw new Error(`Invalid SSO state: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}
