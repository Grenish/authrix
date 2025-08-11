import { authConfig } from "../config";
import { hashPassword, validatePassword } from "../utils/hash";
import { createToken } from "../tokens/createToken";
import { BadRequestError, ConflictError } from "../utils/errors";
import type { Response } from "express";

export interface SignupOptions {
  requireEmailVerification?: boolean;
  autoSignin?: boolean;
  includeUserProfile?: boolean;
  customUserData?: Record<string, any>;
  skipPasswordValidation?: boolean;
  generateUsername?: boolean;
  // New optional profile fields for account creation
  username?: string;
  firstName?: string;
  lastName?: string;
  fullName?: string;
  profilePicture?: string;
}

export interface SignupResult {
  user: {
    id: string;
    email: string;
    username?: string;
    firstName?: string;
    lastName?: string;
  fullName?: string;
  profilePicture?: string;
    emailVerified?: boolean;
    createdAt?: Date;
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
  requiresEmailVerification?: boolean;
}

// Rate limiting for signup attempts (simple in-memory store)
const signupAttempts = new Map<string, { count: number; lastAttempt: number }>();
const MAX_SIGNUP_ATTEMPTS_PER_HOUR = 3;
const SIGNUP_RATE_LIMIT_WINDOW = 60 * 60 * 1000; // 1 hour

/**
 * Check signup rate limiting by IP or email
 */
function checkSignupRateLimit(identifier: string): boolean {
  const now = Date.now();
  const attempts = signupAttempts.get(identifier);

  if (!attempts) {
    signupAttempts.set(identifier, { count: 1, lastAttempt: now });
    return true;
  }

  // Reset counter if window has passed
  if (now - attempts.lastAttempt > SIGNUP_RATE_LIMIT_WINDOW) {
    signupAttempts.set(identifier, { count: 1, lastAttempt: now });
    return true;
  }

  // Check if under limit
  if (attempts.count < MAX_SIGNUP_ATTEMPTS_PER_HOUR) {
    attempts.count++;
    attempts.lastAttempt = now;
    return true;
  }

  return false;
}

/**
 * Generate a unique username from email
 */
async function generateUniqueUsername(email: string, db: any): Promise<string> {
  const baseUsername = email.split('@')[0].toLowerCase().replace(/[^a-z0-9]/g, '');
  let username = baseUsername;
  let counter = 1;

  // Check if username exists and generate unique one
  while (db.findUserByUsername) {
    try {
      const existingUser = await db.findUserByUsername(username);
      if (!existingUser) {
        break;
      }
      username = `${baseUsername}${counter}`;
      counter++;
    } catch (error) {
      // If findUserByUsername not implemented, just use base username
      break;
    }
  }

  return username;
}

/**
 * Framework-agnostic signup function with enhanced features
 */
export async function signupCore(
  email: string,
  password: string,
  options: SignupOptions = {}
): Promise<SignupResult> {
  const {
    requireEmailVerification = false,
    autoSignin = true,
    includeUserProfile = true,
    customUserData = {},
    skipPasswordValidation = false,
  generateUsername = false,
  username,
  firstName,
  lastName,
  fullName,
  profilePicture,
  } = options;

  // Input validation
  if (!email?.trim()) {
    throw new BadRequestError("Email is required");
  }

  if (!password?.trim()) {
    throw new BadRequestError("Password is required");
  }

  const normalizedEmail = email.toLowerCase().trim();

  // Email format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(normalizedEmail)) {
    throw new BadRequestError("Invalid email format");
  }

  // Enhanced password validation (unless skipped for backward compatibility)
  if (!skipPasswordValidation) {
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      throw new BadRequestError(`Password validation failed: ${passwordValidation.errors.join(', ')}`);
    }
  } else {
    // Basic validation for backward compatibility
    if (password.length < 6) {
      throw new BadRequestError("Password must be at least 6 characters long");
    }
  }

  // Rate limiting check
  if (!checkSignupRateLimit(normalizedEmail)) {
    throw new BadRequestError("Too many signup attempts. Please try again later.");
  }

  // Check database configuration
  const db = authConfig.db;
  if (!db) {
    throw new Error("Database not configured. Make sure initAuth() is called before using authentication functions.");
  }

  try {
    // Check if user already exists
    const existingUser = await db.findUserByEmail(normalizedEmail);
    if (existingUser) {
      throw new ConflictError("An account with this email already exists");
    }

    // Hash password
    const hashedPassword = await hashPassword(password, {
      skipValidation: skipPasswordValidation,
      identifier: normalizedEmail
    });

    // Prepare user data
    const userData: any = {
      email: normalizedEmail,
      password: hashedPassword,
      emailVerified: !requireEmailVerification, // Auto-verify if not required
      createdAt: new Date(),
      ...customUserData
    };

    // Apply requested profile fields
    if (typeof username === 'string' && username.trim()) {
      userData.username = username.trim();
    }
    if (typeof firstName === 'string' && firstName.trim()) {
      userData.firstName = firstName.trim();
    }
    if (typeof lastName === 'string' && lastName.trim()) {
      userData.lastName = lastName.trim();
    }
    if (typeof fullName === 'string' && fullName.trim()) {
      userData.fullName = fullName.trim();
    }
    if (typeof profilePicture === 'string' && profilePicture.trim()) {
      userData.profilePicture = profilePicture.trim();
    }

    // Generate username if requested and not provided
    if (generateUsername && !userData.username) {
      userData.username = await generateUniqueUsername(normalizedEmail, db);
    }

    // Set email verification timestamp if auto-verified
    if (!requireEmailVerification) {
      userData.emailVerifiedAt = new Date();
    }

    // Create user
    const user = await db.createUser(userData);

    // Create token payload
    const tokenPayload: any = {
      id: user.id,
      email: user.email
    };

    // Add additional claims if available
    if (user.username) tokenPayload.username = user.username;
    if (user.emailVerified) tokenPayload.emailVerified = user.emailVerified;

    // Create JWT token
    const token = createToken(tokenPayload);

    // Build user response object
    const userResponse: SignupResult['user'] = {
      id: user.id,
      email: user.email,
      createdAt: user.createdAt,
    };

    // Include additional profile data if requested
    if (includeUserProfile) {
      if (user.username) userResponse.username = user.username;
      if (user.firstName) userResponse.firstName = user.firstName;
      if (user.lastName) userResponse.lastName = user.lastName;
      if (user.fullName) userResponse.fullName = user.fullName;
      if (user.profilePicture) userResponse.profilePicture = user.profilePicture;
      if (typeof user.emailVerified === 'boolean') {
        userResponse.emailVerified = user.emailVerified;
      }
    }

    return {
      user: userResponse,
      token,
      cookieOptions: {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
        sameSite: "lax" as const,
        path: "/",
      },
      isNewUser: true,
      requiresEmailVerification: requireEmailVerification
    };

  } catch (error) {
    // Log failed attempt for monitoring
    if (process.env.NODE_ENV === 'development') {
      console.debug('[AUTHRIX] Signup failed:', {
        email: normalizedEmail,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }

    // Re-throw the error to be handled by the caller
    throw error;
  }
}

/**
 * Express.js specific signup function for backward compatibility
 */
export async function signup(
  email: string,
  password: string,
  res: Response,
  options?: SignupOptions
): Promise<SignupResult['user']> {
  const result = await signupCore(email, password, options);

  // Set authentication cookie if auto-signin is enabled
  if (options?.autoSignin !== false) {
    res.cookie(authConfig.cookieName, result.token, result.cookieOptions);
  }

  return result.user;
}

/**
 * Validate signup data without creating user (useful for client-side validation)
 */
export async function validateSignupData(email: string, password: string): Promise<{
  isValid: boolean;
  errors: string[];
}> {
  const errors: string[] = [];

  // Email validation
  if (!email?.trim()) {
    errors.push("Email is required");
  } else {
    const normalizedEmail = email.toLowerCase().trim();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(normalizedEmail)) {
      errors.push("Invalid email format");
    } else {
      // Check if email already exists
      const db = authConfig.db;
      if (db) {
        try {
          const existingUser = await db.findUserByEmail(normalizedEmail);
          if (existingUser) {
            errors.push("An account with this email already exists");
          }
        } catch (error) {
          // Don't fail validation if database check fails
          console.warn('[AUTHRIX] Could not check email existence during validation:', error);
        }
      }
    }
  }

  // Password validation
  if (!password?.trim()) {
    errors.push("Password is required");
  } else {
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      errors.push(...passwordValidation.errors);
    }
  }

  return {
    isValid: errors.length === 0,
    errors
  };
}
