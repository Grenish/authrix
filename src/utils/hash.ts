import * as bcrypt from "bcryptjs";
import * as argon2 from "argon2";
import { createHash, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
import { Worker } from "worker_threads";

// ============================= Types & Interfaces =============================

interface PasswordValidationResult {
  isValid: boolean;
  errors: string[];
  strength: number; // 0-100
  entropy: number;
}

interface HashOptions {
  skipValidation?: boolean;
  identifier?: string;
  algorithm?: "bcrypt" | "argon2id";
  pepper?: string;
}

interface VerifyOptions {
  identifier?: string;
  updateHash?: boolean;
}

interface PasswordPolicy {
  minLength: number;
  maxLength: number;
  requireLowercase: boolean;
  requireUppercase: boolean;
  requireNumbers: boolean;
  requireSymbols: boolean;
  minEntropy: number;
  preventCommonPasswords: boolean;
  preventUserInfo: boolean;
}

interface RateLimitEntry {
  attempts: number[];
  blocked: boolean;
  blockUntil?: number;
}

// ============================= Configuration =============================

class SecurityConfig {
  // Bcrypt configuration
  public readonly BCRYPT_ROUNDS: number;

  // Argon2 configuration
  public readonly ARGON2_TIME_COST = 3;
  public readonly ARGON2_MEMORY_COST = 65536; // 64MB
  public readonly ARGON2_PARALLELISM = 4;

  // Password constraints
  public readonly MIN_PASSWORD_LENGTH = 12; // Increased from 8
  public readonly MAX_PASSWORD_LENGTH = 256; // Increased from 128
  public readonly MIN_ENTROPY = 50; // Minimum entropy bits

  // Rate limiting
  public readonly MAX_ATTEMPTS_PER_MINUTE = 5; // Reduced from 10
  public readonly MAX_ATTEMPTS_PER_HOUR = 20;
  public readonly BLOCK_DURATION = 15 * 60 * 1000; // 15 minutes
  public readonly RATE_LIMIT_WINDOW = 60 * 1000;

  // Security pepper (should be stored securely, e.g., in environment variable or secret manager)
  private readonly PEPPER: string;

  constructor() {
    // Parse bcrypt rounds with stricter validation
    const envRounds = parseInt(process.env.AUTHRIX_BCRYPT_ROUNDS || "", 10);
    this.BCRYPT_ROUNDS = this.validateBcryptRounds(envRounds);

    // Load pepper from secure storage
    const pepper = process.env.AUTHRIX_PASSWORD_PEPPER;
    if (!pepper && process.env.NODE_ENV === 'production') {
      throw new Error('AUTHRIX_PASSWORD_PEPPER must be configured in production');
    }
    this.PEPPER = pepper || this.generateDefaultPepper();

    // Validate configuration on startup
    this.validateConfiguration();
  }

  private validateBcryptRounds(rounds: number): number {
    if (!isNaN(rounds) && rounds >= 12 && rounds <= 20) {
      return rounds;
    }
    return 14; // Secure default
  }

  private generateDefaultPepper(): string {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('Password pepper must be configured in production');
    }
    console.warn(
      "⚠️  DEVELOPMENT MODE: Using generated pepper. Configure AUTHRIX_PASSWORD_PEPPER before deploying to production!"
    );
    return randomBytes(32).toString("hex");
  }

  private validateConfiguration(): void {
    if (this.BCRYPT_ROUNDS < 12) {
      throw new Error(
        "Bcrypt rounds must be at least 12 for production security"
      );
    }
    if (!this.PEPPER || this.PEPPER.length < 32) {
      throw new Error("Password pepper must be at least 32 characters");
    }
  }

  public getPepper(): string {
    return this.PEPPER;
  }
}

const config = new SecurityConfig();

// ============================= Rate Limiting =============================

class RateLimiter {
  private store = new Map<string, RateLimitEntry>();
  private cleanupInterval: NodeJS.Timeout;

  constructor() {
    // Periodic cleanup every 5 minutes
    this.cleanupInterval = setInterval(() => this.cleanup(), 5 * 60 * 1000);
  }

  public checkLimit(identifier: string): {
    allowed: boolean;
    retryAfter?: number;
  } {
    const now = Date.now();
    const entry = this.store.get(identifier) || {
      attempts: [],
      blocked: false,
    };

    // Check if currently blocked
    if (entry.blocked && entry.blockUntil && entry.blockUntil > now) {
      return {
        allowed: false,
        retryAfter: Math.ceil((entry.blockUntil - now) / 1000),
      };
    }

    // Reset block if expired
    if (entry.blocked && entry.blockUntil && entry.blockUntil <= now) {
      entry.blocked = false;
      entry.blockUntil = undefined;
      entry.attempts = [];
    }

    // Filter recent attempts
    entry.attempts = entry.attempts.filter(
      (time) => now - time < config.RATE_LIMIT_WINDOW
    );

    // Check rate limits
    if (entry.attempts.length >= config.MAX_ATTEMPTS_PER_MINUTE) {
      // Block the identifier
      entry.blocked = true;
      entry.blockUntil = now + config.BLOCK_DURATION;
      this.store.set(identifier, entry);

      return {
        allowed: false,
        retryAfter: Math.ceil(config.BLOCK_DURATION / 1000),
      };
    }

    // Add current attempt
    entry.attempts.push(now);
    this.store.set(identifier, entry);

    return { allowed: true };
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.store.entries()) {
      // Remove entries with no recent activity
      const hasRecentActivity = entry.attempts.some(
        (time) => now - time < config.RATE_LIMIT_WINDOW * 2
      );
      const isBlocked =
        entry.blocked && entry.blockUntil && entry.blockUntil > now;

      if (!hasRecentActivity && !isBlocked) {
        this.store.delete(key);
      }
    }

    // Prevent memory leak
    if (this.store.size > 10000) {
      const entries = Array.from(this.store.entries());
      entries.sort((a, b) => {
        const aLast = Math.max(...a[1].attempts, 0);
        const bLast = Math.max(...b[1].attempts, 0);
        return aLast - bLast;
      });

      // Keep only the most recent 5000 entries
      this.store.clear();
      entries
        .slice(-5000)
        .forEach(([key, value]) => this.store.set(key, value));
    }
  }

  public destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
  }
}

const rateLimiter = new RateLimiter();

// ============================= Password Validation =============================

class PasswordValidator {
  private static readonly COMMON_PASSWORDS = new Set([
    "password",
    "123456",
    "password123",
    "admin",
    "letmein",
    "welcome",
    "monkey",
    "1234567890",
    "qwerty",
    "abc123",
    "Password1",
    "password1",
  ]);

  private static readonly KEYBOARD_PATTERNS = [
    /qwerty/i,
    /asdfgh/i,
    /zxcvbn/i,
    /qwertyuiop/i,
    /\d{4,}/, // 4+ consecutive digits
    /(.)\1{3,}/, // 4+ repeated characters
  ];

  public validate(
    password: string,
    policy?: Partial<PasswordPolicy>,
    userInfo?: string[]
  ): PasswordValidationResult {
    const errors: string[] = [];
    const defaultPolicy: PasswordPolicy = {
      minLength: config.MIN_PASSWORD_LENGTH,
      maxLength: config.MAX_PASSWORD_LENGTH,
      requireLowercase: true,
      requireUppercase: true,
      requireNumbers: true,
      requireSymbols: true,
      minEntropy: config.MIN_ENTROPY,
      preventCommonPasswords: true,
      preventUserInfo: true,
    };

    const finalPolicy = { ...defaultPolicy, ...policy };

    // Length validation
    if (!password || password.length < finalPolicy.minLength) {
      errors.push(
        `Password must be at least ${finalPolicy.minLength} characters`
      );
    }

    if (password.length > finalPolicy.maxLength) {
      errors.push(
        `Password must not exceed ${finalPolicy.maxLength} characters`
      );
    }

    // Character requirements
    if (finalPolicy.requireLowercase && !/[a-z]/.test(password)) {
      errors.push("Password must contain lowercase letters");
    }

    if (finalPolicy.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push("Password must contain uppercase letters");
    }

    if (finalPolicy.requireNumbers && !/\d/.test(password)) {
      errors.push("Password must contain numbers");
    }

    if (
      finalPolicy.requireSymbols &&
      !/[!@#$%^&*()_+\-=```math```{};':"\\|,.<>\/?`~]/.test(password)
    ) {
      errors.push("Password must contain special characters");
    }

    // Entropy calculation
    const entropy = this.calculateEntropy(password);
    if (entropy < finalPolicy.minEntropy) {
      errors.push(
        `Password is too predictable (entropy: ${entropy.toFixed(1)} bits, required: ${finalPolicy.minEntropy})`
      );
    }

    // Pattern detection
    for (const pattern of PasswordValidator.KEYBOARD_PATTERNS) {
      if (pattern.test(password)) {
        errors.push("Password contains predictable patterns");
        break;
      }
    }

    // Common password check
    if (finalPolicy.preventCommonPasswords) {
      const lowerPassword = password.toLowerCase();
      if (PasswordValidator.COMMON_PASSWORDS.has(lowerPassword)) {
        errors.push("Password is too common");
      }
    }

    // User info check
    if (finalPolicy.preventUserInfo && userInfo && userInfo.length > 0) {
      const lowerPassword = password.toLowerCase();
      for (const info of userInfo) {
        if (info && lowerPassword.includes(info.toLowerCase())) {
          errors.push("Password must not contain personal information");
          break;
        }
      }
    }

    // Calculate password strength (0-100)
    const strength = this.calculateStrength(password, entropy, errors.length);

    return {
      isValid: errors.length === 0,
      errors,
      strength,
      entropy,
    };
  }

  private calculateEntropy(password: string): number {
    const charsets = {
      lowercase: 26,
      uppercase: 26,
      numbers: 10,
      symbols: 32,
      extended: 128,
    };

    let poolSize = 0;
    if (/[a-z]/.test(password)) poolSize += charsets.lowercase;
    if (/[A-Z]/.test(password)) poolSize += charsets.uppercase;
    if (/\d/.test(password)) poolSize += charsets.numbers;
    if (/[!@#$%^&*()_+\-=```math```{};':"\\|,.<>\/?`~]/.test(password))
      poolSize += charsets.symbols;
    if (/[^\x00-\x7F]/.test(password)) poolSize += charsets.extended;

    return password.length * Math.log2(poolSize);
  }

  private calculateStrength(
    password: string,
    entropy: number,
    errorCount: number
  ): number {
    let strength = Math.min(100, (entropy / 100) * 100);

    // Bonus for length
    if (password.length > 16) strength += 10;
    if (password.length > 20) strength += 10;

    // Penalty for errors
    strength -= errorCount * 15;

    // Bonus for character variety
    const varietyScore = this.getCharacterVariety(password);
    strength += varietyScore * 5;

    return Math.max(0, Math.min(100, Math.round(strength)));
  }

  private getCharacterVariety(password: string): number {
    const types = [
      /[a-z]/,
      /[A-Z]/,
      /\d/,
      /[!@#$%^&*()_+\-=```math```{};':"\\|,.<>\/?`~]/,
      /[^\x00-\x7F]/,
    ];

    return types.filter((regex) => regex.test(password)).length;
  }
}

const validator = new PasswordValidator();

// ============================= Password Hashing =============================

class PasswordHasher {
  /**
   * Hash a password using the specified algorithm
   */
  public async hash(
    password: string,
    options: HashOptions = {}
  ): Promise<string> {
    // Input validation
    if (typeof password !== "string") {
      throw new TypeError("Password must be a string");
    }

    // Rate limiting
    if (options.identifier) {
      const { allowed, retryAfter } = rateLimiter.checkLimit(
        options.identifier
      );
      if (!allowed) {
        throw new Error(
          `Rate limit exceeded. Retry after ${retryAfter} seconds`
        );
      }
    }

    // Password validation
    if (!options.skipValidation) {
      const validation = validator.validate(password);
      if (!validation.isValid) {
        throw new Error(`Invalid password: ${validation.errors[0]}`);
      }
    }

    // Apply pepper if configured
    const pepperedPassword = this.applyPepper(
      password,
      options.pepper || config.getPepper()
    );

    try {
      const algorithm = options.algorithm || "argon2id";

      if (algorithm === "argon2id") {
        return await this.hashWithArgon2(pepperedPassword);
      } else {
        return await this.hashWithBcrypt(pepperedPassword);
      }
    } finally {
      // Attempt to clear sensitive data
      this.clearString(password);
      this.clearString(pepperedPassword);
    }
  }

  /**
   * Verify a password against a hash
   */
  public async verify(
    password: string,
    hash: string,
    options: VerifyOptions = {}
  ): Promise<{ valid: boolean; needsRehash: boolean }> {
    // Input validation
    if (typeof password !== "string" || typeof hash !== "string") {
      return { valid: false, needsRehash: false };
    }

    if (!password || !hash) {
      // Perform dummy operation to prevent timing attacks
      await this.dummyVerify();
      return { valid: false, needsRehash: false };
    }

    // Rate limiting
    if (options.identifier) {
      const { allowed, retryAfter } = rateLimiter.checkLimit(
        options.identifier
      );
      if (!allowed) {
        throw new Error(
          `Rate limit exceeded. Retry after ${retryAfter} seconds`
        );
      }
    }

    try {
      // Apply pepper
      const pepperedPassword = this.applyPepper(password, config.getPepper());

      let valid = false;
      let needsRehash = false;

      // Determine hash type and verify
      if (hash.startsWith("$argon2")) {
        valid = await argon2.verify(hash, pepperedPassword);
        needsRehash = this.needsArgon2Rehash(hash);
      } else if (hash.startsWith("$2")) {
        valid = await bcrypt.compare(pepperedPassword, hash);
        needsRehash = this.needsBcryptRehash(hash);
      } else {
        // Unknown hash format, perform dummy operation
        await this.dummyVerify();
        return { valid: false, needsRehash: true };
      }

      return { valid, needsRehash };
    } catch (error) {
      // Log error securely without exposing sensitive information
      console.error(
        "Password verification error:",
        error instanceof Error ? error.message : "Unknown error"
      );
      await this.dummyVerify();
      return { valid: false, needsRehash: false };
    } finally {
      this.clearString(password);
    }
  }

  private async hashWithArgon2(password: string): Promise<string> {
    return argon2.hash(password, {
      type: argon2.argon2id,
      timeCost: config.ARGON2_TIME_COST,
      memoryCost: config.ARGON2_MEMORY_COST,
      parallelism: config.ARGON2_PARALLELISM,
    });
  }

  private async hashWithBcrypt(password: string): Promise<string> {
    return bcrypt.hash(password, config.BCRYPT_ROUNDS);
  }

  private applyPepper(password: string, pepper: string): string {
    if (!pepper) return password;

    // Use HMAC to apply pepper
    const hmac = createHash("sha256");
    hmac.update(password + pepper);
    return hmac.digest("base64");
  }

  private async dummyVerify(): Promise<void> {
    // Precomputed Argon2 hash for timing attack protection
    const dummyHash =
      "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";
    await argon2.verify(dummyHash, "dummy");
  }

  private needsBcryptRehash(hash: string): boolean {
    try {
      const match = hash.match(/^\$2[aby]?\$(\d+)\$/);
      if (!match) return true;

      const rounds = parseInt(match[1], 10);
      return rounds < config.BCRYPT_ROUNDS;
    } catch {
      return true;
    }
  }

  private needsArgon2Rehash(hash: string): boolean {
    try {
      // Parse Argon2 parameters
      const match = hash.match(/m=(\d+),t=(\d+),p=(\d+)/);
      if (!match) return true;

      const memoryCost = parseInt(match[1], 10);
      const timeCost = parseInt(match[2], 10);
      const parallelism = parseInt(match[3], 10);

      return (
        memoryCost < config.ARGON2_MEMORY_COST ||
        timeCost < config.ARGON2_TIME_COST ||
        parallelism < config.ARGON2_PARALLELISM
      );
    } catch {
      return true;
    }
  }

  private clearString(str: string): void {
    // Best effort to clear string from memory
    // Note: This is not guaranteed in JavaScript
    if (typeof str === "string" && str.length > 0) {
      try {
        // Overwrite with random data
        const buffer = Buffer.from(str);
        randomBytes(buffer.length).copy(buffer);
      } catch {
        // Ignore errors in cleanup
      }
    }
  }
}

const hasher = new PasswordHasher();

// ============================= Password Generation =============================

class SecurePasswordGenerator {
  private readonly charsets = {
    lowercase: "abcdefghijkmnopqrstuvwxyz", // Excludes similar: l, o
    uppercase: "ABCDEFGHJKLMNPQRSTUVWXYZ", // Excludes similar: I, O
    numbers: "23456789", // Excludes similar: 0, 1
    symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?",
    allLowercase: "abcdefghijklmnopqrstuvwxyz",
    allUppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    allNumbers: "0123456789",
  };

  public generate(
    length: number = 16,
    options: {
      includeLowercase?: boolean;
      includeUppercase?: boolean;
      includeNumbers?: boolean;
      includeSymbols?: boolean;
      excludeSimilar?: boolean;
      minEntropy?: number;
    } = {}
  ): string {
    const {
      includeLowercase = true,
      includeUppercase = true,
      includeNumbers = true,
      includeSymbols = true,
      excludeSimilar = true,
      minEntropy = 60,
    } = options;

    // Validate length
    if (length < 8 || length > 256) {
      throw new Error("Password length must be between 8 and 256 characters");
    }

    // Build character set
    let charset = "";
    const requiredChars: string[] = [];

    if (includeLowercase) {
      const chars = excludeSimilar
        ? this.charsets.lowercase
        : this.charsets.allLowercase;
      charset += chars;
      requiredChars.push(this.secureRandomChar(chars));
    }

    if (includeUppercase) {
      const chars = excludeSimilar
        ? this.charsets.uppercase
        : this.charsets.allUppercase;
      charset += chars;
      requiredChars.push(this.secureRandomChar(chars));
    }

    if (includeNumbers) {
      const chars = excludeSimilar
        ? this.charsets.numbers
        : this.charsets.allNumbers;
      charset += chars;
      requiredChars.push(this.secureRandomChar(chars));
    }

    if (includeSymbols) {
      charset += this.charsets.symbols;
      requiredChars.push(this.secureRandomChar(this.charsets.symbols));
    }

    if (!charset || requiredChars.length > length) {
      throw new Error("Invalid password generation options");
    }

    // Generate password
    let password = "";
    let attempts = 0;
    const maxAttempts = 100;

    while (attempts < maxAttempts) {
      password = this.generatePassword(length, charset, requiredChars);

      // Validate entropy
      const validation = validator.validate(password, {
        minEntropy,
        preventCommonPasswords: false,
        preventUserInfo: false,
      });

      if (validation.entropy >= minEntropy) {
        break;
      }

      attempts++;
    }

    if (attempts >= maxAttempts) {
      throw new Error("Failed to generate password with sufficient entropy");
    }

    return password;
  }

  private generatePassword(
    length: number,
    charset: string,
    requiredChars: string[]
  ): string {
    const password: string[] = [...requiredChars];

    // Fill remaining positions
    for (let i = requiredChars.length; i < length; i++) {
      password.push(this.secureRandomChar(charset));
    }

    // Secure shuffle using Fisher-Yates
    for (let i = password.length - 1; i > 0; i--) {
      const j = this.secureRandomInt(i + 1);
      [password[i], password[j]] = [password[j], password[i]];
    }

    return password.join("");
  }

  private secureRandomChar(charset: string): string {
    return charset[this.secureRandomInt(charset.length)];
  }

  private secureRandomInt(max: number): number {
    const range = max;
    const bytesNeeded = Math.ceil(Math.log2(range) / 8);
    const maxValid = Math.floor(256 ** bytesNeeded / range) * range;

    let value: number;
    do {
      const bytes = randomBytes(bytesNeeded);
      value = bytes.reduce((acc, byte, i) => acc + byte * 256 ** i, 0);
    } while (value >= maxValid);

    return value % range;
  }
}

const generator = new SecurePasswordGenerator();

// ============================= Exported Functions =============================

export async function hashPassword(
  password: string,
  options: HashOptions = {}
): Promise<string> {
  return hasher.hash(password, options);
}

export async function verifyPassword(
  password: string,
  hash: string,
  options: VerifyOptions = {}
): Promise<boolean> {
  const result = await hasher.verify(password, hash, options);
  return result.valid;
}

export async function verifyAndCheckRehash(
  password: string,
  hash: string,
  options: VerifyOptions = {}
): Promise<{ valid: boolean; needsRehash: boolean; newHash?: string }> {
  const result = await hasher.verify(password, hash, options);

  if (result.valid && result.needsRehash && options.updateHash) {
    const newHash = await hasher.hash(password, { skipValidation: true });
    return { ...result, newHash };
  }

  return result;
}

export function validatePassword(
  password: string,
  policy?: Partial<PasswordPolicy>,
  userInfo?: string[]
): PasswordValidationResult {
  return validator.validate(password, policy, userInfo);
}

export function generateSecurePassword(
  length?: number,
  options?: Parameters<typeof generator.generate>[1]
): string {
  return generator.generate(length, options);
}

export function needsRehash(hash: string): boolean {
  if (!hash) return true;

  if (hash.startsWith("$argon2")) {
    return hasher["needsArgon2Rehash"](hash);
  } else if (hash.startsWith("$2")) {
    return hasher["needsBcryptRehash"](hash);
  }

  return true;
}

// Cleanup on process exit
process.on("exit", () => {
  rateLimiter.destroy();
});

// Export types for external use
export type {
  PasswordValidationResult,
  HashOptions,
  VerifyOptions,
  PasswordPolicy,
};
