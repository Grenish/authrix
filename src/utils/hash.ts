import * as bcrypt from "bcryptjs";
import * as argon2 from "argon2";
import { createHash, randomBytes, timingSafeEqual, createHmac } from "crypto";
import { Worker } from "worker_threads";
import { promisify } from "util";
import { EventEmitter } from "events";

// Types & Interfaces

interface PasswordValidationResult {
  isValid: boolean;
  errors: string[];
  strength: number; // 0-100
  entropy: number;
  metadata?: {
    hasCompromisedPatterns: boolean;
    characterDiversity: number;
    sequentialCharacters: number;
  };
}

interface HashOptions {
  skipValidation?: boolean;
  identifier?: string;
  algorithm?: "bcrypt" | "argon2id";
  pepper?: string;
  metadata?: Record<string, unknown>;
}

interface VerifyOptions {
  identifier?: string;
  updateHash?: boolean;
  skipRateLimit?: boolean;
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
  preventSequentialPatterns: boolean;
  maxConsecutiveCharacters: number;
}

interface RateLimitEntry {
  attempts: number[];
  blocked: boolean;
  blockUntil?: number;
  consecutiveFailures: number;
}

interface SecurityMetrics {
  totalHashOperations: number;
  totalVerifyOperations: number;
  failedVerifications: number;
  rateLimitBlocks: number;
  rehashesPerformed: number;
  averageHashTime: number;
  averageVerifyTime: number;
}

// Security Event Emitter

class SecurityEventEmitter extends EventEmitter {
  public emitSecurityEvent(event: string, data: Record<string, unknown>): void {
    this.emit('security', { event, timestamp: Date.now(), ...data });
  }
}

const securityEvents = new SecurityEventEmitter();

// Configuration

import os from 'os';

class SecurityConfig {
  // Bcrypt configuration
  public readonly BCRYPT_ROUNDS: number;
  
  // Argon2 configuration
  public readonly ARGON2_TIME_COST: number;
  public readonly ARGON2_MEMORY_COST: number;
  public readonly ARGON2_PARALLELISM: number;
  public readonly ARGON2_SALT_LENGTH: number = 16;
  
  // Password constraints
  public readonly MIN_PASSWORD_LENGTH: number;
  public readonly MAX_PASSWORD_LENGTH: number = 256;
  public readonly MIN_ENTROPY: number;
  
  // Rate limiting
  public readonly MAX_ATTEMPTS_PER_MINUTE: number = 5;
  public readonly MAX_ATTEMPTS_PER_HOUR: number = 20;
  public readonly BLOCK_DURATION: number = 15 * 60 * 1000; // 15 minutes
  public readonly PROGRESSIVE_DELAY_ENABLED: boolean = true;
  
  // Security
  private readonly PEPPER: string;
  private readonly PEPPER_ROTATION_KEY?: string;
  public readonly USE_WORKER_THREADS: boolean;
  public readonly MAX_CONCURRENT_OPERATIONS: number;
  
  // Monitoring
  public readonly ENABLE_METRICS: boolean;
  public readonly METRICS_INTERVAL: number = 60000; // 1 minute

  constructor() {
    this.validateEnvironment();
    
    // Load configuration with production defaults
    this.BCRYPT_ROUNDS = this.loadIntConfig('AUTHRIX_BCRYPT_ROUNDS', 14, 12, 20);
    
    // Argon2 settings optimized for production
    this.ARGON2_TIME_COST = this.loadIntConfig('AUTHRIX_ARGON2_TIME_COST', 3, 2, 10);
    this.ARGON2_MEMORY_COST = this.loadIntConfig('AUTHRIX_ARGON2_MEMORY_COST', 65536, 32768, 1048576);
    this.ARGON2_PARALLELISM = this.loadIntConfig('AUTHRIX_ARGON2_PARALLELISM', 4, 1, 8);
    
    // Password policy
    this.MIN_PASSWORD_LENGTH = this.loadIntConfig('AUTHRIX_MIN_PASSWORD_LENGTH', 12, 8, 128);
    this.MIN_ENTROPY = this.loadIntConfig('AUTHRIX_MIN_ENTROPY', 50, 30, 100);
    
    // Performance settings
    this.USE_WORKER_THREADS = process.env.AUTHRIX_USE_WORKERS === 'true';
    this.MAX_CONCURRENT_OPERATIONS = this.loadIntConfig('AUTHRIX_MAX_CONCURRENT_OPS', 100, 10, 1000);
    
    // Monitoring
    this.ENABLE_METRICS = process.env.AUTHRIX_ENABLE_METRICS !== 'false';
    
    // Load pepper securely
    this.PEPPER = this.loadPepper();
    this.PEPPER_ROTATION_KEY = process.env.AUTHRIX_PEPPER_ROTATION_KEY;
    
    this.validateConfiguration();
  }

  private validateEnvironment(): void {
    if (process.env.NODE_ENV !== 'production' && !process.env.AUTHRIX_ALLOW_NON_PRODUCTION) {
      console.warn('[Security] Running in non-production mode. Set NODE_ENV=production for production use.');
    }
  }

  private loadIntConfig(key: string, defaultValue: number, min: number, max: number): number {
    const value = parseInt(process.env[key] || '', 10);
    if (isNaN(value)) return defaultValue;
    if (value < min || value > max) {
      throw new Error(`${key} must be between ${min} and ${max}`);
    }
    return value;
  }

  private loadPepper(): string {
    const pepper = process.env.AUTHRIX_PASSWORD_PEPPER;
    
    if (!pepper) {
      throw new Error('AUTHRIX_PASSWORD_PEPPER must be configured');
    }
    
    if (pepper.length < 32) {
      throw new Error('Password pepper must be at least 32 characters');
    }
    
    // Validate pepper format (should be hex or base64)
    if (!/^[a-fA-F0-9]{64,}$/.test(pepper) && !/^[A-Za-z0-9+/]+=*$/.test(pepper)) {
      throw new Error('Password pepper must be a valid hex or base64 string');
    }
    
    return pepper;
  }

  private validateConfiguration(): void {
    // Validate Argon2 memory doesn't exceed system limits
  const totalMemory = os.totalmem();
    const maxMemoryPerOperation = this.ARGON2_MEMORY_COST * 1024; // Convert KiB to bytes
    const maxConcurrentMemory = maxMemoryPerOperation * this.MAX_CONCURRENT_OPERATIONS;
    
    if (maxConcurrentMemory > totalMemory * 0.5) {
      console.warn('[Security] Argon2 memory settings may exhaust system memory under load');
    }
  }

  public getPepper(): string {
    return this.PEPPER;
  }

  public getRotationPepper(): string | undefined {
    return this.PEPPER_ROTATION_KEY;
  }
}

// ============================= Singleton Config Instance =============================

const config = new SecurityConfig();

// ============================= Metrics Collection =============================

class MetricsCollector {
  private metrics: SecurityMetrics = {
    totalHashOperations: 0,
    totalVerifyOperations: 0,
    failedVerifications: 0,
    rateLimitBlocks: 0,
    rehashesPerformed: 0,
    averageHashTime: 0,
    averageVerifyTime: 0,
  };

  private hashTimes: number[] = [];
  private verifyTimes: number[] = [];
  private readonly maxSamples = 1000;

  public recordHashOperation(duration: number): void {
    this.metrics.totalHashOperations++;
    this.hashTimes.push(duration);
    if (this.hashTimes.length > this.maxSamples) {
      this.hashTimes.shift();
    }
    this.updateAverages();
  }

  public recordVerifyOperation(duration: number, success: boolean): void {
    this.metrics.totalVerifyOperations++;
    if (!success) this.metrics.failedVerifications++;
    this.verifyTimes.push(duration);
    if (this.verifyTimes.length > this.maxSamples) {
      this.verifyTimes.shift();
    }
    this.updateAverages();
  }

  public recordRateLimitBlock(): void {
    this.metrics.rateLimitBlocks++;
  }

  public recordRehash(): void {
    this.metrics.rehashesPerformed++;
  }

  private updateAverages(): void {
    if (this.hashTimes.length > 0) {
      this.metrics.averageHashTime = 
        this.hashTimes.reduce((a, b) => a + b, 0) / this.hashTimes.length;
    }
    if (this.verifyTimes.length > 0) {
      this.metrics.averageVerifyTime = 
        this.verifyTimes.reduce((a, b) => a + b, 0) / this.verifyTimes.length;
    }
  }

  public getMetrics(): SecurityMetrics {
    return { ...this.metrics };
  }

  public reset(): void {
    this.metrics = {
      totalHashOperations: 0,
      totalVerifyOperations: 0,
      failedVerifications: 0,
      rateLimitBlocks: 0,
      rehashesPerformed: 0,
      averageHashTime: 0,
      averageVerifyTime: 0,
    };
    this.hashTimes = [];
    this.verifyTimes = [];
  }
}

const metricsCollector = config.ENABLE_METRICS ? new MetricsCollector() : null;

// ============================= Enhanced Rate Limiting =============================

class EnhancedRateLimiter {
  private store = new Map<string, RateLimitEntry>();
  private cleanupInterval: NodeJS.Timeout;
  private readonly maxStoreSize = 10000;
  
  constructor() {
    this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
    this.cleanupInterval.unref();
  }

  public async checkLimit(identifier: string): Promise<{
    allowed: boolean;
    retryAfter?: number;
    delayMs?: number;
  }> {
    const now = Date.now();
    const entry = this.store.get(identifier) || {
      attempts: [],
      blocked: false,
      consecutiveFailures: 0,
    };

    // Check if currently blocked
    if (entry.blocked && entry.blockUntil && entry.blockUntil > now) {
      metricsCollector?.recordRateLimitBlock();
      securityEvents.emitSecurityEvent('rate_limit_blocked', { identifier });
      return {
        allowed: false,
        retryAfter: Math.ceil((entry.blockUntil - now) / 1000),
      };
    }

    // Reset block if expired
    if (entry.blocked && entry.blockUntil && entry.blockUntil <= now) {
      entry.blocked = false;
      entry.blockUntil = undefined;
      entry.consecutiveFailures = 0;
    }

    // Filter attempts within the last minute
    entry.attempts = entry.attempts.filter(
      (time) => now - time < 60000
    );

    // Check rate limits
    if (entry.attempts.length >= config.MAX_ATTEMPTS_PER_MINUTE) {
      entry.blocked = true;
      entry.blockUntil = now + config.BLOCK_DURATION * Math.min(entry.consecutiveFailures + 1, 5);
      entry.consecutiveFailures++;
      this.store.set(identifier, entry);
      
      metricsCollector?.recordRateLimitBlock();
      securityEvents.emitSecurityEvent('rate_limit_exceeded', { 
        identifier, 
        attempts: entry.attempts.length 
      });

      return {
        allowed: false,
        retryAfter: Math.ceil((entry.blockUntil - now) / 1000),
      };
    }

    // Calculate progressive delay
    let delayMs = 0;
    if (config.PROGRESSIVE_DELAY_ENABLED && entry.attempts.length > 0) {
      delayMs = Math.min(Math.pow(2, entry.attempts.length) * 100, 5000);
    }

    // Add current attempt
    entry.attempts.push(now);
    this.store.set(identifier, entry);

    // Implement progressive delay
    if (delayMs > 0) {
      await this.delay(delayMs);
    }

    return { allowed: true, delayMs };
  }

  private async delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private cleanup(): void {
    const now = Date.now();
    const entries = Array.from(this.store.entries());
    
    // Remove expired entries
    for (const [key, entry] of entries) {
      const hasRecentActivity = entry.attempts.some(
        (time) => now - time < 120000 // 2 minutes
      );
      const isBlocked = entry.blocked && entry.blockUntil && entry.blockUntil > now;
      
      if (!hasRecentActivity && !isBlocked) {
        this.store.delete(key);
      }
    }

    // Prevent memory exhaustion
    if (this.store.size > this.maxStoreSize) {
      const sortedEntries = entries.sort((a, b) => {
        const aLast = Math.max(...a[1].attempts, 0);
        const bLast = Math.max(...b[1].attempts, 0);
        return aLast - bLast;
      });

      this.store.clear();
      sortedEntries
        .slice(-Math.floor(this.maxStoreSize / 2))
        .forEach(([key, value]) => this.store.set(key, value));
        
      securityEvents.emitSecurityEvent('rate_limit_cleanup', { 
        removed: sortedEntries.length - Math.floor(this.maxStoreSize / 2) 
      });
    }
  }

  public recordFailure(identifier: string): void {
    const entry = this.store.get(identifier);
    if (entry) {
      entry.consecutiveFailures++;
      this.store.set(identifier, entry);
    }
  }

  public clearFailures(identifier: string): void {
    const entry = this.store.get(identifier);
    if (entry) {
      entry.consecutiveFailures = 0;
      this.store.set(identifier, entry);
    }
  }

  public destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    this.store.clear();
  }
}

const rateLimiter = new EnhancedRateLimiter();

// ============================= Password Validation =============================

class PasswordValidator {
  private static readonly COMMON_PASSWORDS = new Set([
    // Extended list - in production, load from a file or database
    "password", "123456", "password123", "admin", "letmein", 
    "welcome", "monkey", "1234567890", "qwerty", "abc123",
    "Password1", "password1", "123456789", "welcome123",
    "admin123", "root", "toor", "pass", "p@ssw0rd", "passw0rd"
  ]);

  private static readonly KEYBOARD_PATTERNS = [
    /qwerty/i, /asdfgh/i, /zxcvbn/i, /qwertyuiop/i,
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
      preventSequentialPatterns: true,
      maxConsecutiveCharacters: 3,
    };

    const finalPolicy = { ...defaultPolicy, ...policy };
    const metadata = {
      hasCompromisedPatterns: false,
      characterDiversity: 0,
      sequentialCharacters: 0,
    };

    // Input validation
    if (!password || typeof password !== 'string') {
      errors.push('Password must be a non-empty string');
      return { isValid: false, errors, strength: 0, entropy: 0, metadata };
    }

    // Length validation
    if (password.length < finalPolicy.minLength) {
      errors.push(`Password must be at least ${finalPolicy.minLength} characters`);
    }
    if (password.length > finalPolicy.maxLength) {
      errors.push(`Password must not exceed ${finalPolicy.maxLength} characters`);
    }

    // Character requirements
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSymbol = /[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]/.test(password);

    if (finalPolicy.requireLowercase && !hasLower) {
      errors.push('Password must contain lowercase letters');
    }
    if (finalPolicy.requireUppercase && !hasUpper) {
      errors.push('Password must contain uppercase letters');
    }
    if (finalPolicy.requireNumbers && !hasNumber) {
      errors.push('Password must contain numbers');
    }
    if (finalPolicy.requireSymbols && !hasSymbol) {
      errors.push('Password must contain special characters');
    }

    // Calculate character diversity
    metadata.characterDiversity = [hasLower, hasUpper, hasNumber, hasSymbol].filter(Boolean).length;

    // Entropy calculation
    const entropy = this.calculateEntropy(password);
    if (entropy < finalPolicy.minEntropy) {
      errors.push(
        `Password is too weak (entropy: ${entropy.toFixed(1)} bits, required: ${finalPolicy.minEntropy})`
      );
    }

    // Pattern detection
    if (finalPolicy.preventSequentialPatterns) {
      const sequentialResult = this.detectSequentialPatterns(password, finalPolicy.maxConsecutiveCharacters);
      if (sequentialResult.hasPatterns) {
        errors.push('Password contains predictable patterns');
        metadata.hasCompromisedPatterns = true;
        metadata.sequentialCharacters = sequentialResult.maxSequence;
      }
    }

    // Common password check
    if (finalPolicy.preventCommonPasswords && this.isCommonPassword(password)) {
      errors.push('Password is too common');
      metadata.hasCompromisedPatterns = true;
    }

    // User info check
    if (finalPolicy.preventUserInfo && userInfo && userInfo.length > 0) {
      if (this.containsUserInfo(password, userInfo)) {
        errors.push('Password must not contain personal information');
      }
    }

    // Calculate strength
    const strength = this.calculateStrength(password, entropy, errors.length, metadata);

    return {
      isValid: errors.length === 0,
      errors,
      strength,
      entropy,
      metadata,
    };
  }

  private calculateEntropy(password: string): number {
    if (!password) return 0;

    const charsets = {
      lowercase: 26,
      uppercase: 26,
      numbers: 10,
      symbols: 32,
      unicode: 65536,
    };

    let poolSize = 0;
    if (/[a-z]/.test(password)) poolSize += charsets.lowercase;
    if (/[A-Z]/.test(password)) poolSize += charsets.uppercase;
    if (/\d/.test(password)) poolSize += charsets.numbers;
    if (/[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]/.test(password)) poolSize += charsets.symbols;
    if (/[^\x00-\x7F]/.test(password)) poolSize += charsets.unicode;

    if (poolSize === 0) return 0;

    // Check for repeated patterns
    const uniqueChars = new Set(password).size;
    const repetitionPenalty = uniqueChars / password.length;

    return password.length * Math.log2(poolSize) * repetitionPenalty;
  }

  private detectSequentialPatterns(password: string, maxConsecutive: number): {
    hasPatterns: boolean;
    maxSequence: number;
  } {
    let maxSequence = 0;
    let currentSequence = 1;

    // Check for keyboard patterns
    for (const pattern of PasswordValidator.KEYBOARD_PATTERNS) {
      if (pattern.test(password)) {
        return { hasPatterns: true, maxSequence: password.length };
      }
    }

    // Check for sequential characters
    for (let i = 1; i < password.length; i++) {
      const prevCode = password.charCodeAt(i - 1);
      const currCode = password.charCodeAt(i);
      
      if (Math.abs(currCode - prevCode) === 1) {
        currentSequence++;
        maxSequence = Math.max(maxSequence, currentSequence);
      } else {
        currentSequence = 1;
      }
    }

    // Check for repeated characters
    const repeatedMatch = password.match(/(.)\1+/g);
    if (repeatedMatch) {
      for (const match of repeatedMatch) {
        maxSequence = Math.max(maxSequence, match.length);
      }
    }

    return {
      hasPatterns: maxSequence > maxConsecutive,
      maxSequence,
    };
  }

  private isCommonPassword(password: string): boolean {
    const normalized = password.toLowerCase();
    
    // Check exact match
    if (PasswordValidator.COMMON_PASSWORDS.has(normalized)) {
      return true;
    }

    // Check variants (with common substitutions)
    const commonSubstitutions = normalized
      .replace(/[@]/g, 'a')
      .replace(/[0]/g, 'o')
      .replace(/[1!]/g, 'i')
      .replace(/[3]/g, 'e')
      .replace(/[$5]/g, 's');

    return PasswordValidator.COMMON_PASSWORDS.has(commonSubstitutions);
  }

  private containsUserInfo(password: string, userInfo: string[]): boolean {
    const normalized = password.toLowerCase();
    return userInfo.some(info => {
      if (!info || info.length < 3) return false;
      return normalized.includes(info.toLowerCase());
    });
  }

  private calculateStrength(
    password: string,
    entropy: number,
    errorCount: number,
    metadata: PasswordValidationResult['metadata']
  ): number {
    let strength = Math.min(100, (entropy / 128) * 100);

    // Bonuses
    if (password.length > 16) strength += 5;
    if (password.length > 24) strength += 5;
    if (metadata?.characterDiversity === 4) strength += 10;

    // Penalties
    strength -= errorCount * 15;
    if (metadata?.hasCompromisedPatterns) strength -= 20;
    if (metadata?.sequentialCharacters && metadata.sequentialCharacters > 3) {
      strength -= metadata.sequentialCharacters * 2;
    }

    return Math.max(0, Math.min(100, Math.round(strength)));
  }
}

const validator = new PasswordValidator();

// ============================= Password Hashing with Worker Thread Support =============================

class PasswordHasher {
  private readonly concurrencyLimiter: ConcurrencyLimiter;
  private workerPool?: WorkerPool;

  constructor() {
    this.concurrencyLimiter = new ConcurrencyLimiter(config.MAX_CONCURRENT_OPERATIONS);
    
    if (config.USE_WORKER_THREADS) {
      this.workerPool = new WorkerPool();
    }
  }

  public async hash(password: string, options: HashOptions = {}): Promise<string> {
    const startTime = Date.now();

    try {
      // Input validation
      if (typeof password !== 'string' || !password) {
        throw new TypeError('Password must be a non-empty string');
      }

      // Rate limiting
      if (options.identifier) {
        const { allowed, retryAfter } = await rateLimiter.checkLimit(options.identifier);
        if (!allowed) {
          securityEvents.emitSecurityEvent('hash_rate_limited', { identifier: options.identifier });
          throw new Error(`Rate limit exceeded. Retry after ${retryAfter} seconds`);
        }
      }

      // Password validation
      if (!options.skipValidation) {
        const validation = validator.validate(password);
        if (!validation.isValid) {
          securityEvents.emitSecurityEvent('hash_validation_failed', { 
            errors: validation.errors 
          });
          throw new Error(`Invalid password: ${validation.errors.join(', ')}`);
        }
      }

      // Apply pepper
      const pepper = options.pepper || config.getPepper();
      const pepperedPassword = this.applyPepper(password, pepper);

      // Hash with concurrency control
      const hash = await this.concurrencyLimiter.execute(async () => {
        const algorithm = options.algorithm || 'argon2id';
        
        if (config.USE_WORKER_THREADS && this.workerPool) {
          return await this.workerPool.hash(pepperedPassword, algorithm);
        }

        if (algorithm === 'argon2id') {
          return await this.hashWithArgon2(pepperedPassword);
        } else {
          return await this.hashWithBcrypt(pepperedPassword);
        }
      });

      metricsCollector?.recordHashOperation(Date.now() - startTime);
      return hash;

    } catch (error) {
      securityEvents.emitSecurityEvent('hash_error', { 
        error: error instanceof Error ? error.message : 'Unknown error' 
      });
      throw error;
    }
  }

  public async verify(
    password: string,
    hash: string,
    options: VerifyOptions = {}
  ): Promise<{ valid: boolean; needsRehash: boolean }> {
    const startTime = Date.now();

    try {
      // Input validation
      if (typeof password !== 'string' || typeof hash !== 'string') {
        return { valid: false, needsRehash: false };
      }

      if (!password || !hash) {
        await this.dummyVerify();
        return { valid: false, needsRehash: false };
      }

      // Rate limiting
      if (options.identifier && !options.skipRateLimit) {
        const { allowed, retryAfter } = await rateLimiter.checkLimit(options.identifier);
        if (!allowed) {
          securityEvents.emitSecurityEvent('verify_rate_limited', {
            identifier: options.identifier,
          });
          throw new Error(`Rate limit exceeded. Retry after ${retryAfter} seconds`);
        }
      }

      // Apply pepper and verify
      const pepper = config.getPepper();
      const pepperedPassword = this.applyPepper(password, pepper);

      let valid = false;
      let needsRehash = false;

      // Primary verify with current pepper
      const result = await this.concurrencyLimiter.execute(async () => {
        if (hash.startsWith('$argon2')) {
          const isValid = await argon2.verify(hash, pepperedPassword);
          return {
            valid: isValid,
            needsRehash: isValid && this.needsArgon2Rehash(hash),
          };
        } else if (hash.startsWith('$2')) {
          const isValid = await bcrypt.compare(pepperedPassword, hash);
          return {
            valid: isValid,
            needsRehash: isValid && this.needsBcryptRehash(hash),
          };
        } else {
          await this.dummyVerify();
          return { valid: false, needsRehash: false };
        }
      });

      valid = result.valid;
      needsRehash = result.needsRehash;

      // Try with rotation pepper if configured and initial verification failed
      if (!valid && config.getRotationPepper()) {
        const rotationPepper = config.getRotationPepper()!;
        const rotationPepperedPassword = this.applyPepper(password, rotationPepper);

        const rotationResult = await this.concurrencyLimiter.execute(async () => {
          if (hash.startsWith('$argon2')) {
            return await argon2.verify(hash, rotationPepperedPassword);
          } else if (hash.startsWith('$2')) {
            return await bcrypt.compare(rotationPepperedPassword, hash);
          }
          return false;
        });

        if (rotationResult) {
          valid = true;
          needsRehash = true; // Force rehash to update pepper
          securityEvents.emitSecurityEvent('pepper_rotation_used', {
            identifier: options.identifier,
          });
        }
      }

      // Legacy (pre-pepper) fallback: verify raw password if peppered checks failed
      if (!valid) {
        const legacyResult = await this.concurrencyLimiter.execute(async () => {
          if (hash.startsWith('$argon2')) {
            return await argon2.verify(hash, password);
          } else if (hash.startsWith('$2')) {
            return await bcrypt.compare(password, hash);
          }
          return false;
        });

        if (legacyResult) {
          valid = true;
          needsRehash = true; // upgrade to current pepper and settings
          securityEvents.emitSecurityEvent('legacy_no_pepper_verified', {
            identifier: options.identifier,
          });
        }
      }

      // If valid, ensure algorithm preference is enforced (migrate on next hash)
      if (valid) {
        const storedAlgo = hash.startsWith('$argon2') ? 'argon2id' : (hash.startsWith('$2') ? 'bcrypt' : null);
        const preferredAlgo = process.env.AUTHRIX_HASH_ALGO === 'bcrypt' ? 'bcrypt' : 'argon2id';
        if (storedAlgo && storedAlgo !== preferredAlgo) {
          needsRehash = true;
          securityEvents.emitSecurityEvent('algorithm_upgrade_needed', {
            identifier: options.identifier,
            from: storedAlgo,
            to: preferredAlgo,
          });
        }
      }

      // Update rate limiter based on result
      if (options.identifier) {
        if (valid) {
          rateLimiter.clearFailures(options.identifier);
        } else {
          rateLimiter.recordFailure(options.identifier);
        }
      }

      metricsCollector?.recordVerifyOperation(Date.now() - startTime, valid);

      if (!valid) {
        securityEvents.emitSecurityEvent('verify_failed', {
          identifier: options.identifier,
        });
      }

      return { valid, needsRehash };
    } catch (error) {
      securityEvents.emitSecurityEvent('verify_error', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      await this.dummyVerify();
      return { valid: false, needsRehash: false };
    }
  }

  private async hashWithArgon2(password: string): Promise<string> {
    return argon2.hash(password, {
      type: argon2.argon2id,
      timeCost: config.ARGON2_TIME_COST,
      memoryCost: config.ARGON2_MEMORY_COST,
      parallelism: config.ARGON2_PARALLELISM,
      salt: randomBytes(config.ARGON2_SALT_LENGTH),
    });
  }

  private async hashWithBcrypt(password: string): Promise<string> {
    return bcrypt.hash(password, config.BCRYPT_ROUNDS);
  }

  private applyPepper(password: string, pepper: string): string {
    if (!pepper) return password;
    
    // Use HMAC-SHA256 for pepper application
    const hmac = createHmac('sha256', pepper);
    hmac.update(password);
    return hmac.digest('base64');
  }

  private async dummyVerify(): Promise<void> {
    // Constant-time dummy operation to prevent timing attacks
    const dummyHash = '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG';
    try {
      await argon2.verify(dummyHash, 'dummy');
    } catch {
      // Expected to fail
    }
  }

  private needsBcryptRehash(hash: string): boolean {
    const match = hash.match(/^\$2[aby]?\$(\d+)\$/);
    if (!match) return true;
    const rounds = parseInt(match[1], 10);
    return rounds < config.BCRYPT_ROUNDS;
  }

  private needsArgon2Rehash(hash: string): boolean {
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
  }

  public destroy(): void {
    this.workerPool?.destroy();
  }
}

// ============================= Concurrency Limiter =============================

class ConcurrencyLimiter {
  private running = 0;
  private queue: Array<{
    resolve: (value: any) => void;
    reject: (error: any) => void;
    fn: () => Promise<any>;
  }> = [];

  constructor(private maxConcurrent: number) {}

  public async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.running >= this.maxConcurrent) {
      return new Promise<T>((resolve, reject) => {
        this.queue.push({ resolve, reject, fn });
      });
    }

    this.running++;
    try {
      const result = await fn();
      this.processQueue();
      return result;
    } finally {
      this.running--;
    }
  }

  private async processQueue(): Promise<void> {
    if (this.queue.length === 0 || this.running >= this.maxConcurrent) {
      return;
    }

    const item = this.queue.shift();
    if (!item) return;

    this.running++;
    try {
      const result = await item.fn();
      item.resolve(result);
    } catch (error) {
      item.reject(error);
    } finally {
      this.running--;
      this.processQueue();
    }
  }
}

// ============================= Worker Pool for CPU-intensive operations =============================

class WorkerPool {
  private workers: Worker[] = [];
  private available: Worker[] = [];
  private pending: Array<{ resolve: (v: any) => void; reject: (e: any) => void; payload: any; type: 'hash' | 'verify'; }> = [];
  private inflight = new Map<string, { resolve: (v: any) => void; reject: (e: any) => void; timer: NodeJS.Timeout }>();
  private destroyed = false;
  private idSeq = 0;
  private readonly timeoutMs = 30000;

  constructor(size: number = Math.min(8, Math.max(2, (os.cpus()?.length || 4)))) {
    for (let i = 0; i < size; i++) this.spawn();
  }

  private inlineWorkerCode(): string {
    // Inline CommonJS worker code to avoid external file resolution in bundlers
    // Note: worker_threads with { eval: true } executes in CJS context, so require() is available.
    return `const { parentPort } = require('worker_threads');
const bcrypt = require('bcryptjs');
const argon2 = require('argon2');
const { randomBytes } = require('crypto');

const port = parentPort;
if (port) {
  port.on('message', async (message) => {
    const response = { id: message.id, success: false };
    try {
      if (message.type === 'hash') {
        if (message.algorithm === 'bcrypt') {
          const rounds = message.options?.bcryptRounds || 14;
          response.result = await bcrypt.hash(message.password, rounds);
        } else {
          const options = message.options?.argon2Options || { timeCost: 3, memoryCost: 65536, parallelism: 4, saltLength: 16 };
          response.result = await argon2.hash(message.password, { type: argon2.argon2id, timeCost: options.timeCost, memoryCost: options.memoryCost, parallelism: options.parallelism, salt: randomBytes(options.saltLength) });
        }
      } else if (message.type === 'verify') {
        if (!message.hash) throw new Error('Hash is required for verification');
        if (message.hash.startsWith('$2')) {
          response.result = await bcrypt.compare(message.password, message.hash);
        } else if (message.hash.startsWith('$argon2')) {
          response.result = await argon2.verify(message.hash, message.password);
        } else {
          throw new Error('Unsupported hash format');
        }
      } else {
        throw new Error('Unknown operation type: ' + message.type);
      }
      response.success = true;
    } catch (error) {
      response.success = false;
      response.error = error instanceof Error ? error.message : String(error);
    }
    port.postMessage(response);
  });
}`;
  }

  private spawn() {
    if (this.destroyed) return;
    try {
      // Prefer inline worker to avoid bundler resolution issues entirely
      let worker: Worker | null = null;
      try {
        worker = new Worker(this.inlineWorkerCode(), { eval: true });
      } catch {}

      if (!worker) {
        // Fallback: operate without workers; hasher will use in-process hashing
        securityEvents.emitSecurityEvent('worker_inline_unavailable', {});
        this.destroyed = true;
        return;
      }

      worker.on('message', (msg: any) => this.handleMessage(worker, msg));
      worker.on('error', err => {
        securityEvents.emitSecurityEvent('worker_error', { error: err.message });
        this.replace(worker);
      });
      worker.on('exit', code => {
        if (!this.destroyed && code !== 0) {
          securityEvents.emitSecurityEvent('worker_exit', { code });
          this.replace(worker);
        }
      });
      this.workers.push(worker);
      this.available.push(worker);
      this.drain();
    } catch (e) {
      securityEvents.emitSecurityEvent('worker_spawn_failed', { error: e instanceof Error ? e.message : String(e) });
      this.destroyed = true;
    }
  }

  private replace(w: Worker) {
    const idx = this.workers.indexOf(w);
    if (idx >= 0) this.workers.splice(idx, 1);
    const aIdx = this.available.indexOf(w);
    if (aIdx >= 0) this.available.splice(aIdx, 1);
    if (!this.destroyed) this.spawn();
  }

  private handleMessage(worker: Worker, msg: any) {
    const inflight = this.inflight.get(msg.id);
    if (!inflight) return;
    clearTimeout(inflight.timer);
    this.inflight.delete(msg.id);
    if (msg.success) inflight.resolve(msg.result); else inflight.reject(new Error(msg.error || 'Worker task failed'));
    this.available.push(worker);
    this.drain();
  }

  private dispatch(worker: Worker, payload: any, type: 'hash' | 'verify'): Promise<any> {
    const id = `w${Date.now()}_${this.idSeq++}`;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.inflight.delete(id);
        reject(new Error('Worker timeout'));
        this.replace(worker);
      }, this.timeoutMs);
      this.inflight.set(id, { resolve, reject, timer });
      worker.postMessage({ id, ...payload, type });
    });
  }

  private drain() {
    while (this.available.length && this.pending.length) {
      const worker = this.available.shift()!;
      const task = this.pending.shift()!;
      this.dispatch(worker, task.payload, task.type).then(task.resolve).catch(task.reject);
    }
  }

  public async hash(password: string, algorithm: 'argon2id' | 'bcrypt'): Promise<string> {
    if (this.destroyed || !this.workers.length) {
      // Fallback to in-process hashing
      if (algorithm === 'argon2id') {
        return argon2.hash(password, { type: argon2.argon2id, timeCost: config.ARGON2_TIME_COST, memoryCost: config.ARGON2_MEMORY_COST, parallelism: config.ARGON2_PARALLELISM, salt: randomBytes(config.ARGON2_SALT_LENGTH) });
      }
      return bcrypt.hash(password, config.BCRYPT_ROUNDS);
    }
    return new Promise<string>((resolve, reject) => {
      this.pending.push({ resolve, reject, type: 'hash', payload: {
        algorithm,
        password,
        options: {
          bcryptRounds: config.BCRYPT_ROUNDS,
          argon2Options: { timeCost: config.ARGON2_TIME_COST, memoryCost: config.ARGON2_MEMORY_COST, parallelism: config.ARGON2_PARALLELISM, saltLength: config.ARGON2_SALT_LENGTH }
        }
      }});
      this.drain();
    });
  }

  public async verify(password: string, hash: string): Promise<boolean> {
    if (this.destroyed || !this.workers.length) {
      if (hash.startsWith('$argon2')) return argon2.verify(hash, password);
      if (hash.startsWith('$2')) return bcrypt.compare(password, hash);
      return false;
    }
    return new Promise<boolean>((resolve, reject) => {
      this.pending.push({ resolve, reject, type: 'verify', payload: { password, hash } });
      this.drain();
    });
  }

  public destroy() {
    this.destroyed = true;
    for (const w of this.workers) {
      try { w.terminate(); } catch {}
    }
    this.workers = [];
    this.available = [];
    for (const [, inflight] of this.inflight) {
      clearTimeout(inflight.timer);
      inflight.reject(new Error('WorkerPool destroyed'));
    }
    this.inflight.clear();
    this.pending.length = 0;
  }
}

// ============================= Secure Password Generator =============================

class SecurePasswordGenerator {
  private readonly charsets = {
    lowercase: 'abcdefghjkmnpqrstuvwxyz',
    uppercase: 'ABCDEFGHJKMNPQRSTUVWXYZ',
    numbers: '23456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
    ambiguous: /[lI1O0o]/g,
  };

  public generate(
    length: number = 16,
    options: {
      includeLowercase?: boolean;
      includeUppercase?: boolean;
      includeNumbers?: boolean;
      includeSymbols?: boolean;
      excludeAmbiguous?: boolean;
      minEntropy?: number;
      memorableFormat?: boolean;
    } = {}
  ): string {
    const {
      includeLowercase = true,
      includeUppercase = true,
      includeNumbers = true,
      includeSymbols = true,
      excludeAmbiguous = true,
      minEntropy = 50,
      memorableFormat = false,
    } = options;

    if (length < 8 || length > 256) {
      throw new Error('Password length must be between 8 and 256 characters');
    }

    if (memorableFormat) {
      return this.generateMemorablePassword(length);
    }

    let charset = '';
    const requiredChars: string[] = [];

    if (includeLowercase) {
      charset += this.charsets.lowercase;
      requiredChars.push(this.secureRandomChar(this.charsets.lowercase));
    }
    if (includeUppercase) {
      charset += this.charsets.uppercase;
      requiredChars.push(this.secureRandomChar(this.charsets.uppercase));
    }
    if (includeNumbers) {
      charset += this.charsets.numbers;
      requiredChars.push(this.secureRandomChar(this.charsets.numbers));
    }
    if (includeSymbols) {
      charset += this.charsets.symbols;
      requiredChars.push(this.secureRandomChar(this.charsets.symbols));
    }

    if (!charset) {
      throw new Error('At least one character type must be included');
    }

    let password = '';
    let attempts = 0;

    while (attempts < 100) {
      password = this.generatePasswordAttempt(length, charset, requiredChars);
      
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

    if (attempts >= 100) {
      throw new Error('Failed to generate password with sufficient entropy');
    }

    return password;
  }

  private generatePasswordAttempt(
    length: number,
    charset: string,
    requiredChars: string[]
  ): string {
    const password: string[] = [...requiredChars];

    for (let i = requiredChars.length; i < length; i++) {
      password.push(this.secureRandomChar(charset));
    }

    // Fisher-Yates shuffle
    for (let i = password.length - 1; i > 0; i--) {
      const j = this.secureRandomInt(i + 1);
      [password[i], password[j]] = [password[j], password[i]];
    }

    return password.join('');
  }

  private generateMemorablePassword(totalLength: number): string {
    const words = ['Time', 'Space', 'Fire', 'Water', 'Earth', 'Wind'];
    const separators = ['-', '_', '.', '!'];
    
    let password = '';
    while (password.length < totalLength) {
      password += words[this.secureRandomInt(words.length)];
      password += separators[this.secureRandomInt(separators.length)];
      password += this.secureRandomInt(100).toString();
    }

    return password.substring(0, totalLength);
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

// ============================= Main Instances =============================

const hasher = new PasswordHasher();
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
    try {
      // Explicitly choose preferred algorithm and avoid rate-limit consumption during rehash
      const algorithm = process.env.AUTHRIX_HASH_ALGO === 'bcrypt' ? 'bcrypt' : 'argon2id';
      const newHash = await hasher.hash(password, {
        skipValidation: true,
        algorithm,
      });
      metricsCollector?.recordRehash();
      return { ...result, newHash };
    } catch (error) {
      // Log but don't fail verification if rehash fails
      securityEvents.emitSecurityEvent('rehash_failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return result;
    }
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

export function getSecurityMetrics(): SecurityMetrics | null {
  return metricsCollector?.getMetrics() || null;
}

export function subscribeToSecurityEvents(
  callback: (event: any) => void
): () => void {
  securityEvents.on('security', callback);
  return () => securityEvents.off('security', callback);
}

// ============================= Public Rehash Helper =============================
/**
 * Determine if a stored password hash should be rehashed according to current security configuration.
 * Supports bcrypt ($2*) and argon2id ($argon2id$) hashes.
 * Returns false for unrecognized algorithms (caller may choose to force upgrade separately).
 */
export function needsRehash(hash: string): boolean {
  if (!hash || typeof hash !== 'string') return false;

  // Bcrypt pattern: $2b$12$...
  if (hash.startsWith('$2a$') || hash.startsWith('$2b$') || hash.startsWith('$2y$')) {
    const match = hash.match(/^\$2[aby]?\$(\d{2})\$/);
    if (!match) return false;
    const rounds = parseInt(match[1], 10);
    return rounds < config.BCRYPT_ROUNDS;
  }

  // Argon2id pattern contains parameters segment with m=,t=,p=
  if (hash.startsWith('$argon2id$')) {
    const match = hash.match(/m=(\d+),t=(\d+),p=(\d+)/);
    if (!match) return false;
    const memoryCost = parseInt(match[1], 10);
    const timeCost = parseInt(match[2], 10);
    const parallelism = parseInt(match[3], 10);
    return (
      memoryCost < config.ARGON2_MEMORY_COST ||
      timeCost < config.ARGON2_TIME_COST ||
      parallelism < config.ARGON2_PARALLELISM
    );
  }

  return false; // Unknown / already adequate
}

// ============================= Cleanup =============================

const cleanup = () => {
  rateLimiter.destroy();
  hasher.destroy();
  if (metricsCollector) {
    const finalMetrics = metricsCollector.getMetrics();
    console.log('[Security] Final metrics:', finalMetrics);
  }
};

process.on('exit', cleanup);
process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);

// ============================= Export Types =============================

export type {
  PasswordValidationResult,
  HashOptions,
  VerifyOptions,
  PasswordPolicy,
  SecurityMetrics,
};
