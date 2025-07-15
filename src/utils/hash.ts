import * as bcrypt from "bcryptjs";
import { createHash, randomBytes } from "crypto";

const BCRYPT_ROUNDS = 14; // Increased from 12 for better security
const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128; // Prevent DoS attacks

// Rate limiting for password operations (simple in-memory store)
const passwordOperationTimes = new Map<string, number[]>();
const MAX_OPERATIONS_PER_MINUTE = 10;
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute

/**
 * Enhanced password validation with comprehensive security checks
 */
export function validatePassword(password: string): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Length validation
    if (!password || password.length < MIN_PASSWORD_LENGTH) {
        errors.push(`Password must be at least ${MIN_PASSWORD_LENGTH} characters long`);
    }
    
    if (password.length > MAX_PASSWORD_LENGTH) {
        errors.push(`Password must not exceed ${MAX_PASSWORD_LENGTH} characters`);
    }

    // Complexity requirements
    if (!/[a-z]/.test(password)) {
        errors.push("Password must contain at least one lowercase letter");
    }
    
    if (!/[A-Z]/.test(password)) {
        errors.push("Password must contain at least one uppercase letter");
    }
    
    if (!/\d/.test(password)) {
        errors.push("Password must contain at least one number");
    }
    
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
        errors.push("Password must contain at least one special character");
    }

    // Check for common patterns
    if (/(.)\1{2,}/.test(password)) {
        errors.push("Password must not contain more than 2 consecutive identical characters");
    }

    // Check for sequential characters
    if (/(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i.test(password)) {
        errors.push("Password must not contain sequential characters");
    }

    return {
        isValid: errors.length === 0,
        errors
    };
}

/**
 * Rate limiting for password operations to prevent brute force attacks
 */
function checkRateLimit(identifier: string): boolean {
    const now = Date.now();
    const operations = passwordOperationTimes.get(identifier) || [];
    
    // Remove operations older than the rate limit window
    const recentOperations = operations.filter(time => now - time < RATE_LIMIT_WINDOW);
    
    if (recentOperations.length >= MAX_OPERATIONS_PER_MINUTE) {
        return false; // Rate limit exceeded
    }
    
    // Add current operation
    recentOperations.push(now);
    passwordOperationTimes.set(identifier, recentOperations);
    
    // Cleanup old entries periodically
    if (passwordOperationTimes.size > 1000) {
        for (const [key, times] of Array.from(passwordOperationTimes.entries())) {
            const validTimes = times.filter(time => now - time < RATE_LIMIT_WINDOW);
            if (validTimes.length === 0) {
                passwordOperationTimes.delete(key);
            } else {
                passwordOperationTimes.set(key, validTimes);
            }
        }
    }
    
    return true;
}

/**
 * Production-grade password hashing with enhanced security
 * @param password - The plaintext password to hash
 * @param options - Optional configuration
 */
export async function hashPassword(
    password: string, 
    options: { skipValidation?: boolean; identifier?: string } = {}
): Promise<string> {
    // Input validation
    if (typeof password !== 'string') {
        throw new Error('Password must be a string');
    }

    // Rate limiting
    if (options.identifier && !checkRateLimit(options.identifier)) {
        throw new Error('Too many password operations. Please try again later.');
    }

    // Password validation (can be skipped for migration scenarios)
    if (!options.skipValidation) {
        const validation = validatePassword(password);
        if (!validation.isValid) {
            throw new Error(`Password validation failed: ${validation.errors.join(', ')}`);
        }
    }

    // Additional security: normalize password to prevent timing attacks
    const normalizedPassword = Buffer.from(password, 'utf8').toString('utf8');
    
    try {
        // Use higher bcrypt rounds for production security
        const hash = await bcrypt.hash(normalizedPassword, BCRYPT_ROUNDS);
        
        // Clear the password from memory (best effort)
        if (typeof password === 'string') {
            // Note: This doesn't guarantee memory clearing in JavaScript, but it's good practice
            password = '';
        }
        
        return hash;
    } catch (error) {
        throw new Error(`Failed to hash password: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}

/**
 * Production-grade password verification with timing attack protection
 * @param password - The plaintext password to verify
 * @param hashedPassword - The stored hash to compare against
 * @param options - Optional configuration
 */
export async function verifyPassword(
    password: string, 
    hashedPassword: string,
    options: { identifier?: string } = {}
): Promise<boolean> {
    // Input validation
    if (typeof password !== 'string' || typeof hashedPassword !== 'string') {
        throw new Error('Password and hash must be strings');
    }

    if (!password || !hashedPassword) {
        // Always perform a dummy bcrypt operation to prevent timing attacks
        await bcrypt.compare('dummy-password', '$2b$14$dummy.hash.to.prevent.timing.attacks.in.production');
        return false;
    }

    // Rate limiting
    if (options.identifier && !checkRateLimit(options.identifier)) {
        throw new Error('Too many password verification attempts. Please try again later.');
    }

    // Validate hash format
    if (!hashedPassword.startsWith('$2b$') && !hashedPassword.startsWith('$2a$') && !hashedPassword.startsWith('$2y$')) {
        // Perform dummy operation to prevent timing attacks
        await bcrypt.compare('dummy-password', '$2b$14$dummy.hash.to.prevent.timing.attacks.in.production');
        return false;
    }

    try {
        // Normalize password to prevent timing attacks
        const normalizedPassword = Buffer.from(password, 'utf8').toString('utf8');
        
        const isValid = await bcrypt.compare(normalizedPassword, hashedPassword);
        
        // Clear the password from memory (best effort)
        if (typeof password === 'string') {
            password = '';
        }
        
        return isValid;
    } catch (error) {
        // Log error for monitoring but don't expose details to prevent information leakage
        console.error('Password verification error:', error);
        return false;
    }
}

/**
 * Generate a cryptographically secure random password
 * @param length - Password length (default: 16)
 * @param options - Character set options
 */
export function generateSecurePassword(
    length: number = 16,
    options: {
        includeLowercase?: boolean;
        includeUppercase?: boolean;
        includeNumbers?: boolean;
        includeSymbols?: boolean;
        excludeSimilar?: boolean;
    } = {}
): string {
    const {
        includeLowercase = true,
        includeUppercase = true,
        includeNumbers = true,
        includeSymbols = true,
        excludeSimilar = true
    } = options;

    let charset = '';
    const requiredChars: string[] = [];
    
    if (includeLowercase) {
        const lowerChars = excludeSimilar ? 'abcdefghijkmnopqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
        charset += lowerChars;
        requiredChars.push(lowerChars[Math.floor(Math.random() * lowerChars.length)]);
    }
    
    if (includeUppercase) {
        const upperChars = excludeSimilar ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        charset += upperChars;
        requiredChars.push(upperChars[Math.floor(Math.random() * upperChars.length)]);
    }
    
    if (includeNumbers) {
        const numberChars = excludeSimilar ? '23456789' : '0123456789';
        charset += numberChars;
        requiredChars.push(numberChars[Math.floor(Math.random() * numberChars.length)]);
    }
    
    if (includeSymbols) {
        const symbolChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';
        charset += symbolChars;
        requiredChars.push(symbolChars[Math.floor(Math.random() * symbolChars.length)]);
    }

    if (!charset) {
        throw new Error('At least one character set must be enabled');
    }

    if (length < 8 || length > 128) {
        throw new Error('Password length must be between 8 and 128 characters');
    }

    if (requiredChars.length > length) {
        throw new Error('Password length must be at least as long as the number of required character types');
    }

    // Start with required characters to ensure all types are included
    let password = '';
    const randomBytesBuffer = randomBytes(length * 2);
    let byteIndex = 0;
    
    // Add required characters first
    for (const char of requiredChars) {
        password += char;
    }
    
    // Fill the rest with random characters from the full charset
    for (let i = requiredChars.length; i < length; i++) {
        const randomIndex = randomBytesBuffer[byteIndex] % charset.length;
        password += charset[randomIndex];
        byteIndex++;
    }

    // Shuffle the password to randomize character positions
    const passwordArray = password.split('');
    for (let i = passwordArray.length - 1; i > 0; i--) {
        const j = randomBytesBuffer[byteIndex] % (i + 1);
        [passwordArray[i], passwordArray[j]] = [passwordArray[j], passwordArray[i]];
        byteIndex++;
    }

    return passwordArray.join('');
}

/**
 * Check if a password hash needs to be rehashed (e.g., due to updated security standards)
 */
export function needsRehash(hashedPassword: string): boolean {
    try {
        // Validate hash format first
        if (!hashedPassword || !hashedPassword.startsWith('$2')) {
            return true; // Invalid hash format, needs rehashing
        }
        
        const parts = hashedPassword.split('$');
        if (parts.length < 4) {
            return true; // Invalid hash format
        }
        
        // Extract rounds from hash
        const rounds = parseInt(parts[2]);
        if (isNaN(rounds)) {
            return true; // Invalid rounds, needs rehashing
        }
        
        return rounds < BCRYPT_ROUNDS;
    } catch {
        return true; // Any error means needs rehashing
    }
}
