import { EmailService } from "../core/twoFactor";
import type { EmailServiceCapabilities } from "../types/email";
import type { Transporter } from "nodemailer";
import type Mail from "nodemailer/lib/mailer";

// Types
interface GmailConfig {
    user: string;
    appPassword: string;
    fromName?: string;
    maxRetries?: number;
    retryDelay?: number;
    enablePooling?: boolean;
    enableLogging?: boolean;
}

interface EmailMetadata {
    appName?: string;
    primaryColor?: string;
    logoUrl?: string;
    trackingId?: string;
    [key: string]: any;
}

interface SendEmailOptions {
    subject?: string;
    template?: string;
    metadata?: EmailMetadata;
}

interface TestResult {
    success: boolean;
    message: string;
    details?: Record<string, any>;
}

// Constants
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DEFAULT_RETRY_COUNT = 3;
const DEFAULT_RETRY_DELAY = 1000;
const PERMANENT_ERROR_PATTERNS = [
    'authentication',
    'Invalid login',
    'Username and Password not accepted',
    'Invalid recipients',
    'Mailbox unavailable'
];

/**
 * Optimized Gmail SMTP Email Service
 */
export class GmailEmailService implements EmailService {
    public readonly capabilities: EmailServiceCapabilities = {
        templates: true,
        headers: true,
        tracking: false,
        tags: false,
        replyTo: false
    };
    private transporter?: Transporter;
    private config: Required<GmailConfig>;
    private initPromise?: Promise<void>;

    constructor(config?: Partial<GmailConfig>) {
        this.config = this.validateAndNormalizeConfig(config);
    }

    /**
     * Validate and normalize configuration
     */
    private validateAndNormalizeConfig(config?: Partial<GmailConfig>): Required<GmailConfig> {
        const user = config?.user || process.env.GMAIL_USER || '';
        const appPassword = config?.appPassword || process.env.GMAIL_APP_PASSWORD || '';
        const fromName = config?.fromName || process.env.GMAIL_FROM_NAME || 'Authrix';

        if (!user) {
            throw new Error('GMAIL_USER is required (your Gmail address).');
        }
        if (!appPassword) {
            throw new Error('GMAIL_APP_PASSWORD is required. Generate one at https://myaccount.google.com/apppasswords');
        }

        if (!EMAIL_REGEX.test(user)) {
            throw new Error('GMAIL_USER must be a valid email address (e.g., you@example.com)');
        }

        return {
            user: user.trim(),
            appPassword: appPassword.trim(),
            fromName,
            maxRetries: config?.maxRetries ?? DEFAULT_RETRY_COUNT,
            retryDelay: config?.retryDelay ?? DEFAULT_RETRY_DELAY,
            enablePooling: config?.enablePooling ?? true,
            enableLogging: config?.enableLogging ?? true
        };
    }

    /**
     * Initialize transporter (singleton pattern)
     */
    private async ensureInitialized(): Promise<void> {
        if (this.transporter) return;

        if (!this.initPromise) {
            this.initPromise = this.initialize();
        }

        await this.initPromise;
    }

    /**
     * Initialize Gmail transporter
     */
    private async initialize(): Promise<void> {
        try {
            const nodemailer = await import('nodemailer');

            // Gmail SMTP configuration
            const transportConfig = {
                host: 'smtp.gmail.com',
                port: 587,
                secure: false,
                auth: {
                    user: this.config.user,
                    pass: this.config.appPassword
                }
            };

            // Add pooling configuration if enabled
            if (this.config.enablePooling) {
                Object.assign(transportConfig, {
                    pool: true,
                    maxConnections: 5,
                    maxMessages: 100,
                    rateDelta: 1000,
                    rateLimit: 5
                } as any);
            }

            this.transporter = nodemailer.createTransport(transportConfig);

            await this.transporter.verify();

            if (this.config.enableLogging) {
                console.log('✅ Gmail service initialized');
            }
        } catch (error) {
            this.initPromise = undefined;
            const message = error instanceof Error ? error.message : 'Unknown error';

            if (message.includes('Invalid login')) {
                throw new Error(
                    'Gmail authentication failed. Ensure you\'re using an App Password, not your regular password.'
                );
            }

            throw new Error(`Gmail initialization failed: ${message}`);
        }
    }

    /**
     * Send verification email with optimized retry logic
     */
    async sendVerificationEmail(
        to: string,
        code: string,
        options: SendEmailOptions = {}
    ): Promise<void> {
        // Validate inputs
        this.validateEmailInputs(to, code);

        // Ensure transporter is initialized
        await this.ensureInitialized();

        // Prepare mail options
        const mailOptions = this.prepareMailOptions(to, code, options);

        // Send with retry logic
        await this.sendWithRetry(mailOptions, to);
    }

    /**
     * Validate email inputs
     */
    private validateEmailInputs(to: string, code: string): void {
        if (!to?.trim()) {
            throw new Error('Recipient email address is required');
        }

        if (!EMAIL_REGEX.test(to.trim())) {
            throw new Error('Invalid recipient email address format');
        }

        if (!code?.trim()) {
            throw new Error('Verification code is required');
        }
    }

    /**
     * Prepare mail options
     */
    private prepareMailOptions(
        to: string,
        code: string,
        options: SendEmailOptions
    ): Mail.Options {
        const { subject = 'Email Verification Code', template, metadata = {} } = options;
        const fromName = metadata.appName || this.config.fromName;

        return {
            from: `"${fromName}" <${this.config.user}>`,
            to: to.trim(),
            subject,
            text: this.generateTextContent(code, metadata),
            html: template || this.generateHtmlContent(code, metadata),
            headers: {
                'X-Mailer': 'Authrix Gmail Service',
                'X-Priority': '1',
                ...(metadata.trackingId && { 'X-Tracking-ID': metadata.trackingId })
            }
        };
    }

    /**
     * Send email with exponential backoff retry
     */
    private async sendWithRetry(mailOptions: Mail.Options, to: string): Promise<void> {
        let lastError: Error | null = null;

        for (let attempt = 1; attempt <= this.config.maxRetries; attempt++) {
            try {
                if (!this.transporter) {
                    throw new Error('Transporter not initialized');
                }
                const info = await this.transporter.sendMail(mailOptions);

                if (this.config.enableLogging) {
                    console.log(`✅ Email sent to ${to} (ID: ${info.messageId})`);
                }

                return;
            } catch (error) {
                lastError = error instanceof Error ? error : new Error(String(error));

                // Check for permanent errors (don't retry)
                if (this.isPermanentError(lastError.message)) {
                    throw lastError;
                }

                if (this.config.enableLogging && attempt < this.config.maxRetries) {
                    console.warn(`⚠️ Attempt ${attempt}/${this.config.maxRetries} failed: ${lastError.message}`);
                }

                // Exponential backoff
                if (attempt < this.config.maxRetries) {
                    const delay = this.config.retryDelay * Math.pow(2, attempt - 1);
                    await this.delay(delay);
                }
            }
        }

        throw new Error(
            `Failed after ${this.config.maxRetries} attempts: ${lastError?.message || 'Unknown error'}`
        );
    }

    /**
     * Check if error is permanent (should not retry)
     */
    private isPermanentError(message: string): boolean {
        return PERMANENT_ERROR_PATTERNS.some(pattern => message.includes(pattern));
    }

    /**
     * Delay helper
     */
    private delay(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Generate plain text email content
     */
    private generateTextContent(code: string, metadata: EmailMetadata): string {
        const appName = metadata.appName || this.config.fromName;

        return `
Email Verification - ${appName}

Your verification code is: ${code}

This code expires in 10 minutes.

If you didn't request this, please ignore this email.

---
${appName}
This is an automated message, please do not reply.
`.trim();
    }

    /**
     * Generate HTML email content (optimized)
     */
    private generateHtmlContent(code: string, metadata: EmailMetadata): string {
        const appName = metadata.appName || this.config.fromName;
        const primaryColor = metadata.primaryColor || '#2563eb';
        const year = new Date().getFullYear();

        return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Email Verification</title>
  <style>
    body {
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f9fafb;
      color: #1f2937;
    }
    .wrapper {
      max-width: 600px;
      margin: 20px auto;
      background: #fff;
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .header {
      background: ${primaryColor};
      color: white;
      padding: 30px;
      text-align: center;
    }
    .header h1 {
      margin: 0;
      font-size: 28px;
    }
    .content {
      padding: 40px 30px;
    }
    .code-box {
      background: #f8fafc;
      border: 2px solid ${primaryColor}20;
      border-radius: 12px;
      padding: 20px;
      margin: 30px 0;
      text-align: center;
    }
    .code {
      font-size: 32px;
      font-weight: bold;
      color: ${primaryColor};
      letter-spacing: 6px;
      font-family: monospace;
    }
    .warning {
      background: #fef3c7;
      border-left: 4px solid #f59e0b;
      padding: 15px;
      margin: 20px 0;
      border-radius: 4px;
    }
    .footer {
      background: #f8fafc;
      padding: 20px;
      text-align: center;
      font-size: 14px;
      color: #6b7280;
    }
    @media (max-width: 600px) {
      .content { padding: 30px 20px; }
      .code { font-size: 24px; letter-spacing: 4px; }
    }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="header">
      ${metadata.logoUrl ? `<img src="${metadata.logoUrl}" alt="${appName}" style="max-height:50px;margin-bottom:15px;">` : ''}
      <h1>${appName}</h1>
      <p style="margin:10px 0 0;opacity:0.9;">Email Verification</p>
    </div>
    <div class="content">
      <h2 style="margin-top:0;">Verify Your Email</h2>
      <p>Please use this verification code:</p>
      <div class="code-box">
        <div class="code">${code}</div>
      </div>
      <div class="warning">
        <strong>⚠️ Security:</strong> This code expires in 10 minutes. Never share it with anyone.
      </div>
      <p>If you didn't request this, please ignore this email.</p>
    </div>
    <div class="footer">
      <p>© ${year} ${appName}. All rights reserved.</p>
      <p style="font-size:12px;margin-top:10px;">This is an automated message, please do not reply.</p>
    </div>
  </div>
</body>
</html>`;
    }

    /**
     * Test connection
     */
    async testConnection(): Promise<TestResult> {
        try {
            await this.ensureInitialized();

            const testCode = Math.floor(100000 + Math.random() * 900000).toString();

            await this.sendVerificationEmail(
                this.config.user,
                testCode,
                {
                    subject: 'Gmail Service Test',
                    metadata: { appName: 'Authrix Test' }
                }
            );

            return {
                success: true,
                message: 'Gmail service test successful',
                details: {
                    user: this.config.user,
                    timestamp: new Date().toISOString()
                }
            };
        } catch (error) {
            return {
                success: false,
                message: error instanceof Error ? error.message : 'Test failed',
                details: { error: String(error) }
            };
        }
    }

    /**
     * Close connection
     */
    async close(): Promise<void> {
        if (this.transporter) {
            this.transporter.close();
            this.transporter = undefined;
            this.initPromise = undefined;
        }
    }
}

// Factory function
export function createGmailEmailService(config?: Partial<GmailConfig>): GmailEmailService {
    return new GmailEmailService(config);
}

// Default instance
export const gmailEmailService = new GmailEmailService();