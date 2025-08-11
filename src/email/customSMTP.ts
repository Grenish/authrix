import { EmailService } from "../core/twoFactor";
import type { Transporter } from "nodemailer";
import type Mail from "nodemailer/lib/mailer";
import type SMTPTransport from "nodemailer/lib/smtp-transport";

// Types
interface SMTPConfig {
    host?: string;
    port?: number;
    user?: string;
    pass?: string;
    from?: string;
    fromName?: string;
    secure?: boolean;
    requireTLS?: boolean;
    authMethod?: string;
    maxRetries?: number;
    retryDelay?: number;
    enableLogging?: boolean;
    enablePooling?: boolean;
    connectionTimeout?: number;
    customTemplate?: EmailTemplate;
}

interface EmailTemplate {
    html: (code: string, metadata?: EmailMetadata) => string;
    text?: (code: string, metadata?: EmailMetadata) => string;
}

interface EmailMetadata {
    appName?: string;
    primaryColor?: string;
    logoUrl?: string;
    supportEmail?: string;
    customHeaders?: Record<string, string>;
    [key: string]: any;
}

interface SendEmailOptions {
    subject?: string;
    template?: string;
    metadata?: EmailMetadata;
    replyTo?: string;
}

interface TestResult {
    success: boolean;
    message: string;
    details?: Record<string, any>;
}

interface ServiceInfo {
    host: string;
    port: number;
    user: string;
    secure: boolean;
    isInitialized: boolean;
}

// Constants
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const HOSTNAME_REGEX = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
const IP_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const DEFAULT_RETRY_COUNT = 3;
const DEFAULT_RETRY_DELAY = 1000;
const DEFAULT_PORT = 587;
const PERMANENT_ERROR_PATTERNS = [
    'authentication',
    'Invalid login',
    'Username and Password not accepted',
    'Invalid recipients',
    'Mailbox unavailable',
    'User unknown',
    'Domain not found'
];

/**
 * Optimized SMTP Email Service
 */
export class SMTPEmailService implements EmailService {
    private transporter?: Transporter;
    private config: Required<Omit<SMTPConfig, 'customTemplate'>> & { customTemplate?: EmailTemplate };
    private initPromise?: Promise<void>;

    constructor(config?: SMTPConfig) {
        this.config = this.validateAndNormalizeConfig(config);
    }

    /**
     * Validate and normalize configuration
     */
    private validateAndNormalizeConfig(
        config?: SMTPConfig
    ): Required<Omit<SMTPConfig, 'customTemplate'>> & { customTemplate?: EmailTemplate } {
        const host = config?.host || process.env.SMTP_HOST || '';
        const port = config?.port || parseInt(process.env.SMTP_PORT || '') || DEFAULT_PORT;
        const user = config?.user || process.env.SMTP_USER || '';
        const pass = config?.pass || process.env.SMTP_PASS || '';
        const from = config?.from || process.env.SMTP_FROM || user;
        const fromName = config?.fromName || process.env.SMTP_FROM_NAME || 'Authrix';

        // Validate required fields
        if (!host || !user || !pass) {
            const missing = [];
            if (!host) missing.push('SMTP_HOST');
            if (!user) missing.push('SMTP_USER');
            if (!pass) missing.push('SMTP_PASS');
            throw new Error(`Missing SMTP configuration: ${missing.join(', ')}`);
        }

        // Validate host format
        if (!HOSTNAME_REGEX.test(host) && !IP_REGEX.test(host)) {
            throw new Error('Invalid SMTP_HOST format');
        }

        // Validate port
        if (port < 1 || port > 65535) {
            throw new Error('SMTP_PORT must be between 1 and 65535');
        }

        // Validate email format
        if (from && !EMAIL_REGEX.test(from)) {
            throw new Error('SMTP_FROM must be a valid email address');
        }

        // Determine security settings
        const secure = config?.secure ?? (process.env.SMTP_SECURE === 'true' || port === 465);
        const requireTLS = config?.requireTLS ?? (process.env.SMTP_REQUIRE_TLS !== 'false');

        return {
            host: host.trim(),
            port,
            user: user.trim(),
            pass: pass.trim(),
            from: from.trim(),
            fromName,
            secure,
            requireTLS,
            authMethod: config?.authMethod || process.env.SMTP_AUTH_METHOD || 'PLAIN',
            maxRetries: config?.maxRetries ?? DEFAULT_RETRY_COUNT,
            retryDelay: config?.retryDelay ?? DEFAULT_RETRY_DELAY,
            enableLogging: config?.enableLogging ?? true,
            enablePooling: config?.enablePooling ?? true,
            connectionTimeout: config?.connectionTimeout ?? 60000,
            customTemplate: config?.customTemplate
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
     * Initialize SMTP transporter
     */
    private async initialize(): Promise<void> {
        try {
            const nodemailer = await import('nodemailer');

            const transportConfig: SMTPTransport.Options = {
                host: this.config.host,
                port: this.config.port,
                secure: this.config.secure,
                auth: {
                    user: this.config.user,
                    pass: this.config.pass
                },
                connectionTimeout: this.config.connectionTimeout,
                greetingTimeout: 30000,
                socketTimeout: 60000
            };

            // TLS settings for non-secure connections
            if (!this.config.secure) {
                transportConfig.requireTLS = this.config.requireTLS;
                transportConfig.tls = {
                    rejectUnauthorized: process.env.SMTP_TLS_REJECT_UNAUTHORIZED !== 'false',
                    ciphers: process.env.SMTP_TLS_CIPHERS || 'SSLv3'
                };
            }

            // Create transporter with optional pooling support
            if (this.config.enablePooling) {
                // Use pooled transport with extended options
                const poolConfig = {
                    ...transportConfig,
                    pool: true,
                    maxConnections: 5,
                    maxMessages: 100,
                    rateDelta: 1000,
                    rateLimit: 5
                };
                this.transporter = nodemailer.createTransport(poolConfig as any);
            } else {
                // Use standard transport
                this.transporter = nodemailer.createTransport(transportConfig);
            }

            // Verify connection
            await this.transporter.verify();

            if (this.config.enableLogging) {
                console.log(`✅ SMTP service initialized (${this.config.host}:${this.config.port})`);
            }
        } catch (error) {
            this.initPromise = undefined;
            const message = error instanceof Error ? error.message : 'Unknown error';

            if (message.includes('ENOTFOUND')) {
                throw new Error(`SMTP host not found: ${this.config.host}`);
            }
            if (message.includes('ECONNREFUSED')) {
                throw new Error(`Connection refused to ${this.config.host}:${this.config.port}`);
            }
            if (message.includes('Invalid login')) {
                throw new Error('SMTP authentication failed. Check credentials.');
            }

            throw new Error(`SMTP initialization failed: ${message}`);
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
            throw new Error('Recipient email is required');
        }

        if (!EMAIL_REGEX.test(to.trim())) {
            throw new Error('Invalid email format');
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
        const { subject = 'Email Verification Code', template, metadata = {}, replyTo } = options;
        const fromName = metadata.appName || this.config.fromName;
        const from = `"${fromName}" <${this.config.from}>`;

        // Generate email content
        let html: string;
        let text: string;

        if (template) {
            // Direct template string provided
            html = template;
            text = this.generateTextContent(code, metadata);
        } else if (this.config.customTemplate) {
            // Use configured custom template
            html = this.config.customTemplate.html(code, metadata);
            text = this.config.customTemplate.text?.(code, metadata) || this.generateTextContent(code, metadata);
        } else {
            // Use default templates
            html = this.generateHtmlContent(code, metadata);
            text = this.generateTextContent(code, metadata);
        }

        return {
            from,
            to: to.trim(),
            subject,
            text,
            html,
            messageId: this.generateMessageId(),
            headers: {
                'X-Mailer': 'Authrix SMTP Service',
                'X-Priority': '1',
                ...metadata.customHeaders
            },
            ...(replyTo && { replyTo })
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
     * Generate message ID
     */
    private generateMessageId(): string {
        const timestamp = Date.now();
        const random = Math.random().toString(36).substring(2, 8);
        const domain = this.config.from.split('@')[1] || 'localhost';
        return `<${timestamp}.${random}@${domain}>`;
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

${metadata.supportEmail ? `Need help? Contact us at ${metadata.supportEmail}` : ''}

---
${appName}
This is an automated message, please do not reply.
`.trim();
    }

    /**
     * Generate HTML email content (optimized and clean)
     */
    private generateHtmlContent(code: string, metadata: EmailMetadata): string {
        const appName = metadata.appName || this.config.fromName;
        const primaryColor = metadata.primaryColor || '#4f46e5';
        const year = new Date().getFullYear();

        return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Email Verification</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f5f5f5;
      color: #333;
      line-height: 1.6;
    }
    .wrapper {
      max-width: 560px;
      margin: 40px auto;
      background: #fff;
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .header {
      background: ${primaryColor};
      color: white;
      padding: 30px;
      text-align: center;
    }
    .header h1 {
      font-size: 24px;
      font-weight: 500;
    }
    .content {
      padding: 35px 30px;
    }
    .content h2 {
      font-size: 20px;
      margin-bottom: 15px;
      color: #333;
    }
    .content p {
      color: #666;
      margin-bottom: 20px;
    }
    .code-box {
      background: #f8f9fa;
      border: 2px dashed ${primaryColor}40;
      border-radius: 8px;
      padding: 20px;
      margin: 30px 0;
      text-align: center;
    }
    .code {
      font-size: 32px;
      font-weight: 700;
      color: ${primaryColor};
      letter-spacing: 4px;
      font-family: monospace;
    }
    .info {
      background: #e3f2fd;
      border-left: 4px solid #2196f3;
      padding: 12px 15px;
      margin: 25px 0;
      border-radius: 4px;
      font-size: 14px;
      color: #1565c0;
    }
    .footer {
      background: #f8f9fa;
      padding: 20px 30px;
      text-align: center;
      font-size: 13px;
      color: #999;
      border-top: 1px solid #e9ecef;
    }
    @media (max-width: 600px) {
      .wrapper { margin: 20px; }
      .content { padding: 25px 20px; }
      .code { font-size: 26px; letter-spacing: 3px; }
    }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="header">
      ${metadata.logoUrl ? `<img src="${metadata.logoUrl}" alt="${appName}" style="height:40px;margin-bottom:15px;">` : ''}
      <h1>${appName}</h1>
    </div>
    <div class="content">
      <h2>Verify Your Email</h2>
      <p>Please use the verification code below:</p>
      <div class="code-box">
        <div class="code">${code}</div>
      </div>
      <div class="info">
        <strong>🔒 Security:</strong> This code expires in 10 minutes. Never share it with anyone.
      </div>
      <p>If you didn't request this code, you can safely ignore this email.</p>
      ${metadata.supportEmail ? `<p>Need help? <a href="mailto:${metadata.supportEmail}" style="color:${primaryColor};">${metadata.supportEmail}</a></p>` : ''}
    </div>
    <div class="footer">
      <p>© ${year} ${appName}. All rights reserved.</p>
      <p style="margin-top:8px;font-size:11px;">This is an automated message, please do not reply.</p>
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
                this.config.from,
                testCode,
                {
                    subject: 'SMTP Service Test',
                    metadata: { appName: 'Authrix Test' }
                }
            );

            return {
                success: true,
                message: 'SMTP service test successful',
                details: {
                    host: this.config.host,
                    port: this.config.port,
                    user: this.config.user,
                    from: this.config.from,
                    timestamp: new Date().toISOString()
                }
            };
        } catch (error) {
            return {
                success: false,
                message: error instanceof Error ? error.message : 'Test failed',
                details: {
                    host: this.config.host,
                    port: this.config.port,
                    error: String(error)
                }
            };
        }
    }

    /**
     * Get service information
     */
    getServiceInfo(): ServiceInfo {
        return {
            host: this.config.host,
            port: this.config.port,
            user: this.config.user,
            secure: this.config.secure,
            isInitialized: !!this.transporter
        };
    }

    /**
     * Set custom template
     */
    setCustomTemplate(template: EmailTemplate): void {
        this.config.customTemplate = template;
    }

    /**
     * Close connection
     */
    async close(): Promise<void> {
        if (this.transporter) {
            this.transporter.close();
            this.transporter = undefined;
            this.initPromise = undefined;

            if (this.config.enableLogging) {
                console.log('🔌 SMTP connection closed');
            }
        }
    }
}

// Factory function with custom template support
export function createSMTPEmailService(config?: SMTPConfig): SMTPEmailService {
    return new SMTPEmailService(config);
}

// Default instance
export const smtpEmailService = new SMTPEmailService();

// Example usage with custom template:
/*
const customTemplate: EmailTemplate = {
  html: (code, metadata) => `
    <div style="font-family: Arial, sans-serif; padding: 20px;">
      <h1>${metadata?.appName || 'App'}</h1>
      <p>Your verification code: <strong>${code}</strong></p>
    </div>
  `,
  text: (code, metadata) => `Your verification code: ${code}`
};

// Option 1: Configure during initialization
const service = createSMTPEmailService({
  host: 'smtp.example.com',
  port: 587,
  user: 'user@example.com',
  pass: 'password',
  customTemplate
});

// Option 2: Set template later
service.setCustomTemplate(customTemplate);

// Option 3: Provide template per email
await service.sendVerificationEmail('user@example.com', '123456', {
  template: '<h1>Custom HTML</h1><p>Code: {{code}}</p>'.replace('{{code}}', '123456')
});
*/