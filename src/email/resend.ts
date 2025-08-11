import { EmailService } from "../core/twoFactor";
import type { Resend } from "resend";

// Types
interface ResendConfig {
    apiKey?: string;
    fromEmail?: string;
    fromName?: string;
    maxRetries?: number;
    retryDelay?: number;
    enableLogging?: boolean;
    enableTracking?: boolean;
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
    trackingId?: string;
    tags?: string[];
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

interface ResendEmailData {
    from: string;
    to: string;
    subject: string;
    html: string;
    text: string;
    headers?: Record<string, string>;
    tags?: Array<{ name: string; value: string }>;
    replyTo?: string;
}

// Constants
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DEFAULT_RETRY_COUNT = 3;
const DEFAULT_RETRY_DELAY = 1000;
const PERMANENT_ERROR_PATTERNS = [
    'API key',
    'Unauthorized',
    'Invalid API key',
    'Invalid email',
    'Domain not verified',
    'Blocked'
];

/**
 * Optimized Resend Email Service
 */
export class ResendEmailService implements EmailService {
    private client?: Resend;
    private config: Required<Omit<ResendConfig, 'customTemplate'>> & { customTemplate?: EmailTemplate };
    private initPromise?: Promise<void>;

    constructor(config?: ResendConfig) {
        this.config = this.validateAndNormalizeConfig(config);
    }

    /**
     * Validate and normalize configuration
     */
    private validateAndNormalizeConfig(
        config?: ResendConfig
    ): Required<Omit<ResendConfig, 'customTemplate'>> & { customTemplate?: EmailTemplate } {
        const apiKey = config?.apiKey || process.env.RESEND_API_KEY || '';
        const fromEmail = config?.fromEmail || process.env.RESEND_FROM_EMAIL || '';
        const fromName = config?.fromName || process.env.RESEND_FROM_NAME || 'Authrix';

        if (!apiKey) {
            throw new Error(
                'Resend requires RESEND_API_KEY. Get your API key from https://resend.com/api-keys'
            );
        }

        if (!apiKey.startsWith('re_')) {
            throw new Error('Invalid Resend API key format. Keys should start with "re_"');
        }

        if (!fromEmail) {
            throw new Error('RESEND_FROM_EMAIL is required');
        }

        if (!EMAIL_REGEX.test(fromEmail)) {
            throw new Error('RESEND_FROM_EMAIL must be a valid email address');
        }

        return {
            apiKey: apiKey.trim(),
            fromEmail: fromEmail.trim(),
            fromName,
            maxRetries: config?.maxRetries ?? DEFAULT_RETRY_COUNT,
            retryDelay: config?.retryDelay ?? DEFAULT_RETRY_DELAY,
            enableLogging: config?.enableLogging ?? true,
            enableTracking: config?.enableTracking ?? true,
            customTemplate: config?.customTemplate
        };
    }

    /**
     * Initialize Resend client (singleton pattern)
     */
    private async ensureInitialized(): Promise<void> {
        if (this.client) return;

        if (!this.initPromise) {
            this.initPromise = this.initialize();
        }

        await this.initPromise;
    }

    /**
     * Initialize Resend client
     */
    private async initialize(): Promise<void> {
        try {
            const { Resend } = await import('resend');
            this.client = new Resend(this.config.apiKey);

            if (this.config.enableLogging) {
                console.log('✅ Resend service initialized');
            }
        } catch (error) {
            this.initPromise = undefined;
            const message = error instanceof Error ? error.message : 'Unknown error';

            if (message.includes('resend')) {
                throw new Error('Resend package not found. Install it with: npm install resend');
            }

            throw new Error(`Resend initialization failed: ${message}`);
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

        // Ensure client is initialized
        await this.ensureInitialized();

        // Prepare email data
        const emailData = this.prepareEmailData(to, code, options);

        // Send with retry logic
        await this.sendWithRetry(emailData, to);
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
     * Prepare email data
     */
    private prepareEmailData(
        to: string,
        code: string,
        options: SendEmailOptions
    ): ResendEmailData {
        const { subject = 'Email Verification Code', template, metadata = {}, replyTo } = options;
        const fromName = metadata.appName || this.config.fromName;
        const from = `${fromName} <${this.config.fromEmail}>`;

        // Use custom template if provided in options or config
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

        const emailData: ResendEmailData = {
            from,
            to: to.trim(),
            subject,
            html,
            text,
            ...(replyTo && { replyTo })
        };

        // Add headers
        if (this.config.enableTracking && metadata.trackingId) {
            emailData.headers = {
                'X-Tracking-ID': metadata.trackingId
            };
        }

        // Add tags for analytics
        if (metadata.tags && metadata.tags.length > 0) {
            emailData.tags = metadata.tags.map(tag => ({ name: 'tag', value: tag }));
        } else {
            emailData.tags = [
                { name: 'category', value: 'verification' },
                { name: 'type', value: 'email' }
            ];
        }

        return emailData;
    }

    /**
     * Send email with exponential backoff retry
     */
    private async sendWithRetry(emailData: ResendEmailData, to: string): Promise<void> {
        let lastError: Error | null = null;

        for (let attempt = 1; attempt <= this.config.maxRetries; attempt++) {
            try {
                const result = await this.client!.emails.send(emailData as any);

                if ('error' in result && result.error) {
                    throw new Error(`Resend API error: ${(result.error as any).message || 'Unknown error'}`);
                }

                if (this.config.enableLogging) {
                    console.log(`✅ Email sent to ${to} (ID: ${(result as any).data?.id})`);
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
        const primaryColor = metadata.primaryColor || '#2563eb';
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
      background: #f3f4f6;
      color: #111827;
      line-height: 1.6;
    }
    .wrapper {
      max-width: 560px;
      margin: 40px auto;
      background: #fff;
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    .header {
      background: ${primaryColor};
      color: white;
      padding: 32px;
      text-align: center;
    }
    .header h1 {
      font-size: 24px;
      font-weight: 600;
    }
    .content {
      padding: 40px 32px;
    }
    .content h2 {
      font-size: 20px;
      margin-bottom: 16px;
      color: #111827;
    }
    .content p {
      color: #6b7280;
      margin-bottom: 24px;
    }
    .code-box {
      background: #f9fafb;
      border: 2px solid #e5e7eb;
      border-radius: 8px;
      padding: 24px;
      margin: 32px 0;
      text-align: center;
    }
    .code {
      font-size: 36px;
      font-weight: 700;
      color: ${primaryColor};
      letter-spacing: 4px;
      font-family: monospace;
    }
    .warning {
      background: #fef3c7;
      border-left: 4px solid #f59e0b;
      padding: 12px 16px;
      margin: 24px 0;
      border-radius: 4px;
      font-size: 14px;
      color: #92400e;
    }
    .footer {
      background: #f9fafb;
      padding: 24px 32px;
      text-align: center;
      font-size: 13px;
      color: #6b7280;
      border-top: 1px solid #e5e7eb;
    }
    .footer a {
      color: ${primaryColor};
      text-decoration: none;
    }
    @media (max-width: 600px) {
      .wrapper { margin: 20px; }
      .content, .footer { padding: 24px; }
      .code { font-size: 28px; }
    }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="header">
      ${metadata.logoUrl ? `<img src="${metadata.logoUrl}" alt="${appName}" style="height:40px;margin-bottom:16px;">` : ''}
      <h1>${appName}</h1>
    </div>
    <div class="content">
      <h2>Verify Your Email</h2>
      <p>Please use the verification code below to confirm your email address:</p>
      <div class="code-box">
        <div class="code">${code}</div>
      </div>
      <div class="warning">
        <strong>⚠️ Security:</strong> This code expires in 10 minutes. Never share it with anyone.
      </div>
      <p>If you didn't request this code, you can safely ignore this email.</p>
      ${metadata.supportEmail ? `<p>Need help? <a href="mailto:${metadata.supportEmail}">${metadata.supportEmail}</a></p>` : ''}
    </div>
    <div class="footer">
      <p>© ${year} ${appName}. All rights reserved.</p>
      <p style="margin-top:8px;font-size:12px;">This is an automated message, please do not reply.</p>
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
                this.config.fromEmail,
                testCode,
                {
                    subject: 'Resend Service Test',
                    metadata: {
                        appName: 'Authrix Test',
                        tags: ['test']
                    }
                }
            );

            return {
                success: true,
                message: 'Resend service test successful',
                details: {
                    from: this.config.fromEmail,
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
     * Set custom template
     */
    setCustomTemplate(template: EmailTemplate): void {
        this.config.customTemplate = template;
    }
}

// Factory function with custom template support
export function createResendEmailService(config?: ResendConfig): ResendEmailService {
    return new ResendEmailService(config);
}

// Default instance
export const resendEmailService = new ResendEmailService();

// Example custom template usage:
/*
const customTemplate: EmailTemplate = {
  html: (code, metadata) => `
    <div style="font-family: Arial, sans-serif; padding: 20px;">
      <h1>${metadata?.appName || 'App'}</h1>
      <p>Your code: <strong>${code}</strong></p>
    </div>
  `,
  text: (code, metadata) => `Your verification code: ${code}`
};

const service = createResendEmailService({
  customTemplate,
  apiKey: 'your-api-key',
  fromEmail: 'noreply@example.com'
});

// Or set template later:
service.setCustomTemplate(customTemplate);

// Or provide template per email:
await service.sendVerificationEmail('user@example.com', '123456', {
  template: '<h1>Custom HTML</h1><p>Code: {{code}}</p>'.replace('{{code}}', '123456')
});
*/