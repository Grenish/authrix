import { EmailService } from "../core/twoFactor";

/**
 * SendGrid Email Service
 * Requires: @sendgrid/mail
 * 
 * Setup Instructions:
 * 1. Sign up at https://sendgrid.com
 * 2. Create an API key in the dashboard
 * 3. Verify your sender identity (domain or single sender)
 * 4. Set environment variables:
 *    - SENDGRID_API_KEY=your-api-key
 *    - SENDGRID_FROM_EMAIL=verified-sender@yourdomain.com
 *    - SENDGRID_FROM_NAME=Your App Name (optional)
 *    - SENDGRID_TEMPLATE_ID=your-template-id (optional)
 * 
 * Features:
 * - Enterprise-grade email delivery
 * - Advanced analytics and tracking
 * - Template support with dynamic data
 * - Automatic retry on failure
 * - Webhook support for delivery events
 * - Suppression list management
 */
export class SendGridEmailService implements EmailService {
  private sgMail: any;
  private isInitialized: boolean = false;
  private initializationPromise: Promise<void> | null = null;
  private readonly maxRetries: number = 3;
  private readonly retryDelay: number = 1000; // 1 second

  constructor(private options: {
    maxRetries?: number;
    retryDelay?: number;
    enableLogging?: boolean;
    enableTracking?: boolean;
    useTemplates?: boolean;
  } = {}) {
    this.maxRetries = options.maxRetries || 3;
    this.retryDelay = options.retryDelay || 1000;
  }

  /**
   * Initialize the SendGrid client
   */
  private async initializeSendGrid(): Promise<void> {
    if (this.isInitialized) return;
    
    if (this.initializationPromise) {
      return this.initializationPromise;
    }

    this.initializationPromise = this._initializeSendGrid();
    return this.initializationPromise;
  }

  private async _initializeSendGrid(): Promise<void> {
    try {
      this.sgMail = await import('@sendgrid/mail');
      
      const apiKey = process.env.SENDGRID_API_KEY;
      if (!apiKey) {
        throw new Error(
          'SendGrid email service requires SENDGRID_API_KEY environment variable. ' +
          'Get your API key from https://app.sendgrid.com/settings/api_keys'
        );
      }

      // Validate API key format
      if (!apiKey.startsWith('SG.')) {
        throw new Error('Invalid SendGrid API key format. API keys should start with "SG."');
      }

      this.sgMail.setApiKey(apiKey.trim());
      this.isInitialized = true;
      
      if (this.options.enableLogging !== false) {
        console.log('✅ SendGrid email service initialized successfully');
      }
      
    } catch (error) {
      this.isInitialized = false;
      this.initializationPromise = null;
      
      console.error('❌ Failed to initialize SendGrid email service:', error);
      
      if (error instanceof Error) {
        if (error.message.includes('@sendgrid/mail')) {
          throw new Error(
            'SendGrid package not found. Install it with: npm install @sendgrid/mail'
          );
        }
        throw error;
      }
      
      throw new Error('Failed to initialize SendGrid email service');
    }
  }

  /**
   * Send verification email with retry logic
   */
  async sendVerificationEmail(
    to: string,
    code: string,
    options: {
      subject?: string;
      template?: string;
      metadata?: any;
    } = {}
  ): Promise<void> {
    const {
      subject = 'Email Verification Code',
      template,
      metadata = {}
    } = options;

    // Input validation
    if (!to?.trim()) {
      throw new Error('Recipient email address is required');
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(to.trim())) {
      throw new Error('Invalid recipient email address format');
    }

    if (!code?.trim()) {
      throw new Error('Verification code is required');
    }

    await this.initializeSendGrid();

    const fromEmail = process.env.SENDGRID_FROM_EMAIL;
    if (!fromEmail) {
      throw new Error('SendGrid requires SENDGRID_FROM_EMAIL environment variable with a verified sender email');
    }

    // Validate from email format
    if (!emailRegex.test(fromEmail)) {
      throw new Error('SENDGRID_FROM_EMAIL must be a valid email address');
    }

    const fromName = process.env.SENDGRID_FROM_NAME || metadata.appName || 'Authrix';
    const from = `${fromName} <${fromEmail}>`;
    
    // Check if we should use templates
    const templateId = process.env.SENDGRID_TEMPLATE_ID;
    const useTemplate = this.options.useTemplates && templateId;

    let emailData: any;

    if (useTemplate) {
      // Use SendGrid template
      emailData = {
        to: to.trim(),
        from,
        templateId,
        dynamicTemplateData: {
          subject,
          verificationCode: code,
          appName: metadata.appName || 'Authrix',
          expiryMinutes: 10,
          ...metadata
        },
        headers: {
          'X-Mailer': 'Authrix SendGrid Service',
          'X-Priority': '1'
        }
      };
    } else {
      // Use custom HTML/text
      const html = template || this.getDefaultTemplate(code, metadata);
      const text = this.generateTextVersion(code, metadata);
      
      emailData = {
        to: to.trim(),
        from,
        subject,
        text,
        html,
        headers: {
          'X-Mailer': 'Authrix SendGrid Service',
          'X-Priority': '1'
        }
      };
    }

    // Add tracking settings
    if (this.options.enableTracking !== false) {
      emailData.trackingSettings = {
        clickTracking: {
          enable: true,
          enableText: false
        },
        openTracking: {
          enable: true,
          substitutionTag: '%open-track%'
        }
      };

      // Add custom tracking headers
      if (metadata.trackingId) {
        emailData.headers['X-Tracking-ID'] = metadata.trackingId;
      }
    }

    // Add categories for analytics
    emailData.categories = [
      'verification',
      'email_verification',
      ...(metadata.categories || [])
    ];

    // Add custom args for webhook data
    if (metadata.customArgs) {
      emailData.customArgs = metadata.customArgs;
    }

    let lastError: Error | null = null;
    
    // Retry logic
    for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
      try {
        const response = await this.sgMail.send(emailData);
        
        if (this.options.enableLogging !== false) {
          const messageId = response[0]?.headers?.['x-message-id'] || 'unknown';
          console.log(`✅ SendGrid verification email sent to ${to}. Message ID: ${messageId}`);
        }
        
        return; // Success, exit retry loop
        
      } catch (error) {
        lastError = this.parseSendGridError(error);
        
        if (this.options.enableLogging !== false) {
          console.warn(`⚠️ SendGrid email attempt ${attempt}/${this.maxRetries} failed:`, lastError.message);
        }
        
        // Don't retry on authentication errors
        if (lastError.message.includes('API key') || 
            lastError.message.includes('Unauthorized') ||
            lastError.message.includes('Forbidden')) {
          throw new Error(
            'SendGrid authentication failed. Please check your SENDGRID_API_KEY and ensure it has send permissions.'
          );
        }
        
        // Don't retry on permanent failures
        if (lastError.message.includes('Invalid email') ||
            lastError.message.includes('Unverified sender') ||
            lastError.message.includes('Blocked') ||
            lastError.message.includes('Suppressed')) {
          throw lastError;
        }
        
        // Wait before retry (except on last attempt)
        if (attempt < this.maxRetries) {
          await new Promise(resolve => setTimeout(resolve, this.retryDelay * attempt));
        }
      }
    }
    
    // All retries failed
    throw new Error(
      `Failed to send SendGrid verification email after ${this.maxRetries} attempts. ` +
      `Last error: ${lastError?.message || 'Unknown error'}`
    );
  }

  /**
   * Parse SendGrid error response
   */
  private parseSendGridError(error: any): Error {
    if (error?.response?.body?.errors) {
      const errors = error.response.body.errors;
      const errorMessages = errors.map((err: any) => err.message || err.field || 'Unknown error');
      return new Error(`SendGrid API error: ${errorMessages.join(', ')}`);
    }
    
    if (error?.message) {
      return new Error(`SendGrid error: ${error.message}`);
    }
    
    return new Error('SendGrid unknown error');
  }

  /**
   * Generate text version of the email
   */
  private generateTextVersion(code: string, metadata: any = {}): string {
    const appName = metadata.appName || 'Your Application';
    
    return `
Email Verification - ${appName}

Hello,

Please use the following verification code to complete your email verification:

Verification Code: ${code}

This code will expire in 10 minutes for security reasons.

If you didn't request this verification, please ignore this email and consider changing your password if you suspect unauthorized access.

Need help? Contact our support team.

---
This email was sent by ${appName}
This is an automated message, please do not reply.
    `.trim();
  }

  /**
   * Get default HTML template with professional design
   */
  private getDefaultTemplate(code: string, metadata: any = {}): string {
    const appName = metadata.appName || 'Authrix';
    const primaryColor = metadata.primaryColor || '#1a73e8';
    const logoUrl = metadata.logoUrl;
    const supportEmail = metadata.supportEmail;
    
    return `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Verification - ${appName}</title>
        <style>
          body { 
            font-family: 'Helvetica Neue', Arial, sans-serif; 
            line-height: 1.6; 
            color: #333333; 
            margin: 0; 
            padding: 0; 
            background-color: #f4f4f4;
          }
          .email-container { 
            max-width: 600px; 
            margin: 0 auto; 
            background: #ffffff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
          }
          .header { 
            background: linear-gradient(135deg, ${primaryColor} 0%, ${this.darkenColor(primaryColor, 20)} 100%);
            color: white; 
            padding: 40px 30px; 
            text-align: center; 
          }
          .header h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 300;
          }
          .content { 
            padding: 40px 30px; 
            background: #ffffff;
          }
          .verification-section {
            text-align: center;
            margin: 30px 0;
          }
          .code-label {
            font-size: 16px;
            color: #666666;
            margin-bottom: 15px;
          }
          .code-box { 
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border: 2px solid ${primaryColor};
            border-radius: 8px; 
            padding: 25px; 
            margin: 20px 0;
            display: inline-block;
          }
          .verification-code { 
            font-size: 36px; 
            font-weight: bold; 
            color: ${primaryColor}; 
            letter-spacing: 8px;
            font-family: 'Courier New', monospace;
          }
          .security-info {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 6px;
            padding: 20px;
            margin: 25px 0;
            border-left: 4px solid #fdcb6e;
          }
          .security-info h3 {
            margin: 0 0 10px 0;
            color: #856404;
            font-size: 16px;
          }
          .security-info p {
            margin: 0;
            color: #856404;
            font-size: 14px;
          }
          .instructions {
            background: #f8f9fa;
            border-radius: 6px;
            padding: 20px;
            margin: 25px 0;
          }
          .instructions h3 {
            margin: 0 0 15px 0;
            color: #333333;
            font-size: 18px;
          }
          .instructions ol {
            margin: 0;
            padding-left: 20px;
          }
          .instructions li {
            margin-bottom: 8px;
            color: #666666;
          }
          .footer { 
            background: #f8f9fa; 
            padding: 30px; 
            text-align: center; 
            border-top: 1px solid #dee2e6;
          }
          .footer-brand {
            font-size: 20px;
            font-weight: bold;
            color: ${primaryColor};
            margin-bottom: 10px;
          }
          .footer-links {
            margin: 20px 0;
          }
          .footer-links a {
            color: ${primaryColor};
            text-decoration: none;
            margin: 0 15px;
            font-size: 14px;
          }
          .footer-links a:hover {
            text-decoration: underline;
          }
          .footer-note {
            font-size: 12px;
            color: #6c757d;
            margin-top: 20px;
            line-height: 1.4;
          }
          @media (max-width: 600px) {
            .email-container { margin: 10px; }
            .content { padding: 30px 20px; }
            .header { padding: 30px 20px; }
            .verification-code { 
              font-size: 28px; 
              letter-spacing: 4px; 
            }
            .code-box { padding: 20px; }
          }
        </style>
      </head>
      <body>
        <div class="email-container">
          <div class="header">
            ${logoUrl ? `<img src="${logoUrl}" alt="${appName}" style="max-height: 50px; margin-bottom: 20px;">` : ''}
            <h1>${appName}</h1>
            <p style="margin: 10px 0 0 0; opacity: 0.9;">Email Verification Required</p>
          </div>
          <div class="content">
            <h2 style="color: #333333; margin-top: 0;">Verify Your Email Address</h2>
            <p>Hello,</p>
            <p>Thank you for signing up! To complete your registration and secure your account, please verify your email address using the code below:</p>
            
            <div class="verification-section">
              <div class="code-label">Your verification code:</div>
              <div class="code-box">
                <div class="verification-code">${code}</div>
              </div>
            </div>

            <div class="instructions">
              <h3>How to verify:</h3>
              <ol>
                <li>Copy the verification code above</li>
                <li>Return to the ${appName} application</li>
                <li>Paste the code in the verification field</li>
                <li>Click "Verify Email" to complete the process</li>
              </ol>
            </div>

            <div class="security-info">
              <h3>🔒 Security Information</h3>
              <p><strong>This code expires in 10 minutes</strong> and can only be used once. Never share this code with anyone. If you didn't request this verification, please ignore this email.</p>
            </div>

            <p>If you're having trouble with verification or didn't request this email, please contact our support team${supportEmail ? ` at <a href="mailto:${supportEmail}" style="color: ${primaryColor};">${supportEmail}</a>` : ''}.</p>
          </div>
          <div class="footer">
            <div class="footer-brand">${appName}</div>
            <p style="color: #6c757d; margin: 10px 0;">Secure email verification service</p>
            ${supportEmail ? `
              <div class="footer-links">
                <a href="mailto:${supportEmail}">Support</a>
                <a href="#">Privacy Policy</a>
                <a href="#">Terms of Service</a>
              </div>
            ` : ''}
            <div class="footer-note">
              This email was sent to verify your email address for ${appName}.<br>
              This is an automated message, please do not reply to this email.<br>
              © ${new Date().getFullYear()} ${appName}. All rights reserved.
            </div>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Darken a hex color by a percentage
   */
  private darkenColor(hex: string, percent: number): string {
    const num = parseInt(hex.replace('#', ''), 16);
    const amt = Math.round(2.55 * percent);
    const R = (num >> 16) - amt;
    const G = (num >> 8 & 0x00FF) - amt;
    const B = (num & 0x0000FF) - amt;
    return '#' + (0x1000000 + (R < 255 ? R < 1 ? 0 : R : 255) * 0x10000 +
      (G < 255 ? G < 1 ? 0 : G : 255) * 0x100 +
      (B < 255 ? B < 1 ? 0 : B : 255)).toString(16).slice(1);
  }

  /**
   * Test the SendGrid service configuration
   */
  async testConnection(): Promise<{
    success: boolean;
    message: string;
    details?: any;
  }> {
    try {
      await this.initializeSendGrid();
      
      const fromEmail = process.env.SENDGRID_FROM_EMAIL;
      if (!fromEmail) {
        throw new Error('SENDGRID_FROM_EMAIL not configured');
      }

      await this.sendVerificationEmail(
        fromEmail,
        '123456',
        {
          subject: 'SendGrid Service Test - Authrix',
          metadata: {
            appName: 'Authrix Test',
            purpose: 'connection_test',
            timestamp: new Date().toISOString(),
            categories: ['test', 'connection'],
            customArgs: {
              test_type: 'connection_test',
              service: 'sendgrid'
            }
          }
        }
      );

      return {
        success: true,
        message: 'SendGrid service test successful',
        details: {
          from: fromEmail,
          service: 'sendgrid',
          timestamp: new Date().toISOString()
        }
      };

    } catch (error) {
      return {
        success: false,
        message: error instanceof Error ? error.message : 'SendGrid service test failed',
        details: {
          error: String(error),
          timestamp: new Date().toISOString()
        }
      };
    }
  }

  /**
   * Get email statistics from SendGrid
   */
  async getEmailStats(options: {
    startDate?: string;
    endDate?: string;
    categories?: string[];
  } = {}): Promise<any> {
    if (!this.sgMail) {
      await this.initializeSendGrid();
    }

    try {
      // Note: This would require additional SendGrid API calls
      // This is a placeholder for future implementation
      return {
        note: 'Email statistics require additional SendGrid API integration',
        options,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.warn('Failed to get email statistics:', error);
      return null;
    }
  }

  /**
   * Manage suppression lists
   */
  async manageSuppression(action: 'add' | 'remove' | 'get', email?: string): Promise<any> {
    if (!this.sgMail) {
      await this.initializeSendGrid();
    }

    try {
      // Note: This would require additional SendGrid API calls
      // This is a placeholder for future implementation
      return {
        action,
        email,
        note: 'Suppression management requires additional SendGrid API integration',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.warn('Failed to manage suppression list:', error);
      return null;
    }
  }
}

// Export default instance
export const sendGridEmailService = new SendGridEmailService();

// Export factory function
export function createSendGridEmailService(options?: {
  maxRetries?: number;
  retryDelay?: number;
  enableLogging?: boolean;
  enableTracking?: boolean;
  useTemplates?: boolean;
}): SendGridEmailService {
  return new SendGridEmailService(options);
}