import { EmailService } from "../core/twoFactor";

// Import individual email service providers
export { GmailEmailService, gmailEmailService, createGmailEmailService } from "./gmail";
export { ResendEmailService, resendEmailService, createResendEmailService } from "./resend";
export { SendGridEmailService, sendGridEmailService, createSendGridEmailService } from "./sendgrid";
export { ConsoleEmailService, consoleEmailService, createConsoleEmailService } from "./console";
export { SMTPEmailService, smtpEmailService, createSMTPEmailService } from "./customSMTP";

// Re-export types for convenience
export type { EmailService } from "../core/twoFactor";

/**
 * Email Service Registry
 * Manages and provides access to different email service providers
 */
export class EmailServiceRegistry {
  private static services = new Map<string, EmailService>();
  private static defaultService: string | null = null;

  /**
   * Register an email service
   */
  static register(name: string, service: EmailService): void {
    if (!name?.trim()) {
      throw new Error('Service name is required');
    }

    if (!service || typeof service.sendVerificationEmail !== 'function') {
      throw new Error('Invalid email service: must implement sendVerificationEmail method');
    }

    this.services.set(name.toLowerCase(), service);
  }

  /**
   * Get a registered email service
   */
  static get(name: string): EmailService | undefined {
    return this.services.get(name.toLowerCase());
  }

  /**
   * Set the default email service
   */
  static setDefault(name: string): void {
    const service = this.get(name);
    if (!service) {
      throw new Error(`Email service '${name}' not found. Register it first.`);
    }
    this.defaultService = name.toLowerCase();
  }

  /**
   * Get the default email service
   */
  static getDefault(): EmailService | undefined {
    if (this.defaultService) {
      return this.get(this.defaultService);
    }
    
    // Auto-detect default based on environment variables
    const autoDefault = this.detectDefaultService();
    if (autoDefault) {
      return this.get(autoDefault);
    }

    return undefined;
  }

  /**
   * List all registered services
   */
  static list(): string[] {
    return Array.from(this.services.keys());
  }

  /**
   * Check if a service is registered
   */
  static has(name: string): boolean {
    return this.services.has(name.toLowerCase());
  }

  /**
   * Remove a service
   */
  static remove(name: string): boolean {
    const removed = this.services.delete(name.toLowerCase());
    if (this.defaultService === name.toLowerCase()) {
      this.defaultService = null;
    }
    return removed;
  }

  /**
   * Clear all services
   */
  static clear(): void {
    this.services.clear();
    this.defaultService = null;
  }

  /**
   * Auto-detect default service based on environment variables
   */
  private static detectDefaultService(): string | null {
    // Check for explicit default setting
    const explicitDefault = process.env.DEFAULT_EMAIL_SERVICE;
    if (explicitDefault && this.has(explicitDefault)) {
      return explicitDefault.toLowerCase();
    }

    // Auto-detect based on available environment variables
    if (process.env.RESEND_API_KEY) return 'resend';
    if (process.env.SENDGRID_API_KEY) return 'sendgrid';
    if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) return 'gmail';
    if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) return 'smtp';
    
    // Fallback to console for development
    if (process.env.NODE_ENV === 'development') return 'console';

    return null;
  }

  /**
   * Get service configuration status
   */
  static getServiceStatus(): {
    registered: string[];
    configured: string[];
    default: string | null;
    recommendations: string[];
  } {
    const registered = this.list();
    const configured: string[] = [];
    const recommendations: string[] = [];

    // Check which services are properly configured
    if (process.env.RESEND_API_KEY) {
      configured.push('resend');
      if (!registered.includes('resend')) {
        recommendations.push('Register Resend service: EmailServiceRegistry.register("resend", new ResendEmailService())');
      }
    }

    if (process.env.SENDGRID_API_KEY && process.env.SENDGRID_FROM_EMAIL) {
      configured.push('sendgrid');
      if (!registered.includes('sendgrid')) {
        recommendations.push('Register SendGrid service: EmailServiceRegistry.register("sendgrid", new SendGridEmailService())');
      }
    }

    if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) {
      configured.push('gmail');
      if (!registered.includes('gmail')) {
        recommendations.push('Register Gmail service: EmailServiceRegistry.register("gmail", new GmailEmailService())');
      }
    }

    if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
      configured.push('smtp');
      if (!registered.includes('smtp')) {
        recommendations.push('Register SMTP service: EmailServiceRegistry.register("smtp", new SMTPEmailService())');
      }
    }

    // Always available
    configured.push('console');
    if (!registered.includes('console')) {
      recommendations.push('Register Console service: EmailServiceRegistry.register("console", new ConsoleEmailService())');
    }

    return {
      registered,
      configured,
      default: this.defaultService,
      recommendations
    };
  }
}

/**
 * Auto-initialize common email services based on environment variables
 */
export function initializeEmailServices(): {
  initialized: string[];
  errors: Array<{ service: string; error: string }>;
  default: string | null;
} {
  const initialized: string[] = [];
  const errors: Array<{ service: string; error: string }> = [];

  // Always register console service
  try {
    const { ConsoleEmailService } = require('./console');
    EmailServiceRegistry.register('console', new ConsoleEmailService());
    initialized.push('console');
  } catch (error) {
    errors.push({
      service: 'console',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }

  // Register Resend if configured
  if (process.env.RESEND_API_KEY) {
    try {
      const { ResendEmailService } = require('./resend');
      EmailServiceRegistry.register('resend', new ResendEmailService());
      initialized.push('resend');
    } catch (error) {
      errors.push({
        service: 'resend',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  // Register SendGrid if configured
  if (process.env.SENDGRID_API_KEY) {
    try {
      const { SendGridEmailService } = require('./sendgrid');
      EmailServiceRegistry.register('sendgrid', new SendGridEmailService());
      initialized.push('sendgrid');
    } catch (error) {
      errors.push({
        service: 'sendgrid',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  // Register Gmail if configured
  if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) {
    try {
      const { GmailEmailService } = require('./gmail');
      EmailServiceRegistry.register('gmail', new GmailEmailService());
      initialized.push('gmail');
    } catch (error) {
      errors.push({
        service: 'gmail',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  // Register SMTP if configured
  if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    try {
      const { SMTPEmailService } = require('./customSMTP');
      EmailServiceRegistry.register('smtp', new SMTPEmailService());
      initialized.push('smtp');
    } catch (error) {
      errors.push({
        service: 'smtp',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  // Set default service
  let defaultService: string | null = null;
  const explicitDefault = process.env.DEFAULT_EMAIL_SERVICE;
  
  if (explicitDefault && initialized.includes(explicitDefault.toLowerCase())) {
    EmailServiceRegistry.setDefault(explicitDefault);
    defaultService = explicitDefault.toLowerCase();
  } else if (initialized.length > 0) {
    // Auto-select best default
    const priority = ['resend', 'sendgrid', 'gmail', 'smtp', 'console'];
    for (const service of priority) {
      if (initialized.includes(service)) {
        EmailServiceRegistry.setDefault(service);
        defaultService = service;
        break;
      }
    }
  }

  return {
    initialized,
    errors,
    default: defaultService
  };
}

/**
 * Get available email services with configuration status
 */
export function getAvailableEmailServices(): {
  available: Array<{
    name: string;
    description: string;
    configured: boolean;
    requirements: string[];
  }>;
  configured: string[];
  instructions: Record<string, any>;
} {
  const services = [
    {
      name: 'resend',
      description: 'Modern email API with excellent deliverability',
      configured: !!(process.env.RESEND_API_KEY),
      requirements: ['RESEND_API_KEY', 'RESEND_FROM_EMAIL (optional)']
    },
    {
      name: 'sendgrid',
      description: 'Enterprise email service with advanced features',
      configured: !!(process.env.SENDGRID_API_KEY && process.env.SENDGRID_FROM_EMAIL),
      requirements: ['SENDGRID_API_KEY', 'SENDGRID_FROM_EMAIL']
    },
    {
      name: 'gmail',
      description: 'Gmail SMTP service using App Passwords',
      configured: !!(process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD),
      requirements: ['GMAIL_USER', 'GMAIL_APP_PASSWORD']
    },
    {
      name: 'smtp',
      description: 'Custom SMTP service for any provider',
      configured: !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS),
      requirements: ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS']
    },
    {
      name: 'console',
      description: 'Development service that logs emails to console',
      configured: true,
      requirements: []
    }
  ];

  const configured = services.filter(s => s.configured).map(s => s.name);

  const instructions = {
    resend: {
      setup: [
        '1. Sign up at https://resend.com',
        '2. Get your API key from the dashboard',
        '3. Set RESEND_API_KEY environment variable',
        '4. Optionally set RESEND_FROM_EMAIL'
      ],
      example: 'RESEND_API_KEY=re_123456789'
    },
    sendgrid: {
      setup: [
        '1. Sign up at https://sendgrid.com',
        '2. Create an API key in the dashboard',
        '3. Verify your sender identity',
        '4. Set SENDGRID_API_KEY and SENDGRID_FROM_EMAIL'
      ],
      example: 'SENDGRID_API_KEY=SG.123456789\nSENDGRID_FROM_EMAIL=noreply@yourdomain.com'
    },
    gmail: {
      setup: [
        '1. Enable 2-Step Verification in your Google Account',
        '2. Generate an App Password at https://myaccount.google.com/apppasswords',
        '3. Set GMAIL_USER and GMAIL_APP_PASSWORD'
      ],
      example: 'GMAIL_USER=your-email@gmail.com\nGMAIL_APP_PASSWORD=your-app-password'
    },
    smtp: {
      setup: [
        '1. Get SMTP credentials from your email provider',
        '2. Set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS',
        '3. Optionally set SMTP_FROM'
      ],
      example: 'SMTP_HOST=smtp.yourprovider.com\nSMTP_PORT=587\nSMTP_USER=username\nSMTP_PASS=password'
    },
    console: {
      setup: [
        'No setup required - logs emails to console for development'
      ],
      example: 'Automatically available in development mode'
    }
  };

  return {
    available: services,
    configured,
    instructions
  };
}

/**
 * Get email service setup instructions
 */
export function getEmailServiceInstructions(): Record<string, {
  description: string;
  requirements: string[];
  setup: string[];
  example: string;
  links?: string[];
}> {
  return {
    resend: {
      description: 'Modern email API with excellent deliverability and analytics',
      requirements: ['RESEND_API_KEY', 'RESEND_FROM_EMAIL (optional)'],
      setup: [
        'Sign up at https://resend.com',
        'Create an API key in your dashboard',
        'Verify your domain (or use test domain)',
        'Set environment variables'
      ],
      example: 'RESEND_API_KEY=re_123456789\nRESEND_FROM_EMAIL=noreply@yourdomain.com',
      links: ['https://resend.com/docs', 'https://resend.com/api-keys']
    },
    sendgrid: {
      description: 'Enterprise-grade email service with advanced features',
      requirements: ['SENDGRID_API_KEY', 'SENDGRID_FROM_EMAIL'],
      setup: [
        'Sign up at https://sendgrid.com',
        'Create an API key with Mail Send permissions',
        'Verify your sender identity (domain or single sender)',
        'Set environment variables'
      ],
      example: 'SENDGRID_API_KEY=SG.123456789\nSENDGRID_FROM_EMAIL=noreply@yourdomain.com',
      links: ['https://docs.sendgrid.com', 'https://app.sendgrid.com/settings/api_keys']
    },
    gmail: {
      description: 'Gmail SMTP service using App Passwords (2FA required)',
      requirements: ['GMAIL_USER', 'GMAIL_APP_PASSWORD'],
      setup: [
        'Enable 2-Step Verification in your Google Account',
        'Generate an App Password for your application',
        'Set environment variables with your Gmail address and app password'
      ],
      example: 'GMAIL_USER=your-email@gmail.com\nGMAIL_APP_PASSWORD=abcd-efgh-ijkl-mnop',
      links: ['https://myaccount.google.com/apppasswords', 'https://support.google.com/accounts/answer/185833']
    },
    smtp: {
      description: 'Custom SMTP service for any email provider',
      requirements: ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS'],
      setup: [
        'Get SMTP credentials from your email provider',
        'Configure host, port, username, and password',
        'Set optional security and authentication settings'
      ],
      example: 'SMTP_HOST=smtp.yourprovider.com\nSMTP_PORT=587\nSMTP_USER=username\nSMTP_PASS=password\nSMTP_FROM=noreply@yourdomain.com',
      links: []
    },
    console: {
      description: 'Development service that logs emails to console instead of sending',
      requirements: [],
      setup: [
        'No configuration required',
        'Automatically available for development and testing',
        'Emails are logged to console with formatting'
      ],
      example: 'No environment variables needed',
      links: []
    }
  };
}