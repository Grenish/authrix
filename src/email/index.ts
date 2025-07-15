import { EmailService, EmailServiceRegistry } from "../core/twoFactor";

// Import email services (these will throw if dependencies aren't installed)
export { 
  GmailEmailService, 
  ResendEmailService, 
  SendGridEmailService, 
  SMTPEmailService,
  ConsoleEmailService 
} from "./providers";

/**
 * Initialize email services with error handling for missing dependencies
 */
export function initializeEmailServices(): void {
  // Always register console service for development
  try {
    const { ConsoleEmailService } = require("./providers");
    EmailServiceRegistry.register('console', new ConsoleEmailService());
    EmailServiceRegistry.register('development', new ConsoleEmailService());
  } catch (error) {
    console.warn('Failed to register console email service:', error);
  }

  // Try to register Gmail service
  try {
    const { GmailEmailService } = require("./providers");
    if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) {
      EmailServiceRegistry.register('gmail', new GmailEmailService());
      console.log('Gmail email service registered');
    }
  } catch (error) {
    console.log('Gmail email service not available. Install nodemailer to use Gmail: npm install nodemailer @types/nodemailer');
  }

  // Try to register Resend service
  try {
    const { ResendEmailService } = require("./providers");
    if (process.env.RESEND_API_KEY) {
      EmailServiceRegistry.register('resend', new ResendEmailService());
      console.log('Resend email service registered');
    }
  } catch (error) {
    console.log('Resend email service not available. Install resend to use Resend: npm install resend');
  }

  // Try to register SendGrid service
  try {
    const { SendGridEmailService } = require("./providers");
    if (process.env.SENDGRID_API_KEY) {
      EmailServiceRegistry.register('sendgrid', new SendGridEmailService());
      console.log('SendGrid email service registered');
    }
  } catch (error) {
    console.log('SendGrid email service not available. Install @sendgrid/mail to use SendGrid: npm install @sendgrid/mail');
  }

  // Try to register SMTP service
  try {
    const { SMTPEmailService } = require("./providers");
    if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
      EmailServiceRegistry.register('smtp', new SMTPEmailService());
      console.log('SMTP email service registered');
    }
  } catch (error) {
    console.log('SMTP email service not available. Install nodemailer to use SMTP: npm install nodemailer @types/nodemailer');
  }

  // Set default service based on environment
  const defaultService = process.env.DEFAULT_EMAIL_SERVICE || 
    (process.env.NODE_ENV === 'development' ? 'console' : null);
  
  if (defaultService && EmailServiceRegistry.get(defaultService)) {
    EmailServiceRegistry.register('default', EmailServiceRegistry.get(defaultService)!);
    console.log(`Default email service set to: ${defaultService}`);
  } else if (process.env.NODE_ENV === 'development') {
    // Use console service as default in development
    const consoleService = EmailServiceRegistry.get('console');
    if (consoleService) {
      EmailServiceRegistry.register('default', consoleService);
      console.log('Default email service set to: console (development mode)');
    }
  }
}

/**
 * Get configuration instructions for email services
 */
export function getEmailServiceInstructions(): Record<string, string> {
  return {
    console: `
// Console Email Service (Development/Testing)
// No configuration needed - emails are logged to console
process.env.DEFAULT_EMAIL_SERVICE = 'console';
`,
    gmail: `
// Gmail Email Service
// 1. Enable 2-Step Verification: https://myaccount.google.com/security
// 2. Generate App Password: https://myaccount.google.com/apppasswords
// 3. Install dependency: npm install nodemailer @types/nodemailer
process.env.GMAIL_USER = 'your-email@gmail.com';
process.env.GMAIL_APP_PASSWORD = 'your-app-password';
process.env.DEFAULT_EMAIL_SERVICE = 'gmail';
`,
    resend: `
// Resend Email Service
// 1. Sign up: https://resend.com
// 2. Get API key: https://resend.com/api-keys
// 3. Install dependency: npm install resend
process.env.RESEND_API_KEY = 'your-api-key';
process.env.RESEND_FROM_EMAIL = 'noreply@yourdomain.com'; // Must be verified
process.env.DEFAULT_EMAIL_SERVICE = 'resend';
`,
    sendgrid: `
// SendGrid Email Service
// 1. Sign up: https://sendgrid.com
// 2. Create API key: https://app.sendgrid.com/settings/api_keys
// 3. Install dependency: npm install @sendgrid/mail
process.env.SENDGRID_API_KEY = 'your-api-key';
process.env.SENDGRID_FROM_EMAIL = 'verified-sender@yourdomain.com';
process.env.DEFAULT_EMAIL_SERVICE = 'sendgrid';
`,
    smtp: `
// Generic SMTP Email Service (Mailgun, AWS SES, etc.)
// Install dependency: npm install nodemailer @types/nodemailer
process.env.SMTP_HOST = 'smtp.yourprovider.com';
process.env.SMTP_PORT = '587'; // or 465 for SSL
process.env.SMTP_USER = 'your-username';
process.env.SMTP_PASS = 'your-password';
process.env.SMTP_FROM = 'noreply@yourdomain.com';
process.env.DEFAULT_EMAIL_SERVICE = 'smtp';
`
  };
}

/**
 * Check which email services are available
 */
export function getAvailableEmailServices(): {
  available: string[];
  configured: string[];
  instructions: Record<string, string>;
} {
  const available = EmailServiceRegistry.list();
  const configured = available.filter(name => {
    const service = EmailServiceRegistry.get(name);
    return service !== undefined;
  });

  return {
    available,
    configured,
    instructions: getEmailServiceInstructions()
  };
}

/**
 * Auto-initialize email services when this module is imported
 */
if (typeof window === 'undefined') { // Only in Node.js environment
  initializeEmailServices();
}
