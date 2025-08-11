// Re-export everything from providers for convenience
export * from "./providers";

// Re-export individual services
export { GmailEmailService, gmailEmailService, createGmailEmailService } from "./gmail";
export { ResendEmailService, resendEmailService, createResendEmailService } from "./resend";
export { SendGridEmailService, sendGridEmailService, createSendGridEmailService } from "./sendgrid";
export { ConsoleEmailService, consoleEmailService, createConsoleEmailService } from "./console";
export { SMTPEmailService, smtpEmailService, createSMTPEmailService } from "./customSMTP";

// Re-export main functions
export { 
  initializeEmailServices, 
  getAvailableEmailServices, 
  getEmailServiceInstructions,
  EmailServiceRegistry
} from "./providers";

// Re-export types
export type { EmailService } from "../core/twoFactor";

/**
 * Auto-initialize email services when this module is imported in Node.js
 */
if (typeof window === 'undefined') { // Only in Node.js environment
  try {
    const { initializeEmailServices } = require("./providers");
    const result = initializeEmailServices();
    
    if (result.initialized.length > 0) {
      console.log(`📧 Authrix Email Services initialized: ${result.initialized.join(', ')}`);
      if (result.default) {
        console.log(`📧 Default email service: ${result.default}`);
      }
    }
    
    if (result.errors.length > 0) {
      console.warn('📧 Some email services failed to initialize:');
      result.errors.forEach(({ service, error }: { service: string; error: string }) => {
        console.warn(`  - ${service}: ${error}`);
      });
    }
  } catch (error) {
    console.warn('📧 Failed to auto-initialize email services:', error);
  }
}
