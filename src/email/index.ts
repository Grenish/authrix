// Do not re-export deprecated helpers from providers

// Re-export individual services
export { GmailEmailService, gmailEmailService, createGmailEmailService } from "./gmail";
export { ResendEmailService, resendEmailService, createResendEmailService } from "./resend";
export { SendGridEmailService, sendGridEmailService, createSendGridEmailService } from "./sendgrid";
export { ConsoleEmailService, consoleEmailService, createConsoleEmailService } from "./console";
export { SMTPEmailService, smtpEmailService, createSMTPEmailService } from "./customSMTP";

// Re-export unified registry only
export { EmailServiceRegistry } from "../core/emailRegistry";

// Re-export types
export type { EmailService } from "../core/twoFactor";

// Note: Auto-initialization removed. Use explicit initialization via exported helpers.
