// Deprecated helpers and local registry removed. This file now only re-exports concrete providers.

export { GmailEmailService, gmailEmailService, createGmailEmailService } from "./gmail";
export { ResendEmailService, resendEmailService, createResendEmailService } from "./resend";
export { SendGridEmailService, sendGridEmailService, createSendGridEmailService } from "./sendgrid";
export { ConsoleEmailService, consoleEmailService, createConsoleEmailService } from "./console";
export { SMTPEmailService, smtpEmailService, createSMTPEmailService } from "./customSMTP";

export { EmailServiceRegistry } from "../core/emailRegistry";
export type { EmailService } from "../core/twoFactor";