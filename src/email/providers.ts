import { EmailService } from "../core/twoFactor";

/**
 * Gmail SMTP Email Service
 * Requires: nodemailer
 * 
 * Setup:
 * 1. Enable 2-Step Verification in your Google Account
 * 2. Generate an App Password: https://myaccount.google.com/apppasswords
 * 3. Set environment variables:
 *    - GMAIL_USER=your-email@gmail.com
 *    - GMAIL_APP_PASSWORD=your-app-password
 */
export class GmailEmailService implements EmailService {
  private transporter: any;
  
  constructor() {
    this.initializeTransporter();
  }
  
  private async initializeTransporter() {
    try {
      const nodemailer = await import('nodemailer');
      
      const user = process.env.GMAIL_USER;
      const appPassword = process.env.GMAIL_APP_PASSWORD;
      
      if (!user || !appPassword) {
        throw new Error(
          'Gmail email service requires GMAIL_USER and GMAIL_APP_PASSWORD environment variables. ' +
          'Generate an app password at https://myaccount.google.com/apppasswords'
        );
      }
      
      this.transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user,
          pass: appPassword
        }
      });
      
      // Verify connection
      await this.transporter.verify();
      console.log('Gmail email service initialized successfully');
      
    } catch (error) {
      console.error('Failed to initialize Gmail email service:', error);
      throw error;
    }
  }
  
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
    
    if (!this.transporter) {
      await this.initializeTransporter();
    }
    
    const html = template || this.getDefaultTemplate(code, metadata);
    const text = `Your verification code is: ${code}`;
    
    const mailOptions = {
      from: process.env.GMAIL_USER,
      to,
      subject,
      text,
      html
    };
    
    try {
      await this.transporter.sendMail(mailOptions);
      console.log(`Verification email sent to ${to}`);
    } catch (error) {
      console.error('Failed to send verification email:', error);
      throw new Error('Failed to send verification email');
    }
  }
  
  private getDefaultTemplate(code: string, metadata: any = {}): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Email Verification</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .code { font-size: 32px; font-weight: bold; color: #2563eb; letter-spacing: 4px; text-align: center; padding: 20px; background: #f3f4f6; border-radius: 8px; margin: 20px 0; }
          .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 14px; color: #6b7280; }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>Email Verification</h2>
          <p>Hello,</p>
          <p>Please use the following verification code to complete your email verification:</p>
          <div class="code">${code}</div>
          <p>This code will expire in 10 minutes for security reasons.</p>
          <p>If you didn't request this verification, please ignore this email.</p>
          <div class="footer">
            <p>This email was sent from ${metadata.appName || 'Your App'}.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }
}

/**
 * Resend Email Service
 * Requires: resend
 * 
 * Setup:
 * 1. Sign up at https://resend.com
 * 2. Get your API key from the dashboard
 * 3. Set environment variable: RESEND_API_KEY=your-api-key
 * 4. Verify your domain or use their test domain
 */
export class ResendEmailService implements EmailService {
  private resend: any;
  
  constructor() {
    this.initializeResend();
  }
  
  private async initializeResend() {
    try {
      const { Resend } = await import('resend');
      
      const apiKey = process.env.RESEND_API_KEY;
      if (!apiKey) {
        throw new Error(
          'Resend email service requires RESEND_API_KEY environment variable. ' +
          'Get your API key from https://resend.com/api-keys'
        );
      }
      
      this.resend = new Resend(apiKey);
      console.log('Resend email service initialized successfully');
      
    } catch (error) {
      console.error('Failed to initialize Resend email service:', error);
      throw error;
    }
  }
  
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
    
    if (!this.resend) {
      await this.initializeResend();
    }
    
    const from = process.env.RESEND_FROM_EMAIL || 'noreply@yourdomain.com';
    const html = template || this.getDefaultTemplate(code, metadata);
    
    try {
      const result = await this.resend.emails.send({
        from,
        to,
        subject,
        html
      });
      
      console.log(`Verification email sent to ${to}. Message ID: ${result.data?.id}`);
    } catch (error) {
      console.error('Failed to send verification email:', error);
      throw new Error('Failed to send verification email');
    }
  }
  
  private getDefaultTemplate(code: string, metadata: any = {}): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Email Verification</title>
        <style>
          body { font-family: system-ui, -apple-system, sans-serif; line-height: 1.6; color: #1f2937; margin: 0; padding: 0; }
          .container { max-width: 600px; margin: 0 auto; padding: 40px 20px; }
          .header { text-align: center; margin-bottom: 40px; }
          .logo { font-size: 24px; font-weight: bold; color: #2563eb; }
          .code-container { text-align: center; margin: 30px 0; }
          .code { font-size: 36px; font-weight: bold; color: #2563eb; letter-spacing: 6px; padding: 24px; background: linear-gradient(135deg, #f3f4f6 0%, #e5e7eb 100%); border-radius: 12px; border: 2px solid #d1d5db; display: inline-block; }
          .content { background: #ffffff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
          .footer { margin-top: 40px; text-align: center; font-size: 14px; color: #6b7280; }
          .security-note { background: #fef3c7; border: 1px solid #fbbf24; border-radius: 8px; padding: 16px; margin: 20px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="logo">${metadata.appName || 'Authrix'}</div>
          </div>
          <div class="content">
            <h2 style="margin-top: 0; color: #1f2937;">Verify your email address</h2>
            <p>Hello,</p>
            <p>Please use the following verification code to complete your email verification:</p>
            <div class="code-container">
              <div class="code">${code}</div>
            </div>
            <div class="security-note">
              <strong>Security Notice:</strong> This code expires in 10 minutes and can only be used once.
            </div>
            <p>If you didn't request this verification, please ignore this email and consider changing your password if you suspect unauthorized access.</p>
          </div>
          <div class="footer">
            <p>Sent by ${metadata.appName || 'Your Application'}</p>
            <p style="font-size: 12px; margin-top: 20px;">This is an automated message, please do not reply.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }
}

/**
 * SendGrid Email Service
 * Requires: @sendgrid/mail
 * 
 * Setup:
 * 1. Sign up at https://sendgrid.com
 * 2. Create an API key in the dashboard
 * 3. Set environment variables:
 *    - SENDGRID_API_KEY=your-api-key
 *    - SENDGRID_FROM_EMAIL=verified-sender@yourdomain.com
 */
export class SendGridEmailService implements EmailService {
  private sgMail: any;
  
  constructor() {
    this.initializeSendGrid();
  }
  
  private async initializeSendGrid() {
    try {
      this.sgMail = await import('@sendgrid/mail');
      
      const apiKey = process.env.SENDGRID_API_KEY;
      if (!apiKey) {
        throw new Error(
          'SendGrid email service requires SENDGRID_API_KEY environment variable. ' +
          'Get your API key from https://app.sendgrid.com/settings/api_keys'
        );
      }
      
      this.sgMail.setApiKey(apiKey);
      console.log('SendGrid email service initialized successfully');
      
    } catch (error) {
      console.error('Failed to initialize SendGrid email service:', error);
      throw error;
    }
  }
  
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
    
    if (!this.sgMail) {
      await this.initializeSendGrid();
    }
    
    const from = process.env.SENDGRID_FROM_EMAIL;
    if (!from) {
      throw new Error('SendGrid requires SENDGRID_FROM_EMAIL environment variable with a verified sender email');
    }
    
    const html = template || this.getDefaultTemplate(code, metadata);
    const text = `Your verification code is: ${code}. This code expires in 10 minutes.`;
    
    const msg = {
      to,
      from,
      subject,
      text,
      html
    };
    
    try {
      await this.sgMail.send(msg);
      console.log(`Verification email sent to ${to}`);
    } catch (error) {
      console.error('Failed to send verification email:', error);
      throw new Error('Failed to send verification email');
    }
  }
  
  private getDefaultTemplate(code: string, metadata: any = {}): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Email Verification</title>
        <style>
          .email-container { max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; }
          .header { background: #1f2937; color: white; padding: 20px; text-align: center; }
          .content { padding: 30px; background: #ffffff; }
          .code-box { background: #f8fafc; border: 2px dashed #3b82f6; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }
          .verification-code { font-size: 28px; font-weight: bold; color: #3b82f6; letter-spacing: 3px; }
          .footer { background: #f9fafb; padding: 20px; text-align: center; font-size: 14px; color: #6b7280; }
        </style>
      </head>
      <body>
        <div class="email-container">
          <div class="header">
            <h1>${metadata.appName || 'Email Verification'}</h1>
          </div>
          <div class="content">
            <h2>Verify Your Email Address</h2>
            <p>Please enter the following verification code to complete your email verification:</p>
            <div class="code-box">
              <div class="verification-code">${code}</div>
            </div>
            <p><strong>Important:</strong> This code will expire in 10 minutes for security purposes.</p>
            <p>If you did not request this verification, please ignore this email.</p>
          </div>
          <div class="footer">
            <p>This email was sent by ${metadata.appName || 'Your Application'}</p>
            <p>© ${new Date().getFullYear()} All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }
}

/**
 * Console Email Service (for development/testing)
 * Logs emails to console instead of sending them
 */
export class ConsoleEmailService implements EmailService {
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
      metadata = {}
    } = options;
    
    console.log('\n📧 EMAIL SERVICE (CONSOLE MODE)');
    console.log('================================');
    console.log(`To: ${to}`);
    console.log(`Subject: ${subject}`);
    console.log(`Verification Code: ${code}`);
    console.log(`Metadata:`, metadata);
    console.log('================================\n');
    
    // Simulate email sending delay
    await new Promise(resolve => setTimeout(resolve, 100));
  }
}

/**
 * Custom SMTP Email Service
 * For any SMTP provider (Mailgun, AWS SES, etc.)
 * 
 * Setup:
 * Set environment variables:
 * - SMTP_HOST=smtp.yourprovider.com
 * - SMTP_PORT=587
 * - SMTP_USER=your-username
 * - SMTP_PASS=your-password
 * - SMTP_FROM=noreply@yourdomain.com
 */
export class SMTPEmailService implements EmailService {
  private transporter: any;
  
  constructor() {
    this.initializeTransporter();
  }
  
  private async initializeTransporter() {
    try {
      const nodemailer = await import('nodemailer');
      
      const host = process.env.SMTP_HOST;
      const port = parseInt(process.env.SMTP_PORT || '587');
      const user = process.env.SMTP_USER;
      const pass = process.env.SMTP_PASS;
      
      if (!host || !user || !pass) {
        throw new Error(
          'SMTP email service requires SMTP_HOST, SMTP_USER, and SMTP_PASS environment variables'
        );
      }
      
      this.transporter = nodemailer.createTransport({
        host,
        port,
        secure: port === 465, // true for 465, false for other ports
        auth: {
          user,
          pass
        }
      });
      
      // Verify connection
      await this.transporter.verify();
      console.log('SMTP email service initialized successfully');
      
    } catch (error) {
      console.error('Failed to initialize SMTP email service:', error);
      throw error;
    }
  }
  
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
    
    if (!this.transporter) {
      await this.initializeTransporter();
    }
    
    const from = process.env.SMTP_FROM || process.env.SMTP_USER;
    const html = template || this.getDefaultTemplate(code, metadata);
    const text = `Your verification code is: ${code}`;
    
    const mailOptions = {
      from,
      to,
      subject,
      text,
      html
    };
    
    try {
      await this.transporter.sendMail(mailOptions);
      console.log(`Verification email sent to ${to}`);
    } catch (error) {
      console.error('Failed to send verification email:', error);
      throw new Error('Failed to send verification email');
    }
  }
  
  private getDefaultTemplate(code: string, metadata: any = {}): string {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Email Verification</h2>
        <p>Your verification code is:</p>
        <div style="font-size: 24px; font-weight: bold; color: #2563eb; text-align: center; padding: 20px; background: #f3f4f6; border-radius: 8px; margin: 20px 0;">
          ${code}
        </div>
        <p>This code expires in 10 minutes.</p>
        <p>If you didn't request this, please ignore this email.</p>
      </div>
    `;
  }
}
