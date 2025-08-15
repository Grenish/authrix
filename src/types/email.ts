// Shared email-related types for providers and core

export interface EmailTemplate {
  html: (code: string, metadata?: EmailMetadata) => string;
  text?: (code: string, metadata?: EmailMetadata) => string;
}

export interface EmailMetadata {
  appName?: string;
  primaryColor?: string;
  logoUrl?: string;
  supportEmail?: string;
  trackingId?: string;
  customHeaders?: Record<string, string>;
  tags?: string[];
  // Diagnostics (non-PII): rate limit info for internal logs only
  rateLimit?: {
    attemptsRemaining?: number;
    blockedUntil?: string; // ISO string if applicable
  };
  [key: string]: any;
}

export interface SendEmailOptions {
  subject?: string;
  template?: string;
  metadata?: EmailMetadata;
  replyTo?: string;
}

export interface TestResult {
  success: boolean;
  message: string;
  details?: Record<string, any>;
}

// Optional capability map each email provider can expose for DX
export interface EmailServiceCapabilities {
  // Supports passing raw HTML/text templates per call or via config
  templates?: boolean;
  // Supports setting custom headers on outbound emails
  headers?: boolean;
  // Supports provider-side tracking/analytics toggles (open/click)
  tracking?: boolean;
  // Supports tagging/categorization (tags, categories, custom args)
  tags?: boolean;
  // Supports setting replyTo on messages
  replyTo?: boolean;
}
