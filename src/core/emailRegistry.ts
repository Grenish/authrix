/**
 * Unified Email/SMS Service Registry
 * Single source of truth shared by core and provider modules.
 */

import type { EmailServiceCapabilities } from "../types/email";

export interface EmailService {
  sendVerificationEmail(
    to: string,
    code: string,
    options?: { subject?: string; template?: string; metadata?: any; replyTo?: string }
  ): Promise<void>;
  // Optional static/runtime-exposed capabilities for DX
  capabilities?: EmailServiceCapabilities;
}

export interface SMSService {
  sendVerificationSMS(
    to: string,
    code: string,
    options?: { template?: string; metadata?: any }
  ): Promise<void>;
}

export class EmailServiceRegistry {
  private static emailServices = new Map<string, EmailService>();
  private static smsServices = new Map<string, SMSService>();
  private static emailCapabilities = new Map<string, EmailServiceCapabilities>();

  // Email
  static register(name: string, service: EmailService): void {
    const key = (name || '').trim();
    if (!key) throw new Error('Service name is required');
    if (!service || typeof service.sendVerificationEmail !== 'function') {
      throw new Error('Invalid email service: must implement sendVerificationEmail');
    }
    this.emailServices.set(key, service);
    // Capture capabilities if provided by the service instance
    if (service.capabilities) {
      this.emailCapabilities.set(key, service.capabilities);
    }
  }

  static get(name: string): EmailService | undefined {
    return this.emailServices.get((name || '').trim());
  }

  static setDefault(name: string): void {
    const svc = this.get(name);
    if (!svc) throw new Error(`Email service '${name}' not found`);
    this.emailServices.set('default', svc);
  }

  static getDefault(): EmailService | undefined {
    return this.get('default');
  }

  static list(): string[] {
    return Array.from(this.emailServices.keys());
  }

  static getCapabilities(name: string): EmailServiceCapabilities | undefined {
    return this.emailCapabilities.get((name || '').trim());
  }

  static setCapabilities(name: string, caps: EmailServiceCapabilities): void {
    const key = (name || '').trim();
    if (!key) throw new Error('Service name is required');
    this.emailCapabilities.set(key, caps);
  }

  static unregister(name: string): boolean {
    return this.emailServices.delete((name || '').trim());
  }

  static clear(): void {
    this.emailServices.clear();
    this.emailCapabilities.clear();
  }

  static status() {
    const names = this.list();
    const caps: Record<string, EmailServiceCapabilities | undefined> = {};
    for (const n of names) {
      caps[n] = this.getCapabilities(n);
    }
    return {
      registered: names,
      hasDefault: !!this.getDefault(),
      capabilities: caps
    };
  }

  // SMS
  static registerSMS(name: string, service: SMSService): void {
    const key = (name || '').trim();
    if (!key) throw new Error('Service name is required');
    if (!service || typeof service.sendVerificationSMS !== 'function') {
      throw new Error('Invalid SMS service: must implement sendVerificationSMS');
    }
    this.smsServices.set(key, service);
  }

  static getSMS(name: string): SMSService | undefined {
    return this.smsServices.get((name || '').trim());
  }

  static setDefaultSMS(name: string): void {
    const svc = this.getSMS(name);
    if (!svc) throw new Error(`SMS service '${name}' not found`);
    this.smsServices.set('default', svc);
  }

  static getDefaultSMS(): SMSService | undefined {
    return this.getSMS('default');
  }

  static listSMS(): string[] {
    return Array.from(this.smsServices.keys());
  }

  static unregisterSMS(name: string): boolean {
    return this.smsServices.delete((name || '').trim());
  }

  static clearSMS(): void {
    this.smsServices.clear();
  }
}
