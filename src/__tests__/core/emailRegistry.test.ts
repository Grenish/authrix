import { describe, it, expect, beforeEach } from '@jest/globals';
import { EmailServiceRegistry, type EmailService } from '../../core/emailRegistry';

class FakeEmailService implements EmailService {
  public sent: Array<{ to: string; code: string; options?: any }> = [];
  capabilities = { templates: true, headers: true, tracking: false, tags: false, replyTo: true } as const;
  async sendVerificationEmail(to: string, code: string, options?: any): Promise<void> {
    this.sent.push({ to, code, options });
  }
}

describe('EmailServiceRegistry (unified)', () => {
  beforeEach(() => {
    EmailServiceRegistry.clear();
  });

  it('registers and retrieves services, sets default, and reports status with capabilities', async () => {
    const svc = new FakeEmailService();
    EmailServiceRegistry.register('test', svc);
    EmailServiceRegistry.setDefault('test');

    const got = EmailServiceRegistry.get('test');
    expect(got).toBeDefined();

    const def = EmailServiceRegistry.getDefault();
    expect(def).toBeDefined();
    expect(def).toBe(svc);

    const status = EmailServiceRegistry.status();
    expect(status.registered).toContain('test');
    expect(status.hasDefault).toBe(true);
    expect(status.capabilities.test).toEqual(svc.capabilities);
  });

  it('unregisters and clears services', () => {
    const svc = new FakeEmailService();
    EmailServiceRegistry.register('temp', svc);
    expect(EmailServiceRegistry.get('temp')).toBeDefined();

    const removed = EmailServiceRegistry.unregister('temp');
    expect(removed).toBe(true);
    expect(EmailServiceRegistry.get('temp')).toBeUndefined();

    EmailServiceRegistry.clear();
    expect(EmailServiceRegistry.list()).toHaveLength(0);
    const status = EmailServiceRegistry.status();
    expect(status.registered).toHaveLength(0);
  });
});
