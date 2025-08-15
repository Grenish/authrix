import { describe, it, expect, beforeEach } from '@jest/globals';
import { EmailServiceRegistry, type EmailService } from '../../core/emailRegistry';
import { initiateEmailVerification } from '../../core/twoFactor';

class FakeEmailService implements EmailService {
  public sent: Array<{ to: string; code: string; options?: any }> = [];
  async sendVerificationEmail(to: string, code: string, options?: any): Promise<void> {
    this.sent.push({ to, code, options });
  }
}

// Minimal mock DB adapter for two-factor storage
const memoryCodes: any[] = [];
const mockDb = {
  storeTwoFactorCode: async (code: any) => { memoryCodes.push(code); },
  getTwoFactorCode: async (id: string) => memoryCodes.find(c => c.id === id),
  updateTwoFactorCode: async (id: string, patch: any) => {
    const idx = memoryCodes.findIndex(c => c.id === id); if (idx >= 0) memoryCodes[idx] = { ...memoryCodes[idx], ...patch };
  }
} as any;

// Patch authConfig singleton indirectly by importing config and setting fields
import { authConfig } from '../../config';

describe('TwoFactor email flow with unified registry', () => {
  beforeEach(() => {
    EmailServiceRegistry.clear();
    memoryCodes.length = 0;
    // Inject mock db
    (authConfig as any).db = mockDb;
  });

  it('generates a code and sends email via default service', async () => {
    const svc = new FakeEmailService();
    EmailServiceRegistry.register('console', svc);
    EmailServiceRegistry.setDefault('console');

    const userId = 'user-1';
    const email = 'user@example.com';

    const res = await initiateEmailVerification(userId, email, { subject: 'Hello' });

    expect(res.codeId).toBeDefined();
    expect(res.expiresAt).toBeInstanceOf(Date);
    expect(memoryCodes.length).toBe(1);

    // Ensure email was sent
    expect(svc.sent.length).toBe(1);
    expect(svc.sent[0].to).toBe(email);
    expect(typeof svc.sent[0].code).toBe('string');
  });
});
