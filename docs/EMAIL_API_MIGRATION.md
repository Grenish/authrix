# Email API Migration Guide (Legacy → Unified)

This guide shows how to migrate from the legacy email helpers under `src/email` to the unified registry and config-driven initialization.

## Summary
- Legacy local `EmailServiceRegistry` and `initializeEmailServices()` are deprecated.
- Use the unified `EmailServiceRegistry` from `core/emailRegistry`.
- Initialize via `initAuth({ email })` or `initEmailServices({ ... })`.

## Before (Legacy)
```ts
import { EmailServiceRegistry, initializeEmailServices } from 'authrix/src/email/providers';
import { ResendEmailService } from 'authrix/src/email/resend';

initializeEmailServices(); // side-effectful
EmailServiceRegistry.register('resend', new ResendEmailService());
EmailServiceRegistry.setDefault('resend');
```

## After (Unified)
```ts
import { initAuth } from 'authrix';

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: adapter,
  email: {
    defaultEmailService: 'resend',
    providers: {
      resend: { apiKey: process.env.RESEND_API_KEY, fromEmail: process.env.RESEND_FROM_EMAIL }
    }
  }
});
```

Or initialize email explicitly (outside of full auth init):
```ts
import { initEmailServices } from 'authrix';

initEmailServices({
  defaultEmailService: 'sendgrid',
  providers: { sendgrid: { /* options */ } },
  autoDetect: true
});
```

## Sending verification emails (unchanged usage)
```ts
import { initiateEmailVerification } from 'authrix';
await initiateEmailVerification(userId, userEmail, { subject: 'Verify your email' });
```

## Capabilities and status
```ts
import { EmailServiceRegistry } from 'authrix';
const status = EmailServiceRegistry.status();
// status.capabilities["resend"] => { templates: true, headers: true, tracking: true, tags: true, replyTo: true }
```

## Notes
- DEFAULT_EMAIL_SERVICE env var is respected when set.
- Deterministic fallback order: resend > sendgrid > gmail > smtp > console.
- See `docs/EMAIL_ENV_VARS.md` for environment setup.
