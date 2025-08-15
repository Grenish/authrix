# Authrix Email Providers: Environment Variables

This page documents the environment variables recognized by Authrix email providers and initialization.

Default selection
- DEFAULT_EMAIL_SERVICE: Explicit default provider name (resend | sendgrid | gmail | smtp | console)
  - Example: DEFAULT_EMAIL_SERVICE=resend

Resend
- RESEND_API_KEY: API key (required). Format: re_...
- RESEND_FROM_EMAIL: Verified sender address (required)
- RESEND_FROM_NAME: Optional sender name

SendGrid
- SENDGRID_API_KEY: API key (required). Format: SG....
- SENDGRID_FROM_EMAIL: Verified sender address (required)
- SENDGRID_FROM_NAME: Optional sender name
- SENDGRID_TEMPLATE_ID: Optional dynamic template ID

Gmail (App Password)
- GMAIL_USER: Gmail address (required)
- GMAIL_APP_PASSWORD: App password (required)
- GMAIL_FROM_NAME: Optional sender name

Custom SMTP
- SMTP_HOST: Hostname or IP (required)
- SMTP_PORT: Port (default 587)
- SMTP_USER: Username (required)
- SMTP_PASS: Password (required)
- SMTP_FROM: From email (defaults to SMTP_USER)
- SMTP_FROM_NAME: Optional sender name
- SMTP_SECURE: true for port 465/SSL (optional)
- SMTP_REQUIRE_TLS: true/false (default true)
- SMTP_TLS_REJECT_UNAUTHORIZED: false to allow self-signed (not recommended)
- SMTP_TLS_CIPHERS: Optional ciphers list

Console (dev)
- No variables required

Notes
- If multiple providers are configured, the default selection order is: resend > sendgrid > gmail > smtp > console, unless DEFAULT_EMAIL_SERVICE or config.defaultService overrides it.
- You can also pass a config alias `defaultEmailService` in code; it behaves like `defaultService`.
