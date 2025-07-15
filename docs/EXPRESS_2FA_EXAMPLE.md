# Express.js 2FA Example

This is a complete example showing how to set up Authrix with 2FA email verification in an Express.js application.

## Setup

```bash
# Install dependencies
npm install express authrix nodemailer @types/nodemailer
npm install -D @types/express typescript tsx

# Set environment variables
echo "MONGO_URI=mongodb://localhost:27017" > .env
echo "DB_NAME=authrix_demo" >> .env
echo "JWT_SECRET=your-super-secret-jwt-key" >> .env
echo "GMAIL_USER=your-email@gmail.com" >> .env
echo "GMAIL_APP_PASSWORD=your-app-password" >> .env
echo "DEFAULT_EMAIL_SERVICE=gmail" >> .env
```

## Complete Server Code

```typescript
// server.ts
import express from 'express';
import { initAuth } from 'authrix';
import { mongoAdapter } from 'authrix/adapters/mongo';
import 'authrix/email'; // Initialize email services

// Import authentication endpoints
import { 
  sendVerificationCodeHandler,
  verifyCodeHandler,
  signupWithVerificationHandler,
  getEmailServicesHandler
} from 'authrix/core/emailEndpoints';

// Import basic auth functions for Express
import { signupExpress, signinExpress, getCurrentUser } from 'authrix/universal';

const app = express();
app.use(express.json());

// Initialize Authrix
initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter,
});

// Basic auth routes
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await signupExpress(email, password, req, res);
    res.status(201).json({ success: true, user });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

app.post('/api/auth/signin', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await signinExpress(email, password, req, res);
    res.json({ success: true, user });
  } catch (error) {
    res.status(401).json({ success: false, error: error.message });
  }
});

app.get('/api/auth/me', async (req, res) => {
  try {
    const user = await getCurrentUser(req);
    if (!user) {
      return res.status(401).json({ success: false, error: 'Not authenticated' });
    }
    res.json({ success: true, user });
  } catch (error) {
    res.status(401).json({ success: false, error: error.message });
  }
});

// 2FA Email Verification routes
app.post('/api/auth/send-verification-code', sendVerificationCodeHandler);
app.post('/api/auth/verify-code', verifyCodeHandler);
app.post('/api/auth/signup-with-verification', signupWithVerificationHandler);
app.get('/api/auth/email-services', getEmailServicesHandler);

// Static files for demo
app.use(express.static('public'));

// Error handling middleware
app.use((error: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Server error:', error);
  res.status(500).json({ 
    success: false, 
    error: 'Internal server error' 
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log('📧 Email service configured and ready');
});
```

## Frontend Demo (HTML + Vanilla JS)

```html
<!-- public/index.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authrix 2FA Demo</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .container { background: #f5f5f5; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .hidden { display: none; }
        .success { color: green; }
        .error { color: red; }
        .btn { padding: 10px 15px; margin: 5px; border: none; border-radius: 4px; cursor: pointer; }
        .btn-primary { background: #007bff; color: white; }
        .btn-success { background: #28a745; color: white; }
        .btn-secondary { background: #6c757d; color: white; }
        input { padding: 8px; margin: 5px; border: 1px solid #ccc; border-radius: 4px; width: 200px; }
        .code-input { width: 100px; text-align: center; font-size: 18px; }
    </style>
</head>
<body>
    <h1>🔐 Authrix 2FA Demo</h1>
    
    <!-- Authentication Status -->
    <div class="container">
        <h3>Authentication Status</h3>
        <div id="auth-status">Checking...</div>
        <button class="btn btn-secondary" onclick="logout()" id="logout-btn" style="display: none;">Logout</button>
    </div>

    <!-- Signup with 2FA -->
    <div class="container" id="signup-section">
        <h3>Signup with Email Verification</h3>
        <input type="email" id="signup-email" placeholder="Email" />
        <input type="password" id="signup-password" placeholder="Password" />
        <button class="btn btn-primary" onclick="signupWithVerification()">Signup & Send Verification</button>
        <div id="signup-message"></div>
    </div>

    <!-- Email Verification -->
    <div class="container hidden" id="verification-section">
        <h3>Verify Your Email</h3>
        <p>Enter the 6-digit code sent to your email:</p>
        <input type="text" id="verification-code" class="code-input" placeholder="123456" maxlength="6" />
        <button class="btn btn-success" onclick="verifyCode()">Verify</button>
        <button class="btn btn-secondary" onclick="resendCode()">Resend Code</button>
        <div id="verification-message"></div>
        <p id="attempts-remaining"></p>
    </div>

    <!-- Manual Verification (for existing users) -->
    <div class="container" id="manual-verification-section">
        <h3>Send Verification Code (Existing Users)</h3>
        <input type="email" id="manual-email" placeholder="Email" />
        <button class="btn btn-primary" onclick="sendVerificationCode()">Send Code</button>
        <div id="manual-message"></div>
    </div>

    <!-- Email Services Info -->
    <div class="container">
        <h3>Email Services</h3>
        <button class="btn btn-secondary" onclick="checkEmailServices()">Check Services</button>
        <div id="services-info"></div>
    </div>

    <script>
        let currentCodeId = null;
        let currentEmail = null;

        // Check authentication status on page load
        window.addEventListener('load', checkAuthStatus);

        async function checkAuthStatus() {
            try {
                const response = await fetch('/api/auth/me', { credentials: 'include' });
                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('auth-status').innerHTML = `
                        <span class="success">✅ Authenticated as: ${data.user.email}</span>
                    `;
                    document.getElementById('logout-btn').style.display = 'inline-block';
                    document.getElementById('signup-section').style.display = 'none';
                } else {
                    document.getElementById('auth-status').innerHTML = `
                        <span class="error">❌ Not authenticated</span>
                    `;
                }
            } catch (error) {
                document.getElementById('auth-status').innerHTML = `
                    <span class="error">❌ Error checking status</span>
                `;
            }
        }

        async function signupWithVerification() {
            const email = document.getElementById('signup-email').value;
            const password = document.getElementById('signup-password').value;
            
            if (!email || !password) {
                document.getElementById('signup-message').innerHTML = 
                    '<span class="error">Please enter email and password</span>';
                return;
            }

            try {
                const response = await fetch('/api/auth/signup-with-verification', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({
                        email,
                        password,
                        autoSendVerification: true
                    })
                });

                const data = await response.json();
                
                if (data.success) {
                    currentCodeId = data.data.verification.codeId;
                    currentEmail = email;
                    
                    document.getElementById('signup-message').innerHTML = 
                        `<span class="success">${data.data.verification.message}</span>`;
                    
                    document.getElementById('verification-section').classList.remove('hidden');
                    document.getElementById('signup-section').style.display = 'none';
                } else {
                    document.getElementById('signup-message').innerHTML = 
                        `<span class="error">${data.error.message}</span>`;
                }
            } catch (error) {
                document.getElementById('signup-message').innerHTML = 
                    '<span class="error">Signup failed</span>';
            }
        }

        async function verifyCode() {
            const code = document.getElementById('verification-code').value;
            
            if (!code || !currentCodeId) {
                document.getElementById('verification-message').innerHTML = 
                    '<span class="error">Please enter verification code</span>';
                return;
            }

            try {
                const response = await fetch('/api/auth/verify-code', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({
                        codeId: currentCodeId,
                        code: code
                    })
                });

                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('verification-message').innerHTML = 
                        `<span class="success">${data.data.message}</span>`;
                    
                    // Refresh auth status
                    setTimeout(checkAuthStatus, 1000);
                    
                    // Hide verification section
                    setTimeout(() => {
                        document.getElementById('verification-section').classList.add('hidden');
                    }, 2000);
                } else {
                    document.getElementById('verification-message').innerHTML = 
                        `<span class="error">${data.error.message}</span>`;
                    
                    document.getElementById('attempts-remaining').innerHTML = 
                        `Attempts remaining: ${data.error.attemptsRemaining || 0}`;
                }
            } catch (error) {
                document.getElementById('verification-message').innerHTML = 
                    '<span class="error">Verification failed</span>';
            }
        }

        async function resendCode() {
            if (!currentEmail) {
                document.getElementById('verification-message').innerHTML = 
                    '<span class="error">No email to resend to</span>';
                return;
            }

            try {
                const response = await fetch('/api/auth/send-verification-code', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ email: currentEmail })
                });

                const data = await response.json();
                
                if (data.success) {
                    currentCodeId = data.data.codeId;
                    document.getElementById('verification-message').innerHTML = 
                        `<span class="success">${data.data.message}</span>`;
                } else {
                    document.getElementById('verification-message').innerHTML = 
                        `<span class="error">${data.error.message}</span>`;
                }
            } catch (error) {
                document.getElementById('verification-message').innerHTML = 
                    '<span class="error">Failed to resend code</span>';
            }
        }

        async function sendVerificationCode() {
            const email = document.getElementById('manual-email').value;
            
            if (!email) {
                document.getElementById('manual-message').innerHTML = 
                    '<span class="error">Please enter email</span>';
                return;
            }

            try {
                const response = await fetch('/api/auth/send-verification-code', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ email })
                });

                const data = await response.json();
                
                if (data.success) {
                    currentCodeId = data.data.codeId;
                    currentEmail = email;
                    
                    document.getElementById('manual-message').innerHTML = 
                        `<span class="success">${data.data.message}</span>`;
                    
                    document.getElementById('verification-section').classList.remove('hidden');
                } else {
                    document.getElementById('manual-message').innerHTML = 
                        `<span class="error">${data.error.message}</span>`;
                }
            } catch (error) {
                document.getElementById('manual-message').innerHTML = 
                    '<span class="error">Failed to send code</span>';
            }
        }

        async function checkEmailServices() {
            try {
                const response = await fetch('/api/auth/email-services');
                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('services-info').innerHTML = `
                        <div>
                            <p><strong>Available Services:</strong> ${data.data.availableServices.join(', ')}</p>
                            <p><strong>Configured Services:</strong> ${data.data.configuredServices.join(', ')}</p>
                            <p><strong>Current Default:</strong> ${data.data.currentDefault}</p>
                        </div>
                    `;
                } else {
                    document.getElementById('services-info').innerHTML = 
                        `<span class="error">Failed to load services</span>`;
                }
            } catch (error) {
                document.getElementById('services-info').innerHTML = 
                    '<span class="error">Error loading services</span>';
            }
        }

        async function logout() {
            try {
                // You would implement logout endpoint
                // For now, just clear cookies and refresh
                document.cookie = 'authToken=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
                location.reload();
            } catch (error) {
                console.error('Logout failed:', error);
            }
        }
    </script>
</body>
</html>
```

## Running the Demo

1. **Start MongoDB** (if using locally):
   ```bash
   mongod --dbpath ./data
   ```

2. **Run the server**:
   ```bash
   npx tsx server.ts
   ```

3. **Open your browser**:
   ```
   http://localhost:3000
   ```

## What the Demo Shows

- ✅ **Signup with automatic email verification**
- ✅ **Manual verification code sending**
- ✅ **Code verification with attempt tracking**
- ✅ **Resend functionality**
- ✅ **Email service status checking**
- ✅ **Authentication status tracking**
- ✅ **Real-time feedback and error handling**

## Email Service Setup

The demo uses Gmail by default. To set up:

1. **Enable 2-Step Verification** in your Google Account
2. **Generate an App Password**:
   - Go to https://myaccount.google.com/apppasswords
   - Generate a password for "Mail"
   - Use this password in `GMAIL_APP_PASSWORD`

3. **Update .env**:
   ```bash
   GMAIL_USER=your-actual-email@gmail.com
   GMAIL_APP_PASSWORD=your-16-character-app-password
   ```

## Testing Different Email Services

Change the `DEFAULT_EMAIL_SERVICE` environment variable:

```bash
# For development (logs to console)
DEFAULT_EMAIL_SERVICE=console

# For Resend
DEFAULT_EMAIL_SERVICE=resend
RESEND_API_KEY=your-api-key
RESEND_FROM_EMAIL=noreply@yourdomain.com

# For SendGrid
DEFAULT_EMAIL_SERVICE=sendgrid
SENDGRID_API_KEY=your-api-key
SENDGRID_FROM_EMAIL=verified-sender@yourdomain.com
```

This example demonstrates the complete 2FA email verification workflow with Authrix!
