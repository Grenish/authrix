// Lazy-load environment variables to avoid errors when OAuth is not used
function getGoogleOAuthConfig() {
    const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
    const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
    const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;

    if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !REDIRECT_URI) {
        throw new Error("Missing Google OAuth environment variables. Please set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and GOOGLE_REDIRECT_URI in your environment file. These are only required when using Google OAuth functionality.");
    }

    return { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, REDIRECT_URI };
}

export function getGoogleOAuthURL(state: string) {
    const { GOOGLE_CLIENT_ID, REDIRECT_URI } = getGoogleOAuthConfig();
    
    const params = new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        response_type: "code",
        scope: "openid profile email",
        access_type: "offline",
        prompt: "consent",
        state,
    });

    return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
}

export async function handleGoogleCallback(code: string) {
    const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, REDIRECT_URI } = getGoogleOAuthConfig();
    
    try {
        const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body: new URLSearchParams({
                code,
                client_id: GOOGLE_CLIENT_ID,
                client_secret: GOOGLE_CLIENT_SECRET,
                redirect_uri: REDIRECT_URI,
                grant_type: "authorization_code",
            }).toString(),
        });

        if (!tokenRes.ok) {
            throw new Error(`Google OAuth token request failed: ${tokenRes.statusText}`);
        }

        const tokenData = await tokenRes.json();
        const { id_token } = tokenData;
        if (!id_token) throw new Error("Google OAuth failed: no id_token");

        // Verify the id_token to get user info securely
        const userRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${id_token}`);
        
        if (!userRes.ok) {
            throw new Error(`Google OAuth user info request failed: ${userRes.statusText}`);
        }

        const userData = await userRes.json();
        const { sub, email, name, picture, email_verified } = userData;

        if (userData.aud !== GOOGLE_CLIENT_ID) {
            throw new Error("Google OAuth failed: token audience mismatch.");
        }

        if (email_verified !== true) {
            throw new Error("Google OAuth failed: email not verified.");
        }

        return {
            id: sub,
            email: email,
            name: name,
            avatar: picture,
            provider: "google",
        };
    } catch (error) {
        console.error("Error during Google OAuth callback:", error);
        throw new Error("An error occurred during Google authentication.");
    }
}
