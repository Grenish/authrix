import axios from "axios";

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !REDIRECT_URI) {
    throw new Error("Missing Google OAuth environment variables. Please set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and GOOGLE_REDIRECT_URI.");
}

export function getGoogleOAuthURL(state: string) {
    const params = new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID!,
        redirect_uri: REDIRECT_URI!,
        response_type: "code",
        scope: "openid profile email",
        access_type: "offline",
        prompt: "consent",
        state,
    });

    return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
}

export async function handleGoogleCallback(code: string) {
    try {
        const tokenRes = await axios.post(
            "https://oauth2.googleapis.com/token",
            new URLSearchParams({
                code,
                client_id: GOOGLE_CLIENT_ID!,
                client_secret: GOOGLE_CLIENT_SECRET!,
                redirect_uri: REDIRECT_URI!,
                grant_type: "authorization_code",
            }),
            {
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            }
        );

        const { id_token } = tokenRes.data;
        if (!id_token) throw new Error("Google OAuth failed: no id_token");

        // Verify the id_token to get user info securely
        const userRes = await axios.get(`https://oauth2.googleapis.com/tokeninfo?id_token=${id_token}`);

        const { sub, email, name, picture, email_verified } = userRes.data;

        if (userRes.data.aud !== GOOGLE_CLIENT_ID) {
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
