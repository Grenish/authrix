import axios from "axios";

// Lazy-load environment variables to avoid errors when OAuth is not used
function getGitHubOAuthConfig() {
    const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
    const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
    const REDIRECT_URI = process.env.GITHUB_REDIRECT_URI;

    if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET || !REDIRECT_URI) {
        throw new Error("Missing GitHub OAuth environment variables. Please set GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, and GITHUB_REDIRECT_URI in your environment file. These are only required when using GitHub OAuth functionality.");
    }

    return { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, REDIRECT_URI };
}

export function getGitHubOAuthURL(state: string) {
    const { GITHUB_CLIENT_ID, REDIRECT_URI } = getGitHubOAuthConfig();
    
    const params = new URLSearchParams({
        client_id: GITHUB_CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: "read:user user:email",
        state,
    });

    return `https://github.com/login/oauth/authorize?${params.toString()}`;
}

export async function handleGitHubCallback(code: string) {
    const { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, REDIRECT_URI } = getGitHubOAuthConfig();
    
    try {
        const tokenRes = await axios.post(
            "https://github.com/login/oauth/access_token",
            {
                client_id: GITHUB_CLIENT_ID,
                client_secret: GITHUB_CLIENT_SECRET,
                code,
                redirect_uri: REDIRECT_URI,
            },
            {
                headers: {
                    Accept: "application/json",
                },
            }
        );

        const accessToken = tokenRes.data.access_token;
        if (!accessToken) throw new Error("GitHub OAuth failed: no access token");

        const userRes = await axios.get("https://api.github.com/user", {
            headers: {
                Authorization: `Bearer ${accessToken}`,
            },
        });

        const emailRes = await axios.get("https://api.github.com/user/emails", {
            headers: {
                Authorization: `Bearer ${accessToken}`,
            },
        });

        const primaryEmail = emailRes.data.find((e: any) => e.primary && e.verified)?.email;

        if (!primaryEmail) {
            throw new Error("GitHub OAuth failed: no verified primary email found.");
        }

        return {
            id: userRes.data.id.toString(),
            email: primaryEmail,
            name: userRes.data.name,
            avatar: userRes.data.avatar_url,
            provider: "github",
        };
    } catch (error) {
        console.error("Error during GitHub OAuth callback:", error);
        throw new Error("An error occurred during GitHub authentication.");
    }
}
