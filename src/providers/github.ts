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
        const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
            method: "POST",
            headers: {
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                client_id: GITHUB_CLIENT_ID,
                client_secret: GITHUB_CLIENT_SECRET,
                code,
                redirect_uri: REDIRECT_URI,
            }),
        });

        if (!tokenRes.ok) {
            throw new Error(`GitHub OAuth token request failed: ${tokenRes.statusText}`);
        }

        const tokenData = await tokenRes.json();
        const accessToken = tokenData.access_token;
        if (!accessToken) throw new Error("GitHub OAuth failed: no access token");

        const userRes = await fetch("https://api.github.com/user", {
            headers: {
                Authorization: `Bearer ${accessToken}`,
            },
        });

        if (!userRes.ok) {
            throw new Error(`GitHub OAuth user request failed: ${userRes.statusText}`);
        }

        const emailRes = await fetch("https://api.github.com/user/emails", {
            headers: {
                Authorization: `Bearer ${accessToken}`,
            },
        });

        if (!emailRes.ok) {
            throw new Error(`GitHub OAuth email request failed: ${emailRes.statusText}`);
        }

        const userData = await userRes.json();
        const emailData = await emailRes.json();

        const primaryEmail = emailData.find((e: any) => e.primary && e.verified)?.email;

        if (!primaryEmail) {
            throw new Error("GitHub OAuth failed: no verified primary email found.");
        }

        return {
            id: userData.id.toString(),
            email: primaryEmail,
            name: userData.name,
            avatar: userData.avatar_url,
            provider: "github",
        };
    } catch (error) {
        console.error("Error during GitHub OAuth callback:", error);
        throw new Error("An error occurred during GitHub authentication.");
    }
}
