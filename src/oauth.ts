// OAuth providers - separate export for optional imports
// Import these directly when you need OAuth functionality

// Providers without conflicting helper names can be re-exported wholesale
export * from "./providers/google";
export * from "./providers/apple";
export * from "./providers/linkedin";

// Providers with overlapping helper names (generateOAuthState/parseOAuthState)
// are re-exported explicitly to avoid name collisions.
export {
	DiscordPermissions,
	getDiscordOAuthURL,
	handleDiscordCallback,
	refreshDiscordToken,
	revokeDiscordToken,
	getDiscordUserById,
	checkGuildMembership,
	getGuildMemberRoles,
	validateDiscordToken,
	getDiscordBotInviteURL,
	resetDiscordOAuthConfig,
	calculatePermissions,
} from "./providers/discord";

export {
	getFacebookOAuthURL,
	handleFacebookCallback,
	exchangeForLongLivedToken,
	debugToken as debugFacebookToken,
	getUserPermissions as getFacebookUserPermissions,
	revokeFacebookPermission,
	getFacebookUserById,
	validateFacebookToken,
	getAppAccessToken as getFacebookAppAccessToken,
	deleteFacebookUserData,
	resetFacebookOAuthConfig,
	getFacebookLoginStatusURL,
	verifyFacebookWebhookSignature,
} from "./providers/facebook";

export {
	PKCEUtils,
	getXOAuthURL,
	handleXCallback,
	refreshXToken,
	revokeXToken,
	getXUserById,
	validateXToken,
	cleanupPKCEStorage,
	resetXOAuthConfig,
} from "./providers/x";

// Explicit GitHub exports to avoid colliding helper names
export {
	getGitHubOAuthURL,
	handleGitHubCallback,
	revokeGitHubToken,
	validateGitHubToken,
	getGitHubUserOrganizations,
	checkGitHubOrgMembership,
	resetGitHubOAuthConfig,
	getGitHubRateLimit,
} from "./providers/github";

// Custom OAuth toolkit
export * from "./providers/customOAuth";
