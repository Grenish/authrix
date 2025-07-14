import { authConfig } from "../config";

// Framework-agnostic logout function
export function logoutCore() {
  return {
    cookieName: authConfig.cookieName,
    cookieOptions: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax" as const,
      path: "/",
      expires: new Date(0), // Expire immediately
    },
    message: "Logged out successfully"
  };
}

// Express.js specific logout function for backward compatibility
export function logout(res: any) {
  const result = logoutCore();

  if (res.clearCookie) {
    res.clearCookie(result.cookieName, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
    });
  }

  return { message: result.message };
}
