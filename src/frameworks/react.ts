// React client-side utilities for Authrix
// These functions work with cookies on the client side for SPAs

import { authConfig } from "../config";

// Client-side cookie utilities
function getCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop()?.split(';').shift() || null;
  return null;
}

function setCookie(name: string, value: string, options: {
  maxAge?: number;
  path?: string;
  secure?: boolean;
  sameSite?: string;
}) {
  if (typeof document === "undefined") return;
  
  let cookieString = `${name}=${value}`;
  
  if (options.maxAge) cookieString += `; Max-Age=${options.maxAge}`;
  if (options.path) cookieString += `; Path=${options.path}`;
  if (options.secure) cookieString += `; Secure`;
  if (options.sameSite) cookieString += `; SameSite=${options.sameSite}`;
  
  document.cookie = cookieString;
}

function deleteCookie(name: string, path = "/") {
  if (typeof document === "undefined") return;
  document.cookie = `${name}=; Path=${path}; Expires=Thu, 01 Jan 1970 00:00:01 GMT;`;
}

// React-specific authentication functions

/**
 * Sign up a user (client-side)
 * Note: This requires your API to handle the authentication logic
 */
export async function signupReact(
  email: string, 
  password: string,
  apiEndpoint = "/api/auth/signup"
): Promise<{ user: { id: string; email: string } }> {
  const response = await fetch(apiEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ email, password }),
    credentials: "include", // Important for cookies
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error?.message || "Signup failed");
  }

  return response.json();
}

/**
 * Sign in a user (client-side)
 */
export async function signinReact(
  email: string, 
  password: string,
  apiEndpoint = "/api/auth/signin"
): Promise<{ user: { id: string; email: string } }> {
  const response = await fetch(apiEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ email, password }),
    credentials: "include", // Important for cookies
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error?.message || "Signin failed");
  }

  return response.json();
}

/**
 * Log out a user (client-side)
 */
export async function logoutReact(apiEndpoint = "/api/auth/logout"): Promise<{ message: string }> {
  const response = await fetch(apiEndpoint, {
    method: "POST",
    credentials: "include", // Important for cookies
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error?.message || "Logout failed");
  }

  // Also clear the cookie on client side as backup
  deleteCookie(authConfig.cookieName);

  return response.json();
}

/**
 * Get current user (client-side)
 */
export async function getCurrentUserReact(
  apiEndpoint = "/api/auth/me"
): Promise<{ id: string; email: string; createdAt?: Date } | null> {
  try {
    const response = await fetch(apiEndpoint, {
      credentials: "include", // Important for cookies
    });

    if (!response.ok) {
      if (response.status === 401) return null;
      throw new Error("Failed to get current user");
    }

    const data = await response.json();
    return data.user || null;
  } catch (error) {
    console.error("Get current user error:", error);
    return null;
  }
}

/**
 * Check if user is authenticated (client-side)
 */
export async function isAuthenticatedReact(apiEndpoint = "/api/auth/me"): Promise<boolean> {
  const user = await getCurrentUserReact(apiEndpoint);
  return user !== null;
}

/**
 * Get auth token from cookies (client-side)
 * Useful for making authenticated requests to your API
 */
export function getAuthToken(): string | null {
  return getCookie(authConfig.cookieName);
}

/**
 * Check if there's an auth token in cookies (client-side)
 * This is a quick check without API call, but doesn't validate the token
 */
export function hasAuthToken(): boolean {
  return getAuthToken() !== null;
}

// React Hook for authentication token
// Note: This is a conceptual implementation - actual React hooks would be imported from 'react'
export function createUseAuthToken() {
  return function useAuthToken() {
    // This would use React.useState and React.useEffect in a real React environment
    // For now, we provide the implementation structure
    return getAuthToken();
  };
}

/**
 * Higher-order component for protecting React routes
 * This is a factory function that returns the actual HOC
 * Usage: const ProtectedComponent = withAuthReact(MyComponent);
 */
export function withAuthReact(options: {
  fallback?: any; // React component
  redirectTo?: string;
  checkAuthEndpoint?: string;
} = {}) {
  return function <P extends object>(WrappedComponent: any) {
    return function AuthenticatedComponent(props: P) {
      // In a real React environment, this would use React hooks
      // The implementation would check authentication and conditionally render
      // For TypeScript compilation, we return a placeholder
      return null;
    };
  };
}
