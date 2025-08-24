import { authConfig } from "../config";

async function apiFetch<T>(url: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(url, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(init.headers || {}) },
    ...init
  });
  let data: any = null;
  try { data = await res.json(); } catch {}
  if (!res.ok) {
    const msg = data?.error?.message || data?.message || `${res.status} ${res.statusText}`;
    throw new Error(msg);
  }
  return data as T;
}

function getCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop()?.split(';').shift() || null;
  return null;
}

function deleteCookie(name: string, path = "/") {
  if (typeof document === "undefined") return;
  document.cookie = `${name}=; Path=${path}; Expires=Thu, 01 Jan 1970 00:00:01 GMT;`;
}

export async function signupReact(
  email: string,
  password: string,
  apiEndpoint = '/api/auth/signup'
): Promise<{ user: { id: string; email: string } }> {
  return apiFetch(apiEndpoint, { method: 'POST', body: JSON.stringify({ email, password }) });
}

export async function signinReact(
  email: string,
  password: string,
  apiEndpoint = '/api/auth/signin'
): Promise<{ user: { id: string; email: string } }> {
  return apiFetch(apiEndpoint, { method: 'POST', body: JSON.stringify({ email, password }) });
}

export async function logoutReact(apiEndpoint = '/api/auth/logout'): Promise<{ message: string }> {
  const result = await apiFetch<{ message: string }>(apiEndpoint, { method: 'POST' });
  deleteCookie(authConfig.cookieName); // local fallback
  return result;
}

export async function getCurrentUserReact(
  apiEndpoint = '/api/auth/me'
): Promise<{ id: string; email: string; createdAt?: Date } | null> {
  try {
    const data = await apiFetch<any>(apiEndpoint, { method: 'GET' });
    return data.user || null;
  } catch (e: any) {
    if (e.message?.toLowerCase().includes('unauthorized') || e.message === '401 Unauthorized') return null;
    return null; // silent fail
  }
}

export async function isAuthenticatedReact(apiEndpoint = '/api/auth/me'): Promise<boolean> {
  return (await getCurrentUserReact(apiEndpoint)) !== null;
}

export function getAuthToken(): string | null {
  return getCookie(authConfig.cookieName);
}

export function hasAuthToken(): boolean { return getAuthToken() !== null; }

export function createUseAuthToken() {
  return function useAuthToken() {
  return getAuthToken();
  };
}

export function withAuthReact(options: {
  fallback?: any;
  redirectTo?: string;
  checkAuthEndpoint?: string;
} = {}) {
  return function <P extends object>(WrappedComponent: any) {
    return function AuthenticatedComponent(props: P) {
      return null;
    };
  };
}
