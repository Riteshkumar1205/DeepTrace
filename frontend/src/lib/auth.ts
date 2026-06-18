const TOKEN_COOKIE = "deeptrace_auth_token";
const EMAIL_COOKIE = "deeptrace_auth_email";
const SESSION_COOKIE = "deeptrace_auth_session";
const TOKEN_STORAGE = "deeptrace_auth_token";
const EMAIL_STORAGE = "deeptrace_auth_email";
const SESSION_STORAGE = "deeptrace_auth_session";

export function setAuthState(token: string, email: string, sessionId?: string | null) {
  if (typeof document === "undefined") return;
  const maxAge = 60 * 60 * 24 * 7;
  document.cookie = `${TOKEN_COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=${maxAge}; SameSite=Lax`;
  document.cookie = `${EMAIL_COOKIE}=${encodeURIComponent(email)}; Path=/; Max-Age=${maxAge}; SameSite=Lax`;
  if (sessionId) {
    document.cookie = `${SESSION_COOKIE}=${encodeURIComponent(sessionId)}; Path=/; Max-Age=${maxAge}; SameSite=Lax`;
  }
  window.localStorage.setItem(TOKEN_STORAGE, token);
  window.localStorage.setItem(EMAIL_STORAGE, email);
  if (sessionId) {
    window.localStorage.setItem(SESSION_STORAGE, sessionId);
  } else {
    window.localStorage.removeItem(SESSION_STORAGE);
  }
}

export function clearAuthState() {
  if (typeof document === "undefined") return;
  document.cookie = `${TOKEN_COOKIE}=; Path=/; Max-Age=0; SameSite=Lax`;
  document.cookie = `${EMAIL_COOKIE}=; Path=/; Max-Age=0; SameSite=Lax`;
  document.cookie = `${SESSION_COOKIE}=; Path=/; Max-Age=0; SameSite=Lax`;
  window.localStorage.removeItem(TOKEN_STORAGE);
  window.localStorage.removeItem(EMAIL_STORAGE);
  window.localStorage.removeItem(SESSION_STORAGE);
}

export function readAuthToken() {
  if (typeof document === "undefined") return null;
  const match = document.cookie.split("; ").find((part) => part.startsWith(`${TOKEN_COOKIE}=`));
  if (match) return decodeURIComponent(match.split("=").slice(1).join("="));
  return window.localStorage.getItem(TOKEN_STORAGE);
}

export function readAuthEmail() {
  if (typeof document === "undefined") return null;
  const match = document.cookie.split("; ").find((part) => part.startsWith(`${EMAIL_COOKIE}=`));
  if (match) return decodeURIComponent(match.split("=").slice(1).join("="));
  return window.localStorage.getItem(EMAIL_STORAGE);
}

export function readAuthSession() {
  if (typeof document === "undefined") return null;
  const match = document.cookie.split("; ").find((part) => part.startsWith(`${SESSION_COOKIE}=`));
  if (match) return decodeURIComponent(match.split("=").slice(1).join("="));
  return window.localStorage.getItem(SESSION_STORAGE);
}

export function hasAuthTokenCookie() {
  return Boolean(readAuthToken());
}
