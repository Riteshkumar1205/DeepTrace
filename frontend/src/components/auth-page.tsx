"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { ArrowRight, Loader2, ShieldCheck, Mail, KeyRound, UserRound, Building2 } from "lucide-react";

import { API_BASE_URL } from "@/components/shared-config";
import { hasAuthTokenCookie, readAuthToken, setAuthState } from "@/lib/auth";

type Mode = "login" | "register" | "forgot" | "reset";

function apiPath(path: string) {
  return `${API_BASE_URL}${path.startsWith("/") ? path : `/${path}`}`;
}

async function requestJson(path: string, init: RequestInit = {}) {
  const response = await fetch(apiPath(path), {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init.headers || {}),
    },
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(data?.detail || data?.message || `Request failed (${response.status})`);
  }
  return data;
}

export function AuthPage({ mode }: { mode: Mode }) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [form, setForm] = useState({
    fullName: "",
    organization: "",
    email: "",
    password: "",
    confirmPassword: "",
    token: "",
  });

  useEffect(() => {
    if (hasAuthTokenCookie() && (mode === "login" || mode === "register")) {
      router.replace("/");
    }
  }, [mode, router]);

  useEffect(() => {
    const token = searchParams.get("token") || "";
    if (token && mode === "reset") {
      setForm((current) => ({ ...current, token }));
    }
  }, [mode, searchParams]);

  const title = useMemo(() => {
    switch (mode) {
      case "register":
        return "Create account";
      case "forgot":
        return "Reset access";
      case "reset":
        return "Set new password";
      default:
        return "Sign in";
    }
  }, [mode]);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setMessage("");

    try {
      if (mode === "register") {
        if (form.password !== form.confirmPassword) {
          throw new Error("Passwords do not match.");
        }
        const data = await requestJson("/auth/register", {
          method: "POST",
          body: JSON.stringify({
            email: form.email,
            password: form.password,
            full_name: form.fullName,
            organization_name: form.organization,
          }),
        });
        setAuthState(data.access_token, form.email, data.session_id);
        window.location.assign("/");
        return;
      }

      if (mode === "login") {
        const data = await requestJson("/auth/login", {
          method: "POST",
          body: JSON.stringify({
            email: form.email,
            password: form.password,
          }),
        });
        setAuthState(data.access_token, form.email, data.session_id);
        window.location.assign("/");
        return;
      }

      if (mode === "forgot") {
        const data = await requestJson("/auth/forgot-password", {
          method: "POST",
          body: JSON.stringify({ email: form.email }),
        });
        setMessage(data.message || "Password reset request submitted.");
        return;
      }

      if (!form.token) throw new Error("Reset token is required.");
      if (form.password !== form.confirmPassword) throw new Error("Passwords do not match.");
      const data = await requestJson("/auth/reset-password", {
        method: "POST",
        body: JSON.stringify({
          token: form.token,
          password: form.password,
          confirm_password: form.confirmPassword,
        }),
      });
      setMessage(data.message || "Password updated.");
      setTimeout(() => window.location.assign("/login"), 1000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-shell">
      <div className="panel auth-hero">
        <div className="auth-badge">
          <ShieldCheck size={15} />
          DeepTrace Secure Access
        </div>
        <h1>{title}</h1>
        <p>Authenticate to the live backend. All authentication, reset, and dashboard actions are routed to actual server state.</p>
        <div className="auth-metrics">
          <div className="stat-card">
            <div className="stat-top"><span className="stat-label">Session</span></div>
            <div className="stat-value">{readAuthToken() ? "Active" : "Idle"}</div>
            <div className="stat-sub">Token stored locally for API access</div>
          </div>
          <div className="stat-card">
            <div className="stat-top"><span className="stat-label">Backend</span></div>
            <div className="stat-value">Live</div>
            <div className="stat-sub">Direct API integration</div>
          </div>
          <div className="stat-card">
            <div className="stat-top"><span className="stat-label">Security</span></div>
            <div className="stat-value">Secure</div>
            <div className="stat-sub">Password hashing + token auth</div>
          </div>
        </div>
      </div>

      <div className="panel auth-form-panel">
        <form className="stack" onSubmit={submit}>
          {mode === "register" ? (
            <>
              <label className="field">
                <span>Full name</span>
                <div className="input-icon">
                  <UserRound size={14} />
                  <input className="input" value={form.fullName} onChange={(e) => setForm((c) => ({ ...c, fullName: e.target.value }))} required />
                </div>
              </label>
              <label className="field">
                <span>Organization</span>
                <div className="input-icon">
                  <Building2 size={14} />
                  <input className="input" value={form.organization} onChange={(e) => setForm((c) => ({ ...c, organization: e.target.value }))} required />
                </div>
              </label>
            </>
          ) : null}

          {mode === "reset" ? (
            <label className="field">
              <span>Reset token</span>
              <div className="input-icon">
                <KeyRound size={14} />
                <input className="input" value={form.token} onChange={(e) => setForm((c) => ({ ...c, token: e.target.value }))} required />
              </div>
            </label>
          ) : null}

          <label className="field">
            <span>Email</span>
            <div className="input-icon">
              <Mail size={14} />
              <input className="input" type="email" value={form.email} onChange={(e) => setForm((c) => ({ ...c, email: e.target.value }))} required />
            </div>
          </label>

          {mode !== "forgot" ? (
            <label className="field">
              <span>Password</span>
              <div className="input-icon">
                <KeyRound size={14} />
                <input className="input" type="password" value={form.password} onChange={(e) => setForm((c) => ({ ...c, password: e.target.value }))} required />
              </div>
            </label>
          ) : null}

          {mode === "register" || mode === "reset" ? (
            <label className="field">
              <span>Confirm password</span>
              <div className="input-icon">
                <KeyRound size={14} />
                <input className="input" type="password" value={form.confirmPassword} onChange={(e) => setForm((c) => ({ ...c, confirmPassword: e.target.value }))} required />
              </div>
            </label>
          ) : null}

          {error ? <div className="status-banner danger">{error}</div> : null}
          {message ? <div className="status-banner">{message}</div> : null}

          <button className="btn primary" type="submit" disabled={busy}>
            {busy ? <Loader2 size={16} className="spin" /> : <ArrowRight size={16} />}
            {busy ? "Working..." : title}
          </button>
        </form>

        <div className="auth-links">
          {mode !== "login" ? <Link href="/login">Sign in</Link> : null}
          {mode !== "register" ? <Link href="/register">Create account</Link> : null}
          {mode !== "forgot" ? <Link href="/forgot-password">Forgot password</Link> : null}
          {mode !== "reset" ? <Link href="/reset-password">Reset password</Link> : null}
          <Link href="/">Dashboard</Link>
        </div>
      </div>
    </div>
  );
}
