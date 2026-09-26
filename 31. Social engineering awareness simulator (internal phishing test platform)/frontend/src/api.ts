import type { User } from "./types";

const TOKEN_KEY = "seas_token";
const USER_KEY = "seas_user";

export function saveAuth(token: string, user: User) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function clearAuth() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function getUser(): User | null {
  const raw = localStorage.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as User;
  } catch {
    return null;
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    ...(init.headers as Record<string, string>),
  };
  const token = getToken();
  if (token) headers["Authorization"] = "Bearer " + token;
  if (init.body && typeof init.body === "string") {
    headers["Content-Type"] = "application/json";
  }
  const res = await fetch(path, { ...init, headers });
  if (res.status === 401) {
    clearAuth();
    window.location.reload();
    throw new Error("Session expired");
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch {
      /* ignore */
    }
    throw new Error(String(detail));
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  login: (username: string, password: string) =>
    request<{ access_token: string; user: User }>("/api/v1/auth/token", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  me: () => request<User>("/api/v1/auth/me"),
  dashboard: () => request<import("./types").Dashboard>("/api/v1/dashboard"),
  campaigns: () => request<import("./types").Campaign[]>("/api/v1/campaigns"),
  createCampaign: (body: unknown) =>
    request("/api/v1/campaigns", { method: "POST", body: JSON.stringify(body) }),
  approveCampaign: (id: number) =>
    request(`/api/v1/campaigns/${id}/approve`, { method: "POST" }),
  launchCampaign: (id: number) =>
    request(`/api/v1/campaigns/${id}/launch`, { method: "POST" }),
  deliveries: (id: number) =>
    request<import("./types").Delivery[]>(`/api/v1/campaigns/${id}/deliveries`),
  targets: () => request<import("./types").Employee[]>("/api/v1/targets"),
  addTarget: (body: unknown) =>
    request("/api/v1/targets", { method: "POST", body: JSON.stringify(body) }),
  toggleOptOut: (id: number) =>
    request(`/api/v1/targets/${id}/optout`, { method: "POST" }),
  templates: () => request<import("./types").LureTemplate[]>("/api/v1/templates"),
  createTemplate: (body: unknown) =>
    request("/api/v1/templates", { method: "POST", body: JSON.stringify(body) }),
  landingPages: () => request<{ id: number; name: string; title: string; body_html: string }[]>("/api/v1/landing-pages"),
  createLandingPage: (body: unknown) =>
    request("/api/v1/landing-pages", { method: "POST", body: JSON.stringify(body) }),
  reports: () => request<import("./types").Report[]>("/api/v1/reports"),
  createReport: (fmt: string) =>
    request<{ url_token: string; name: string }>("/api/v1/reports", {
      method: "POST",
      body: JSON.stringify({ fmt }),
    }),
  reportUrl: (token: string) => `/api/v1/reports/${token}/download`,
  trainings: () => request<import("./types").Training[]>("/api/v1/training"),
  autoAssign: () => request<{ ok: boolean; assigned: number }>("/api/v1/training/auto-assign", { method: "POST", body: "{}" }),
  audit: (limit = 200) => request<import("./types").AuditEntry[]>(`/api/v1/audit?limit=${limit}`),
};