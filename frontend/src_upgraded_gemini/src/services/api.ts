/**
 * ProShield API client (TypeScript port of `frontend/js/services/api.js`).
 *
 * This REUSES the existing ProShield API architecture: every call goes
 * through the single `POST /api/proxy` wire boundary of
 * `SecureProxy.handle(ProxyRequest)` with the same operation names, the
 * same session header (`X-ProShield-Session`), the same localStorage
 * session keys, and the same error-envelope handling as the legacy
 * frontend. No second API layer is introduced.
 *
 * Success requires HTTP 2xx AND a body without an error envelope
 * (same V2-16 semantics as api.js).
 */
export const SESSION_KEY = "proshield.session";
export const USER_KEY = "proshield.user";

export interface ProxyError {
  code: string;
  message: string;
}

export interface ProxyResult<T = any> {
  ok: boolean;
  status: number;
  data: T | null;
  error: ProxyError | null;
}

export interface SessionUser {
  subject_id: string;
  role: string;
  expires_at?: string;
}

export function getSessionToken(): string {
  try {
    return localStorage.getItem(SESSION_KEY) || "";
  } catch {
    return "";
  }
}

export function getSessionUser(): SessionUser | null {
  try {
    const raw = localStorage.getItem(USER_KEY);
    return raw ? (JSON.parse(raw) as SessionUser) : null;
  } catch {
    return null;
  }
}

export function setSession(token: string | null, user: SessionUser | null): void {
  if (token) localStorage.setItem(SESSION_KEY, token);
  else localStorage.removeItem(SESSION_KEY);
  if (user) localStorage.setItem(USER_KEY, JSON.stringify(user));
  else localStorage.removeItem(USER_KEY);
}

export class ProxyCallError extends Error {
  code: string;
  status: number;
  detail: ProxyError | null;

  constructor(message: string, code: string, status: number, detail: ProxyError | null) {
    super(message);
    this.name = "ProxyCallError";
    this.code = code;
    this.status = status;
    this.detail = detail;
  }
}

/** Call the SecureProxy wire boundary. Never throws. */
export async function call<T = any>(
  operation: string,
  body?: Record<string, unknown>,
  opts?: { authenticated?: boolean }
): Promise<ProxyResult<T>> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const useSession = opts?.authenticated !== false;
  if (useSession) {
    const token = getSessionToken();
    if (token) headers["X-ProShield-Session"] = token;
  }
  const payload = Object.assign({ operation }, body || {});
  try {
    const resp = await fetch("/api/proxy", {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    });
    let parsed: any = null;
    try {
      parsed = await resp.json();
    } catch {
      parsed = null;
    }
    const httpOk = resp.ok;
    const envelopeOk = !!parsed && parsed.ok !== false && !parsed.error;
    return {
      ok: httpOk && envelopeOk,
      status: resp.status,
      data: (parsed && parsed.data) as T,
      error: (parsed && parsed.error) as ProxyError | null,
    };
  } catch (e: any) {
    return {
      ok: false,
      status: 0,
      data: null,
      error: { code: "network_error", message: e?.message || "network failure" },
    };
  }
}

/** Call and throw on error so callers can use plain `await` semantics. */
export async function callOrThrow<T = any>(
  operation: string,
  body?: Record<string, unknown>,
  opts?: { authenticated?: boolean }
): Promise<T> {
  const r = await call<T>(operation, body, opts);
  if (!r.ok) {
    const code = r.error?.code || "unknown_error";
    const msg = r.error?.message || "Backend error";
    throw new ProxyCallError(msg, code, r.status, r.error);
  }
  return r.data as T;
}

/** Issue a session via `auth.issue` and persist it. */
export async function authIssue(
  subjectId: string,
  credential: string
): Promise<ProxyResult<{ token: string; subject_id: string; role: string; expires_at?: string }>> {
  const r = await call<{ token: string; subject_id: string; role: string; expires_at?: string }>(
    "auth.issue",
    { subject_id: subjectId, credential },
    { authenticated: false }
  );
  if (r.ok && r.data && r.data.token) {
    setSession(r.data.token, {
      subject_id: r.data.subject_id,
      role: r.data.role,
      expires_at: r.data.expires_at,
    });
  }
  return r;
}

/** Unauthenticated liveness probe (`health` op, no session needed). */
export async function healthCheck(): Promise<{ ok: boolean; latencyMs: number | null }> {
  const started = typeof performance !== "undefined" ? performance.now() : Date.now();
  try {
    const r = await call("health", {}, { authenticated: false });
    const elapsed = performance.now() - started;
    return { ok: r.ok, latencyMs: Math.round(elapsed) };
  } catch {
    return { ok: false, latencyMs: null };
  }
}

export function logout(): void {
  setSession(null, null);
}
