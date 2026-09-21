import type {
  ApiErrorBody,
  Application,
  ApprovalRequest,
  AuditEvent,
  Authorization,
  Me,
  Note,
  Overview,
} from "./types";

// ApiError carries the server's structured error code/message (spec
// section 9's `{ error: { code, message, request_id } }` body) so
// callers can show the real reason rather than a generic failure.
export class ApiError extends Error {
  code: string;
  requestId: string;
  status: number;
  constructor(status: number, body: ApiErrorBody) {
    super(body.error.message);
    this.code = body.error.code;
    this.requestId = body.error.request_id;
    this.status = status;
  }
}

let csrfToken = "";

// setCsrfToken is called once after GET /api/v1/me returns the current
// session's token; every mutation below echoes it back via the
// X-CSRF-Token header (spec section 9's synchronizer-token CSRF check).
export function setCsrfToken(token: string): void {
  csrfToken = token;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  let requestBody: string | undefined;
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    requestBody = JSON.stringify(body);
  }
  if (method !== "GET") {
    headers["X-CSRF-Token"] = csrfToken;
  }

  const res = await fetch(path, { method, headers, body: requestBody, credentials: "same-origin" });
  const contentType = res.headers.get("content-type") ?? "";

  if (!contentType.includes("application/json")) {
    if (!res.ok) {
      throw new ApiError(res.status, { error: { code: "unknown", message: `request failed with status ${res.status}`, request_id: "" } });
    }
    return undefined as T;
  }

  const data = await res.json();
  if (!res.ok) {
    throw new ApiError(res.status, data as ApiErrorBody);
  }
  return data as T;
}

export interface CreateApplicationInput {
  hostname: string;
  display_name: string;
  description?: string;
  default_duration_seconds?: number;
  max_duration_seconds?: number;
  contact_info?: string;
}

export interface DisableApplicationResponse {
  application: Application;
  canceled_requests: number;
  revoked_authorizations: number;
}

export interface BulkItemResult {
  id: string;
  success: boolean;
  error?: string;
}

export const api = {
  me: () => request<Me>("GET", "/api/v1/me"),
  logout: () => request<{ logged_out: boolean }>("POST", "/auth/logout"),

  overview: () => request<Overview>("GET", "/api/v1/overview"),

  listApplications: () => request<{ applications: Application[] }>("GET", "/api/v1/applications"),
  createApplication: (input: CreateApplicationInput) => request<Application>("POST", "/api/v1/applications", input),
  updateApplication: (id: string, body: { version: number; display_name?: string; description?: string; contact_info?: string }) =>
    request<Application>("PATCH", `/api/v1/applications/${id}`, body),
  disableApplication: (id: string, body: { version: number; reason: string }) =>
    request<DisableApplicationResponse>("POST", `/api/v1/applications/${id}/disable`, body),
  enableApplication: (id: string, body: { version: number }) =>
    request<Application>("POST", `/api/v1/applications/${id}/enable`, body),

  listRequests: (status?: string) =>
    request<{ requests: ApprovalRequest[] }>("GET", `/api/v1/requests${status ? `?status=${encodeURIComponent(status)}` : ""}`),
  approveRequest: (id: string, body: { version: number; expires_at?: string; label?: string; private_note?: string }) =>
    request<{ authorization_id: string; expires_at: string }>("POST", `/api/v1/requests/${id}/approve`, body),
  denyRequest: (id: string, body: { version: number; reason: string; public_message?: string }) =>
    request<{ denied: boolean }>("POST", `/api/v1/requests/${id}/deny`, body),
  listRequestNotes: (id: string) => request<{ notes: Note[] }>("GET", `/api/v1/requests/${id}/notes`),
  addRequestNote: (id: string, body: { body: string }) => request<Note>("POST", `/api/v1/requests/${id}/notes`, body),

  listAuthorizations: (activeOnly = true, mine = false) =>
    request<{ authorizations: Authorization[] }>("GET", `/api/v1/authorizations?active_only=${activeOnly}&mine=${mine}`),
  renewAuthorization: (id: string, body: { version: number; new_expires_at: string; reason: string }) =>
    request<{ renewed: boolean }>("POST", `/api/v1/authorizations/${id}/renew`, body),
  revokeAuthorization: (id: string, body: { version: number; reason: string }) =>
    request<{ revoked: boolean }>("POST", `/api/v1/authorizations/${id}/revoke`, body),
  listAuthorizationNotes: (id: string) => request<{ notes: Note[] }>("GET", `/api/v1/authorizations/${id}/notes`),
  addAuthorizationNote: (id: string, body: { body: string }) => request<Note>("POST", `/api/v1/authorizations/${id}/notes`, body),
  bulkRevokeAuthorizations: (body: { items: { id: string; version: number }[]; reason: string }) =>
    request<{ results: BulkItemResult[] }>("POST", "/api/v1/authorizations/bulk-revoke", body),

  listAuditEvents: () => request<{ audit_events: AuditEvent[] }>("GET", "/api/v1/audit-events"),
};
