// Mirrors internal/httpserver's admin_dto.go response shapes.

export interface Me {
  subject: string;
  display_name: string;
  role: "administrator" | "viewer";
  csrf_token: string;
  default_authorization_duration_seconds: number;
  max_authorization_duration_seconds: number;
}

export interface Overview {
  pending: number;
  active: number;
  expiring_soon: number;
  revoked_or_expired_recent: number;
}

export interface Application {
  id: string;
  hostname: string;
  display_name: string;
  description: string;
  enabled: boolean;
  default_duration_seconds: number;
  max_duration_seconds: number;
  created_at: string;
  updated_at: string;
  archived_at?: string;
  version: number;
}

export interface ApprovalRequest {
  id: string;
  application_id: string;
  verification_code: string;
  label?: string;
  message?: string;
  status: string;
  requested_at: string;
  deadline_at: string;
  decided_at?: string;
  decided_by?: string;
  claim_deadline_at?: string;
  claimed_at?: string;
  public_decision_message?: string;
  private_note?: string;
  source_ip?: string;
  user_agent?: string;
  version: number;
}

export interface Authorization {
  id: string;
  application_id: string;
  request_id: string;
  label?: string;
  approved_by: string;
  approved_at: string;
  activated_at?: string;
  expires_at: string;
  revoked_at?: string;
  revoked_by?: string;
  revocation_reason?: string;
  last_seen_at?: string;
  last_seen_user_agent?: string;
  version: number;
}

export interface AuditEvent {
  id: string;
  occurred_at: string;
  actor_type: string;
  actor_subject?: string;
  action: string;
  application_id?: string;
  request_id?: string;
  authorization_id?: string;
  correlation_id: string;
  reason?: string;
  outcome: string;
}

export interface ApiErrorBody {
  error: { code: string; message: string; request_id: string };
}
