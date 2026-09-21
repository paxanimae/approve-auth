// Mirrors internal/httpserver's admin_dto.go response shapes.

export interface Me {
  subject: string;
  display_name: string;
  role: "administrator" | "viewer" | "application_owner";
  csrf_token: string;
  default_authorization_duration_seconds: number;
  max_authorization_duration_seconds: number;
  version: string;
  instance_name: string;
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
  // Absent means this application uses the global contact_info config
  // default instead of an override of its own.
  contact_info?: string;
  // Absent means this application uses the global notify_default_email/
  // notify_default_webhook_url config defaults instead of overrides of
  // its own.
  notify_email?: string;
  notify_webhook_url?: string;
}

export interface ApprovalRequest {
  id: string;
  application_id: string;
  application_hostname: string;
  application_display_name: string;
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
  // Both absent when no GeoIP database is configured, or the lookup
  // simply didn't resolve for this address.
  source_geo_country?: string;
  source_geo_city?: string;
  user_agent?: string;
  version: number;
}

export interface Authorization {
  id: string;
  application_id: string;
  application_hostname: string;
  application_display_name: string;
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

export interface Note {
  id: string;
  author_subject: string;
  body: string;
  created_at: string;
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
