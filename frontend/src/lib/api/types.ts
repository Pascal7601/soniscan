export type Role = 'owner' | 'admin' | 'viewer';
export interface Membership { tenant_id: string; tenant_name: string; role: Role }
export interface Me { id: string; email: string; display_name: string; memberships: Membership[]; mfa_enabled: boolean }
export type DomainStatus = 'pending' | 'verified' | 'expired' | 'suspended';
export interface Domain { id: string; fqdn: string; status: DomainStatus; verified_at: string | null; reverify_due: string | null }
export interface Posture { score: number; grade: 'A'|'B'|'C'|'D'|'F'; total_risk: number; capped_by: string | null; open_findings: number; counts_by_tier: Record<string, number> }
export type ScanMode = 'passive'|'active';
export type ScanStatus = 'queued'|'running'|'succeeded'|'partial'|'failed'|'cancelled'|'refused';
export interface Scan { id: string; domain_id: string; mode: ScanMode; status: ScanStatus; trigger_type: string; queued_at: string; started_at: string | null; finished_at: string | null }
export type Severity = 'critical'|'high'|'medium'|'low'|'info';
export type FindingStatus = 'open'|'fixed'|'accepted_risk'|'false_positive';
export interface Finding { id: string; check_key: string; title: string; asset: string; severity: Severity; score: number; tier: string; status: FindingStatus; first_seen_at: string; last_seen_at: string; reopened_count: number; accepted_until: string | null }
export interface FindingDetail extends Finding { plain_explanation: string; why_it_matters: string; fix_steps: string[]; effort: string; owner_hint: string; accepted_reason: string | null }
export interface FixFirstItem { rank: number; finding_id: string; check_key: string; asset: string; title: string; plain_explanation: string; why_it_matters: string; fix_steps: string[]; effort: string; owner_hint: string; severity: string; score: number; tier: string }
export interface Report { id: string; domain_id: string; scan_id: string; generated_at: string; score: number; grade: string; open_findings: number }
export interface VerificationInstructions { method: string; record_name: string; record_value: string; expires_at: string }
