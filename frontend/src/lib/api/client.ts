import type { Domain, Finding, FindingDetail, FixFirstItem, Me, Posture, Report, Scan, VerificationInstructions } from './types';

const API_BASE = ''; 
let tenantId: string | null = null;
export function setTenantId(id: string | null) { tenantId = id; }
export class ApiError extends Error {
  status: number; code?: string; payload: unknown;
  constructor(message: string, status: number, payload?: unknown) { super(message); this.name = 'ApiError'; this.status = status; this.payload = payload; if (payload && typeof payload === 'object' && 'code' in payload) this.code = String((payload as {code: unknown}).code); }
}
function csrfToken() {
  if (typeof document === 'undefined') return '';
  return document.cookie.split('; ').find((part) => part.startsWith('csrftoken='))?.split('=').slice(1).join('=') ?? '';
}
async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  if (tenantId) headers.set('X-Tenant-ID', tenantId);
  if (['POST','PUT','PATCH','DELETE'].includes((init.method ?? 'GET').toUpperCase())) {
    const token = csrfToken(); if (token) headers.set('X-CSRFToken', token);
  }
  const response = await fetch(`${API_BASE}${path}`, { ...init, headers, credentials: 'include', cache: 'no-store' });
  if (response.status === 204) return undefined as T;
  const contentType = response.headers.get('content-type') ?? '';
  const payload = contentType.includes('application/json') ? await response.json() : await response.text();
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    if (payload && typeof payload === 'object') {
      const p = payload as Record<string, unknown>;
      message = String(p.detail ?? p.fqdn ?? p.reason ?? message);
      if (Array.isArray(p.fqdn)) message = p.fqdn.join(', ');
    }
    throw new ApiError(message, response.status, payload);
  }
  return payload as T;
}
export const api = {
  csrf: () => request<void>('/api/v1/auth/csrf/'),
  me: () => request<Me>('/api/v1/me/'),
  domains: () => request<Domain[]>('/api/v1/domains/'),
  addDomain: (fqdn: string) => request<Domain>('/api/v1/domains/', { method: 'POST', body: JSON.stringify({ fqdn }) }),
  startVerification: (id: string) => request<VerificationInstructions>(`/api/v1/domains/${id}/verification/`, { method: 'POST' }),
  checkVerification: (id: string) => request<{status: 'queued'|'already_verified'}>(`/api/v1/domains/${id}/verification/check/`, { method: 'POST' }),
  posture: (id: string) => request<Posture>(`/api/v1/domains/${id}/posture/`),
  fixFirst: (id: string) => request<FixFirstItem[]>(`/api/v1/domains/${id}/fix-first/`),
  scans: (id: string) => request<Scan[]>(`/api/v1/domains/${id}/scans/`),
  createScan: (id: string, mode: 'passive'|'active') => request<Scan>(`/api/v1/domains/${id}/scans/`, { method: 'POST', body: JSON.stringify({ mode }) }),
  scan: (id: string) => request<Scan>(`/api/v1/scans/${id}/`),
  findings: (id: string, status = 'all') => request<Finding[]>(`/api/v1/domains/${id}/findings/?status=${encodeURIComponent(status)}`),
  finding: (id: string) => request<FindingDetail>(`/api/v1/findings/${id}/`),
  acceptRisk: (id: string, reason: string, until: string) => request<Finding>(`/api/v1/findings/${id}/accept-risk/`, { method: 'POST', body: JSON.stringify({ reason, until }) }),
  reports: (id: string) => request<Report[]>(`/api/v1/domains/${id}/reports/`),
  createReport: (id: string) => request<Report>(`/api/v1/domains/${id}/reports/`, { method: 'POST' }),
  downloadReport: async (id: string) => {
    const headers = new Headers(); if (tenantId) headers.set('X-Tenant-ID', tenantId);
    const response = await fetch(`${API_BASE}/api/v1/reports/${id}/pdf/`, { headers, credentials: 'include', cache: 'no-store' });
    if (!response.ok) throw new ApiError('Could not download the PDF report.', response.status, await response.text());
    const blob = await response.blob(); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = `security-report-${id}.pdf`; a.click(); URL.revokeObjectURL(url);
  },
};
