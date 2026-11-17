// Client for django-allauth's "headless" browser API (see backend/config/urls.py).
//
// Every call resolves to an AuthResult and NEVER throws on an HTTP error: 400/401/403/409/429 are
// normal outcomes here (wrong password, "second factor needed", "confirm your email first").
// Next.js proxies /api/auth/browser/* to Django (next.config.ts), so cookies stay same-origin.

const BASE = '/api/auth/browser/v1';
export const TOTP_ISSUER = 'Security Posture Scanner'; // keep equal to MFA_TOTP_ISSUER in Django

export interface FieldError {
  message: string;
  code?: string;
  param?: string;
}
export interface Flow {
  id: string;
  is_pending?: boolean;
  types?: string[];
}
export interface AuthUser {
  id?: string | number;
  display?: string;
  email?: string;
  has_usable_password?: boolean;
}
export interface AuthResult<T = unknown> {
  status: number; // HTTP status; 0 = the server could not be reached
  ok: boolean; // 2xx
  authenticated: boolean; // the browser now holds a signed-in session
  flows: Flow[]; // what the server wants next (verify_email, mfa_authenticate, reauthenticate...)
  user: AuthUser | null;
  errors: FieldError[];
  data: T | null;
  meta: Record<string, unknown>;
}

export interface SignupPayload {
  email: string;
  password: string;
  organisation_name: string;
  display_name?: string;
}
export interface Authenticator {
  type: string; // 'totp' | 'recovery_codes'
  created_at?: number;
  last_used_at?: number | null;
  total_code_count?: number;
  unused_code_count?: number;
  unused_codes?: string[];
}
export interface SocialProvider {
  id: string;
  name: string;
  flows?: string[];
}
interface ConfigData {
  socialaccount?: { providers?: SocialProvider[] };
}

// ---- helpers ---------------------------------------------------------------------------------

function readCookie(name: string): string {
  if (typeof document === 'undefined') return '';
  const hit = document.cookie.split('; ').find((part) => part.startsWith(`${name}=`));
  return hit ? decodeURIComponent(hit.slice(name.length + 1)) : '';
}

/** Django sets the csrftoken cookie from this endpoint; POST/PUT/DELETE need it. */
async function ensureCsrf(): Promise<void> {
  if (readCookie('csrftoken')) return;
  try {
    await fetch('/api/v1/auth/csrf/', { credentials: 'include', cache: 'no-store' });
  } catch {
    /* the real request below reports the network problem */
  }
}

function failure<T>(status: number, message: string): AuthResult<T> {
  return {
    status,
    ok: false,
    authenticated: false,
    flows: [],
    user: null,
    errors: [{ message }],
    data: null,
    meta: {},
  };
}

async function call<T = unknown>(
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  path: string,
  body?: unknown,
  headers: Record<string, string> = {},
): Promise<AuthResult<T>> {
  const unsafe = method !== 'GET';
  if (unsafe) await ensureCsrf();

  const h = new Headers({ Accept: 'application/json', ...headers });
  if (body !== undefined) h.set('Content-Type', 'application/json');
  if (unsafe) {
    const token = readCookie('csrftoken');
    if (token) h.set('X-CSRFToken', token);
  }

  let response: Response;
  try {
    response = await fetch(`${BASE}${path}`, {
      method,
      headers: h,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'include',
      cache: 'no-store',
    });
  } catch {
    return failure(0, 'Cannot reach the server. Check your connection and try again.');
  }

  let json: Record<string, unknown> = {};
  try {
    json = (await response.json()) as Record<string, unknown>;
  } catch {
    /* empty or non-JSON body (proxy error page, 204...) */
  }

  const data = (json.data ?? null) as (T & { flows?: Flow[]; user?: AuthUser }) | null;
  const meta = (json.meta ?? {}) as Record<string, unknown>;
  const errors = Array.isArray(json.errors) ? (json.errors as FieldError[]) : [];
  const flows = Array.isArray(data?.flows) ? (data?.flows as Flow[]) : [];

  const result: AuthResult<T> = {
    status: response.status,
    ok: response.ok,
    authenticated: meta.is_authenticated === true,
    flows,
    user: data?.user ?? null,
    errors,
    data,
    meta,
  };

  if (!result.ok && result.status !== 401 && errors.length === 0) {
    result.errors = [
      {
        message:
          response.status === 429
            ? 'Too many attempts. Wait a few minutes and try again.'
            : response.status === 403
              ? 'That is not allowed.'
              : `Unexpected server response (${response.status}).`,
      },
    ];
  }
  return result;
}

export function hasPendingFlow(result: { flows: Flow[] }, id: string): boolean {
  return result.flows.some((flow) => flow.id === id && flow.is_pending === true);
}

/** The server wants the user to confirm their identity again before a sensitive change. */
export function needsReauth(result: AuthResult<unknown>): boolean {
  return (
    result.status === 401 &&
    result.flows.some((flow) => flow.id === 'reauthenticate' || flow.id === 'mfa_reauthenticate')
  );
}

/** Splits errors into per-field messages (param set) and a general message. */
export function splitErrors(errors: FieldError[]): {
  fields: Record<string, string>;
  general: string;
} {
  const fields: Record<string, string> = {};
  const general: string[] = [];
  for (const error of errors) {
    if (error.param) fields[error.param] ??= error.message;
    else general.push(error.message);
  }
  return { fields, general: general.join(' ') };
}

/** Only same-site paths: stops "?next=https://evil.example" open redirects. */
export function safeNext(raw: string | null | undefined): string {
  if (!raw || !raw.startsWith('/') || raw.startsWith('//') || raw.startsWith('/\\')) return '/';
  return raw;
}

export function totpUri(secret: string, account: string): string {
  const label = `${encodeURIComponent(TOTP_ISSUER)}:${encodeURIComponent(account)}`;
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(TOTP_ISSUER)}`;
}

/** Social sign-in must be a real browser form POST (the server answers with a redirect). */
export async function startSocialLogin(provider: string, callbackUrl: string): Promise<void> {
  await ensureCsrf();
  const form = document.createElement('form');
  form.method = 'POST';
  form.action = `${BASE}/auth/provider/redirect`;
  const fields: Record<string, string> = {
    provider,
    callback_url: callbackUrl,
    process: 'login',
    csrfmiddlewaretoken: readCookie('csrftoken'),
  };
  for (const [name, value] of Object.entries(fields)) {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = name;
    input.value = value;
    form.appendChild(input);
  }
  document.body.appendChild(form);
  form.submit();
}

// ---- endpoints -------------------------------------------------------------------------------

export const authApi = {
  config: () => call<ConfigData>('GET', '/config'),
  session: () => call('GET', '/auth/session'),
  login: (email: string, password: string) => call('POST', '/auth/login', { email, password }),
  signup: (payload: SignupPayload) => call('POST', '/auth/signup', payload),
  logout: () => call('DELETE', '/auth/session'), // answers 401 ("now signed out"): that is success

  requestPasswordReset: (email: string) => call('POST', '/auth/password/request', { email }),
  passwordResetInfo: (key: string) =>
    call('GET', '/auth/password/reset', undefined, { 'X-Password-Reset-Key': key }),
  resetPassword: (key: string, password: string) =>
    call('POST', '/auth/password/reset', { key, password }),

  emailVerificationInfo: (key: string) =>
    call<{ email?: string }>('GET', '/auth/email/verify', undefined, {
      'X-Email-Verification-Key': key,
    }),
  verifyEmail: (key: string) => call('POST', '/auth/email/verify', { key }),

  mfaAuthenticate: (code: string) => call('POST', '/auth/2fa/authenticate', { code }),
  reauthenticate: (password: string) => call('POST', '/auth/reauthenticate', { password }),
  mfaReauthenticate: (code: string) => call('POST', '/auth/2fa/reauthenticate', { code }),

  changePassword: (currentPassword: string | null, newPassword: string) =>
    call('POST', '/account/password/change', {
      ...(currentPassword ? { current_password: currentPassword } : {}),
      new_password: newPassword,
    }),

  authenticators: () => call<Authenticator[]>('GET', '/account/authenticators'),
  totpSetup: () => call<Authenticator>('GET', '/account/authenticators/totp'), // 404 + meta.secret
  totpActivate: (code: string) => call<Authenticator>('POST', '/account/authenticators/totp', { code }),
  totpDeactivate: () => call('DELETE', '/account/authenticators/totp'),
  recoveryCodes: () => call<Authenticator>('GET', '/account/authenticators/recovery_codes'),
  regenerateRecoveryCodes: () => call('POST', '/account/authenticators/recovery_codes'),
};