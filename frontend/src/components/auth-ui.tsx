'use client';
import { useEffect, useId, useState } from 'react';
import { AlertCircle, CheckCircle2, Eye, EyeOff, LoaderCircle, MailCheck, ShieldCheck } from 'lucide-react';
import { authApi, hasPendingFlow, splitErrors, startSocialLogin, type SocialProvider } from '@/lib/api/auth';

// ---- layout ----------------------------------------------------------------------------------

export function AuthCard({
  title,
  subtitle,
  children,
  footer,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
}) {
  return (
    <div className="auth-wrap">
      <div className="auth-brand">
        <span className="brand-mark"><ShieldCheck size={20} /></span>
        <span><strong>soni</strong><small>SECURITY POSTURE</small></span>
      </div>
      <section className="auth-card">
        <h1>{title}</h1>
        {subtitle && <p className="auth-subtitle">{subtitle}</p>}
        {children}
      </section>
      {footer && <div className="auth-footer">{footer}</div>}
    </div>
  );
}

export function Alert({ kind, children }: { kind: 'error' | 'success' | 'info'; children: React.ReactNode }) {
  return (
    <div className={`auth-alert ${kind}`} role={kind === 'error' ? 'alert' : 'status'}>
      {kind === 'success' ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
      <span>{children}</span>
    </div>
  );
}

// ---- form fields -----------------------------------------------------------------------------

type FieldProps = React.InputHTMLAttributes<HTMLInputElement> & {
  label: string;
  error?: string;
  hint?: string;
};

export function TextField({ label, error, hint, id, ...input }: FieldProps) {
  const auto = useId();
  const fieldId = id ?? auto;
  return (
    <div className={`auth-field ${error ? 'has-error' : ''}`}>
      <label htmlFor={fieldId}>{label}</label>
      <input id={fieldId} aria-invalid={error ? true : undefined} {...input} />
      {error ? <small className="field-error">{error}</small> : hint ? <small>{hint}</small> : null}
    </div>
  );
}

export function PasswordField({ label, error, hint, id, ...input }: FieldProps) {
  const auto = useId();
  const fieldId = id ?? auto;
  const [shown, setShown] = useState(false);
  return (
    <div className={`auth-field ${error ? 'has-error' : ''}`}>
      <label htmlFor={fieldId}>{label}</label>
      <div className="password-wrap">
        <input id={fieldId} type={shown ? 'text' : 'password'} aria-invalid={error ? true : undefined} {...input} />
        <button
          type="button"
          className="password-toggle"
          onClick={() => setShown((v) => !v)}
          aria-label={shown ? 'Hide password' : 'Show password'}
          tabIndex={-1}
        >
          {shown ? <EyeOff size={16} /> : <Eye size={16} />}
        </button>
      </div>
      {error ? <small className="field-error">{error}</small> : hint ? <small>{hint}</small> : null}
    </div>
  );
}

export function SubmitButton({ busy, children, busyLabel }: { busy: boolean; children: React.ReactNode; busyLabel?: string }) {
  return (
    <button className="button primary full-width" disabled={busy} type="submit">
      {busy ? <><LoaderCircle className="spin" size={15} /> {busyLabel ?? 'Please wait…'}</> : children}
    </button>
  );
}

// ---- social sign-in (shown only when the backend has a provider configured) ---------------------

export function SocialButtons({ next = '/' }: { next?: string }) {
  const [providers, setProviders] = useState<SocialProvider[]>([]);

  useEffect(() => {
    let live = true;
    void authApi.config().then((result) => {
      if (!live) return;
      const all = result.data?.socialaccount?.providers ?? [];
      setProviders(all.filter((p) => !p.flows || p.flows.includes('provider_redirect')));
    });
    return () => {
      live = false;
    };
  }, []);

  if (providers.length === 0) return null;
  // After the provider round-trip the browser lands on /login, which resumes any pending step
  // (for example a second factor) and then forwards to `next`.
  const callback = `${window.location.origin}/login${next && next !== '/' ? `?next=${encodeURIComponent(next)}` : ''}`;
  return (
    <>
      <div className="auth-divider"><span>or</span></div>
      <div className="social-list">
        {providers.map((p) => (
          <button key={p.id} type="button" className="button subtle full-width" onClick={() => void startSocialLogin(p.id, callback)}>
            Continue with {p.name}
          </button>
        ))}
      </div>
    </>
  );
}

// ---- second factor at sign-in ----------------------------------------------------------------

export function MfaChallenge({
  onAuthenticated,
  onCancel,
}: {
  onAuthenticated: () => Promise<void> | void;
  onCancel: () => void;
}) {
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    const result = await authApi.mfaAuthenticate(code.trim());
    if (result.authenticated) {
      await onAuthenticated();
      return;
    }
    setBusy(false);
    if (!hasPendingFlow(result, 'mfa_authenticate') && result.status === 401) {
      setError('Your sign-in session expired. Please start again.');
    } else {
      setError(splitErrors(result.errors).general || splitErrors(result.errors).fields.code || 'That code is not valid.');
    }
  };

  return (
    <form className="auth-form" onSubmit={submit} noValidate>
      {error && <Alert kind="error">{error}</Alert>}
      <TextField
        label="Authentication code"
        hint="Enter the 6-digit code from your authenticator app, or one of your recovery codes."
        value={code}
        onChange={(e) => setCode(e.target.value)}
        autoComplete="one-time-code"
        autoFocus
        required
        spellCheck={false}
      />
      <SubmitButton busy={busy} busyLabel="Verifying…">Verify and sign in</SubmitButton>
      <button type="button" className="auth-link-button" onClick={onCancel}>Cancel and use a different account</button>
    </form>
  );
}

// ---- "confirm your email" waiting screen -----------------------------------------------------

export function CheckInbox({
  email,
  password,
  onSignedIn,
  onBack,
}: {
  email?: string;
  password?: string; // kept in memory only, so the confirmation email can be re-sent
  onSignedIn: () => Promise<void> | void;
  onBack: () => void;
}) {
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  // allauth sends at most one confirmation email per 3 minutes per address (its default rate
  // limit), and one was just sent, so the button unlocks after the same period.
  const [cooldown, setCooldown] = useState(180);

  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setTimeout(() => setCooldown((n) => n - 1), 1000);
    return () => clearTimeout(timer);
  }, [cooldown]);

  // Signing in again with the same credentials makes the server re-send the confirmation email.
  const resend = async () => {
    if (!email || !password) return;
    setNotice('');
    setError('');
    setCooldown(180);
    const result = await authApi.login(email, password);
    if (result.authenticated) await onSignedIn();
    else if (hasPendingFlow(result, 'verify_email')) setNotice('We sent the confirmation email again. It can take a minute to arrive.');
    else setError(splitErrors(result.errors).general || 'Could not re-send the email.');
  };

  return (
    <div className="auth-form">
      <div className="auth-icon"><MailCheck size={22} /></div>
      <p className="auth-copy">
        We sent a confirmation link{email ? <> to <strong>{email}</strong></> : null}. Open it to finish signing in. The link works
        once, so check the newest email if you asked for more than one.
      </p>
      {notice && <Alert kind="success">{notice}</Alert>}
      {error && <Alert kind="error">{error}</Alert>}
      {email && password && (
        <button type="button" className="button subtle full-width" disabled={cooldown > 0} onClick={() => void resend()}>
          {cooldown > 0
            ? `Re-send available in ${Math.floor(cooldown / 60)}:${String(cooldown % 60).padStart(2, '0')}`
            : 'Re-send confirmation email'}
        </button>
      )}
      <button type="button" className="auth-link-button" onClick={onBack}>Back to sign in</button>
    </div>
  );
}