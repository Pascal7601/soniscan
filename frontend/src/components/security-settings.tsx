'use client';
import { useCallback, useEffect, useState } from 'react';
import { Copy, Download, KeyRound, ShieldCheck, Smartphone } from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';
import { useApp } from '@/components/app-provider';
import { Alert, PasswordField, SubmitButton, TextField } from '@/components/auth-ui';
import { useReauth } from '@/components/reauth';
import { LoadingState } from '@/components/ui';
import { authApi, needsReauth, splitErrors, totpUri } from '@/lib/api/auth';

export function SecuritySettings() {
  return (
    <div className="settings-stack">
      <PasswordPanel />
      <TwoFactorPanel />
    </div>
  );
}

// ---- change password -------------------------------------------------------------------------

function PasswordPanel() {
  const { authUser, refresh } = useApp();
  const hasPassword = authUser?.has_usable_password !== false; // social-only accounts have none
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [fields, setFields] = useState<Record<string, string>>({});
  const [general, setGeneral] = useState('');
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFields({});
    setGeneral('');
    setDone(false);
    if (next !== confirm) {
      setFields({ confirm: 'The two passwords do not match.' });
      return;
    }
    setBusy(true);
    const result = await authApi.changePassword(hasPassword ? current : null, next);
    setBusy(false);
    if (result.ok) {
      setCurrent('');
      setNext('');
      setConfirm('');
      setDone(true);
      void refresh();
      return;
    }
    const split = splitErrors(result.errors);
    setFields(split.fields);
    setGeneral(split.general || (Object.keys(split.fields).length ? '' : 'Could not change the password.'));
  };

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2><KeyRound size={18} /> {hasPassword ? 'Change password' : 'Set a password'}</h2>
          <p>Use at least 12 characters. Changing your password signs you out on other devices.</p>
        </div>
      </div>
      <form className="inline-form" onSubmit={submit} noValidate>
        {done && <Alert kind="success">Your password was updated.</Alert>}
        {general && <Alert kind="error">{general}</Alert>}
        {hasPassword && (
          <PasswordField label="Current password" value={current} onChange={(e) => setCurrent(e.target.value)} error={fields.current_password} autoComplete="current-password" required />
        )}
        <PasswordField label="New password" value={next} onChange={(e) => setNext(e.target.value)} error={fields.new_password} autoComplete="new-password" minLength={12} required />
        <PasswordField label="Confirm new password" value={confirm} onChange={(e) => setConfirm(e.target.value)} error={fields.confirm} autoComplete="new-password" required />
        <div><SubmitButton busy={busy} busyLabel="Saving…">Update password</SubmitButton></div>
      </form>
    </section>
  );
}

// ---- two-step verification (authenticator app + recovery codes) ------------------------------

type View =
  | { kind: 'loading' }
  | { kind: 'off' }
  | { kind: 'on'; unused?: number }
  | { kind: 'setup'; secret: string }
  | { kind: 'codes'; codes: string[]; fresh: boolean };

function TwoFactorPanel() {
  const { me, authUser, refresh } = useApp();
  const { withReauth, dialog } = useReauth();
  const [view, setView] = useState<View>({ kind: 'loading' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [confirmingOff, setConfirmingOff] = useState(false);
  const account = me?.email ?? authUser?.email ?? 'account';

  const load = useCallback(async () => {
    const result = await authApi.authenticators();
    const list = result.data ?? [];
    const totp = list.some((a) => a.type === 'totp');
    const recovery = list.find((a) => a.type === 'recovery_codes');
    setView(totp ? { kind: 'on', unused: recovery?.unused_code_count } : { kind: 'off' });
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const startSetup = async () => {
    setBusy(true);
    setError('');
    setNotice('');
    const result = await withReauth(() => authApi.totpSetup());
    setBusy(false);
    if (needsReauth(result)) return; // the person cancelled the password prompt
    const secret = result.meta.secret; // "404 + secret" means: not set up yet, here is a new key
    if (typeof secret === 'string') setView({ kind: 'setup', secret });
    else if (result.ok) await load();
    else setError(splitErrors(result.errors).general || 'Could not start the setup. Please try again.');
  };

  const showRecoveryCodes = async (fresh: boolean) => {
    setBusy(true);
    setError('');
    const result = await withReauth(() => authApi.recoveryCodes());
    setBusy(false);
    const codes = result.data?.unused_codes ?? [];
    if (result.ok && codes.length > 0) setView({ kind: 'codes', codes, fresh });
    else if (result.ok) {
      setView({ kind: 'on', unused: 0 });
      setNotice('There are no unused recovery codes. Generate new ones.');
    } else if (!needsReauth(result)) {
      setError(splitErrors(result.errors).general || 'Could not load the recovery codes.');
    }
  };

  const confirmSetup = async (code: string): Promise<string> => {
    const result = await withReauth(() => authApi.totpActivate(code));
    if (!result.ok) {
      const split = splitErrors(result.errors);
      return split.fields.code || split.general || 'That code is not valid. Check your app and try again.';
    }
    void refresh(); // updates "MFA: Enabled" in the account card
    await showRecoveryCodes(true);
    return '';
  };

  const regenerate = async () => {
    setBusy(true);
    setError('');
    const result = await withReauth(() => authApi.regenerateRecoveryCodes());
    setBusy(false);
    if (result.ok) await showRecoveryCodes(true);
    else if (!needsReauth(result)) setError(splitErrors(result.errors).general || 'Could not generate new codes.');
  };

  const turnOff = async () => {
    setBusy(true);
    setError('');
    const result = await withReauth(() => authApi.totpDeactivate());
    setBusy(false);
    setConfirmingOff(false);
    if (result.ok) {
      setNotice('Two-step verification is now off.');
      void refresh();
      await load();
    } else if (!needsReauth(result)) {
      setError(splitErrors(result.errors).general || 'Could not turn off two-step verification.');
    }
  };

  return (
    <section className="panel">
      {dialog}
      <div className="panel-heading">
        <div>
          <h2><ShieldCheck size={18} /> Two-step verification</h2>
          <p>Require a code from an authenticator app (Google Authenticator, 1Password, Authy) after your password.</p>
        </div>
      </div>
      {error && <Alert kind="error">{error}</Alert>}
      {notice && <Alert kind="success">{notice}</Alert>}

      {view.kind === 'loading' && <LoadingState label="Loading…" />}

      {view.kind === 'off' && (
        <div className="inline-form">
          <p className="muted-copy">Two-step verification is off. Turn it on to protect your account if your password is ever stolen.</p>
          <div><button className="button primary" disabled={busy} onClick={() => void startSetup()}><Smartphone size={15} /> {busy ? 'Starting…' : 'Set up authenticator app'}</button></div>
        </div>
      )}

      {view.kind === 'setup' && (
        <TotpSetup
          secret={view.secret}
          account={account}
          onConfirm={confirmSetup}
          onCancel={() => setView({ kind: 'off' })}
        />
      )}

      {view.kind === 'on' && (
        <div className="inline-form">
          <p className="muted-copy">
            Two-step verification is <strong>on</strong>.
            {typeof view.unused === 'number' ? ` You have ${view.unused} unused recovery code${view.unused === 1 ? '' : 's'}.` : ''}
          </p>
          <div className="button-row">
            <button className="button subtle" disabled={busy} onClick={() => void showRecoveryCodes(false)}>View recovery codes</button>
            <button className="button subtle" disabled={busy} onClick={() => void regenerate()}>Generate new codes</button>
            {confirmingOff ? (
              <>
                <button className="button danger" disabled={busy} onClick={() => void turnOff()}>Yes, turn off</button>
                <button className="button subtle" onClick={() => setConfirmingOff(false)}>Keep it on</button>
              </>
            ) : (
              <button className="button danger" disabled={busy} onClick={() => setConfirmingOff(true)}>Turn off</button>
            )}
          </div>
        </div>
      )}

      {view.kind === 'codes' && (
        <RecoveryCodes
          codes={view.codes}
          fresh={view.fresh}
          onDone={() => {
            setNotice(view.fresh ? 'Two-step verification is on. Keep your recovery codes somewhere safe.' : '');
            void load();
          }}
        />
      )}
    </section>
  );
}

function TotpSetup({
  secret,
  account,
  onConfirm,
  onCancel,
}: {
  secret: string;
  account: string;
  onConfirm: (code: string) => Promise<string>;
  onCancel: () => void;
}) {
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    const message = await onConfirm(code.trim());
    if (message) {
      setError(message);
      setBusy(false);
    }
  };

  return (
    <form className="inline-form" onSubmit={submit} noValidate>
      <ol className="steps">
        <li><span>1</span><div><strong>Scan this QR code</strong><p>Open your authenticator app and add an account by scanning the code.</p></div></li>
      </ol>
      <div className="qr-row">
        <div className="qr-box"><QRCodeSVG value={totpUri(secret, account)} size={168} /></div>
        <div>
          <p className="muted-copy">Cannot scan? Enter this key by hand:</p>
          <code className="secret-code">{secret}</code>
        </div>
      </div>
      <ol className="steps">
        <li><span>2</span><div><strong>Enter the 6-digit code</strong><p>Type the code your app shows to finish.</p></div></li>
      </ol>
      {error && <Alert kind="error">{error}</Alert>}
      <TextField label="Code from your app" value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" maxLength={8} required />
      <div className="button-row">
        <SubmitButton busy={busy} busyLabel="Checking…">Turn on</SubmitButton>
        <button type="button" className="button subtle" onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}

function RecoveryCodes({ codes, fresh, onDone }: { codes: string[]; fresh: boolean; onDone: () => void }) {
  const [copied, setCopied] = useState(false);
  const text = codes.join('\n');

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
    } catch {
      /* clipboard blocked: the codes are still on screen */
    }
  };
  const download = () => {
    const url = URL.createObjectURL(new Blob([`Soni recovery codes\n\n${text}\n`], { type: 'text/plain' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'soni-recovery-codes.txt';
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="inline-form">
      <Alert kind="info">
        {fresh ? 'Save these recovery codes now. ' : ''}Each code works once if you lose access to your authenticator app. Anyone with a code can sign in, so store them like a password.
      </Alert>
      <div className="recovery-grid">
        {codes.map((c) => <code key={c}>{c}</code>)}
      </div>
      <div className="button-row">
        <button className="button subtle" onClick={() => void copy()}><Copy size={15} /> {copied ? 'Copied' : 'Copy'}</button>
        <button className="button subtle" onClick={download}><Download size={15} /> Download</button>
        <button className="button primary" onClick={onDone}>I have saved them</button>
      </div>
    </div>
  );
}