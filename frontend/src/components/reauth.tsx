'use client';
import { useCallback, useState } from 'react';
import { X } from 'lucide-react';
import { authApi, needsReauth, splitErrors, type AuthResult } from '@/lib/api/auth';

type Request = { mode: 'password' | 'code'; done: (ok: boolean) => void };

/**
 * Sensitive account changes (set up or remove two-step verification, view recovery codes) make the
 * server answer 401 "reauthenticate" when the last password check is older than a few minutes.
 *
 *   const { withReauth, dialog } = useReauth();
 *   const result = await withReauth(() => authApi.totpDeactivate());
 *   ...
 *   return <>{dialog} ...</>;
 *
 * withReauth runs the call, asks for the password if the server demands it, then runs it once more.
 */
export function useReauth() {
  const [request, setRequest] = useState<Request | null>(null);

  const withReauth = useCallback(async <T,>(run: () => Promise<AuthResult<T>>): Promise<AuthResult<T>> => {
    const first = await run();
    if (!needsReauth(first)) return first;
    // Accounts without a password (social sign-in) confirm with their authenticator code instead.
    const mode = first.flows.some((flow) => flow.id === 'reauthenticate') ? 'password' : 'code';
    const confirmed = await new Promise<boolean>((resolve) => setRequest({ mode, done: resolve }));
    return confirmed ? run() : first;
  }, []);

  const dialog = request ? (
    <ReauthDialog
      mode={request.mode}
      onDone={(ok) => {
        request.done(ok);
        setRequest(null);
      }}
    />
  ) : null;

  return { withReauth, dialog };
}

function ReauthDialog({ mode, onDone }: { mode: 'password' | 'code'; onDone: (ok: boolean) => void }) {
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    const result = mode === 'password' ? await authApi.reauthenticate(value) : await authApi.mfaReauthenticate(value.trim());
    if (result.ok) return onDone(true);
    setBusy(false);
    const { fields, general } = splitErrors(result.errors);
    setError(general || Object.values(fields)[0] || 'That did not work. Please try again.');
  };

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="reauth-title">
        <button className="modal-close" onClick={() => onDone(false)} aria-label="Close" type="button"><X /></button>
        <h2 id="reauth-title">Confirm it is you</h2>
        <p>{mode === 'password' ? 'Enter your password to continue with this change.' : 'Enter a code from your authenticator app to continue with this change.'}</p>
        <form onSubmit={submit}>
          <label htmlFor="reauth-input">{mode === 'password' ? 'Password' : 'Authentication code'}</label>
          <input
            id="reauth-input"
            type={mode === 'password' ? 'password' : 'text'}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            autoComplete={mode === 'password' ? 'current-password' : 'one-time-code'}
            autoFocus
            required
          />
          {error && <small className="field-error">{error}</small>}
          <div className="modal-actions">
            <button type="button" className="button subtle" onClick={() => onDone(false)}>Cancel</button>
            <button className="button primary" disabled={busy}>{busy ? 'Checking…' : 'Confirm'}</button>
          </div>
        </form>
      </div>
    </div>
  );
}