'use client';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import { Alert, AuthCard, PasswordField, SubmitButton } from '@/components/auth-ui';
import { authApi, splitErrors } from '@/lib/api/auth';

export default function ResetPasswordPage() {
  const { key } = useParams<{ key: string }>();
  const router = useRouter();
  const [phase, setPhase] = useState<'checking' | 'ready' | 'invalid'>('checking');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [fields, setFields] = useState<Record<string, string>>({});
  const [general, setGeneral] = useState('');
  const [busy, setBusy] = useState(false);

  // Look the link up first, so an expired or used link says so instead of failing after typing.
  useEffect(() => {
    let live = true;
    void authApi.passwordResetInfo(key).then((result) => {
      if (live) setPhase(result.ok ? 'ready' : 'invalid');
    });
    return () => {
      live = false;
    };
  }, [key]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFields({});
    setGeneral('');
    if (password !== confirm) {
      setFields({ confirm: 'The two passwords do not match.' });
      return;
    }
    setBusy(true);
    const result = await authApi.resetPassword(key, password);
    setBusy(false);
    // 401 without errors means "password changed, you are not signed in": the normal outcome.
    if (result.ok || (result.status === 401 && result.errors.length === 0)) {
      router.replace('/login?reset=1');
      return;
    }
    const split = splitErrors(result.errors);
    if (result.status === 400 && split.fields.key) return setPhase('invalid');
    setFields(split.fields);
    setGeneral(split.general || (Object.keys(split.fields).length ? '' : 'Could not update the password. Please try again.'));
  };

  if (phase === 'checking') {
    return <AuthCard title="Reset your password"><p className="auth-copy">Checking your link…</p></AuthCard>;
  }
  if (phase === 'invalid') {
    return (
      <AuthCard title="Link expired" subtitle="This password reset link is invalid or has already been used." footer={<Link href="/login">Back to sign in</Link>}>
        <Link className="button primary full-width" href="/forgot-password">Request a new link</Link>
      </AuthCard>
    );
  }
  return (
    <AuthCard title="Choose a new password" subtitle="Pick a strong password you do not use anywhere else.">
      <form className="auth-form" onSubmit={submit} noValidate>
        {general && <Alert kind="error">{general}</Alert>}
        <PasswordField label="New password" value={password} onChange={(e) => setPassword(e.target.value)} error={fields.password} hint="At least 12 characters. Avoid common passwords." autoComplete="new-password" minLength={12} autoFocus required />
        <PasswordField label="Confirm new password" value={confirm} onChange={(e) => setConfirm(e.target.value)} error={fields.confirm} autoComplete="new-password" required />
        <SubmitButton busy={busy} busyLabel="Saving…">Update password</SubmitButton>
      </form>
    </AuthCard>
  );
}