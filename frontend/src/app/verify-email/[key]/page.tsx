'use client';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import { useApp } from '@/components/app-provider';
import { Alert, AuthCard } from '@/components/auth-ui';
import { authApi, splitErrors } from '@/lib/api/auth';

export default function VerifyEmailPage() {
  const { key } = useParams<{ key: string }>();
  const router = useRouter();
  const { refresh } = useApp();
  const [phase, setPhase] = useState<'checking' | 'ready' | 'invalid' | 'confirmed'>('checking');
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  // Reading the link has no side effects (only the button confirms), so mail scanners that
  // pre-open links cannot use it up.
  useEffect(() => {
    let live = true;
    void authApi.emailVerificationInfo(key).then((result) => {
      if (!live) return;
      if (result.ok) {
        setEmail(result.data?.email ?? '');
        setPhase('ready');
      } else {
        setPhase('invalid');
      }
    });
    return () => {
      live = false;
    };
  }, [key]);

  const confirm = async () => {
    setBusy(true);
    setError('');
    const result = await authApi.verifyEmail(key);
    if (result.authenticated) {
      await refresh();
      router.replace('/');
      return;
    }
    setBusy(false);
    // 401: confirmed, but the browser is not signed in (opened in another browser, or a second
    // factor is still needed). The sign-in page picks up from there.
    if (result.ok || result.status === 401) return setPhase('confirmed');
    const { general, fields } = splitErrors(result.errors);
    if (result.status === 400) return setPhase('invalid');
    setError(general || fields.key || 'Could not confirm the email address. Please try again.');
  };

  if (phase === 'checking') {
    return <AuthCard title="Confirm your email"><p className="auth-copy">Checking your link…</p></AuthCard>;
  }
  if (phase === 'invalid') {
    return (
      <AuthCard title="Link expired" subtitle="This confirmation link is invalid or has already been used." footer={<Link href="/login">Back to sign in</Link>}>
        <p className="auth-copy">If you have already confirmed your email, you can sign in. Otherwise sign in and we will send a fresh link.</p>
      </AuthCard>
    );
  }
  if (phase === 'confirmed') {
    return (
      <AuthCard title="Email confirmed" subtitle="Thanks. Your email address is verified.">
        <Link className="button primary full-width" href="/login">Continue to sign in</Link>
      </AuthCard>
    );
  }
  return (
    <AuthCard title="Confirm your email" subtitle={email ? `Confirm ${email} to finish setting up your account.` : 'Confirm your email address to finish setting up your account.'}>
      <div className="auth-form">
        {error && <Alert kind="error">{error}</Alert>}
        <button className="button primary full-width" disabled={busy} onClick={() => void confirm()}>
          {busy ? 'Confirming…' : 'Confirm email address'}
        </button>
      </div>
    </AuthCard>
  );
}