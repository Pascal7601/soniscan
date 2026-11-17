'use client';
import Link from 'next/link';
import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { useApp } from '@/components/app-provider';
import { Alert, AuthCard, CheckInbox, MfaChallenge, PasswordField, SocialButtons, SubmitButton, TextField } from '@/components/auth-ui';
import { authApi, hasPendingFlow, safeNext, splitErrors } from '@/lib/api/auth';

type Step = 'credentials' | 'mfa' | 'verify';

function LoginForm() {
  const params = useSearchParams();
  const next = safeNext(params.get('next'));
  const { refresh } = useApp();
  const [step, setStep] = useState<Step>('credentials');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  // Resume a half-finished sign-in: page reload, or coming back from Google/Microsoft.
  useEffect(() => {
    let live = true;
    void authApi.session().then((result) => {
      if (!live) return;
      if (hasPendingFlow(result, 'mfa_authenticate')) setStep('mfa');
      else if (hasPendingFlow(result, 'verify_email')) setStep('verify');
    });
    return () => {
      live = false;
    };
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    const result = await authApi.login(email.trim(), password);
    if (result.authenticated) {
      await refresh(); // the app shell then forwards to `next`
      return;
    }
    setBusy(false);
    if (hasPendingFlow(result, 'mfa_authenticate')) return setStep('mfa');
    if (hasPendingFlow(result, 'verify_email')) return setStep('verify');
    const { fields, general } = splitErrors(result.errors);
    setError(general || Object.values(fields)[0] || 'Could not sign in. Please try again.');
  };

  // Drops the half-finished session on the server, so the next attempt starts clean.
  const startOver = async () => {
    await authApi.logout();
    setPassword('');
    setError('');
    setStep('credentials');
  };

  if (step === 'mfa') {
    return (
      <AuthCard title="Two-step verification" subtitle="Your account is protected with a second factor.">
        <MfaChallenge onAuthenticated={refresh} onCancel={() => void startOver()} />
      </AuthCard>
    );
  }
  if (step === 'verify') {
    return (
      <AuthCard title="Confirm your email" subtitle="One more step before you can sign in.">
        <CheckInbox email={email.trim() || undefined} password={password || undefined} onSignedIn={refresh} onBack={() => void startOver()} />
      </AuthCard>
    );
  }

  return (
    <AuthCard
      title="Sign in"
      subtitle="Welcome back. Sign in to see your security posture."
      footer={<>New to Soni? <Link href="/signup">Create an account</Link></>}
    >
      <form className="auth-form" onSubmit={submit} noValidate>
        {params.get('reset') === '1' && <Alert kind="success">Password updated. Sign in with your new password.</Alert>}
        {params.get('error') === 'social' && <Alert kind="error">Social sign-in did not complete. Please try again.</Alert>}
        {error && <Alert kind="error">{error}</Alert>}
        <TextField label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" autoFocus required />
        <PasswordField label="Password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
        <div className="auth-row-end"><Link className="auth-inline-link" href="/forgot-password">Forgot password?</Link></div>
        <SubmitButton busy={busy} busyLabel="Signing in…">Sign in</SubmitButton>
      </form>
      <SocialButtons next={next} />
    </AuthCard>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={null}>
      <LoginForm />
    </Suspense>
  );
}