'use client';
import Link from 'next/link';
import { useState } from 'react';
import { Alert, AuthCard, SubmitButton, TextField } from '@/components/auth-ui';
import { authApi, splitErrors } from '@/lib/api/auth';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [sent, setSent] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    const result = await authApi.requestPasswordReset(email.trim());
    setBusy(false);
    if (result.ok) return setSent(true);
    const { fields, general } = splitErrors(result.errors);
    setError(general || fields.email || 'Could not send the reset email. Please try again.');
  };

  return (
    <AuthCard
      title="Reset your password"
      subtitle="Enter your email and we will send you a link to choose a new password."
      footer={<Link href="/login">Back to sign in</Link>}
    >
      {sent ? (
        <div className="auth-form">
          <Alert kind="success">If an account exists for {email.trim()}, a reset link is on its way. The link expires in one hour.</Alert>
        </div>
      ) : (
        <form className="auth-form" onSubmit={submit} noValidate>
          {error && <Alert kind="error">{error}</Alert>}
          <TextField label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" autoFocus required />
          <SubmitButton busy={busy} busyLabel="Sending…">Send reset link</SubmitButton>
        </form>
      )}
    </AuthCard>
  );
}