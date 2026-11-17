'use client';
import Link from 'next/link';
import { useState } from 'react';
import { useApp } from '@/components/app-provider';
import { Alert, AuthCard, CheckInbox, PasswordField, SocialButtons, SubmitButton, TextField } from '@/components/auth-ui';
import { authApi, hasPendingFlow, splitErrors } from '@/lib/api/auth';

export default function SignupPage() {
  const { refresh } = useApp();
  const [organisation, setOrganisation] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [fields, setFields] = useState<Record<string, string>>({});
  const [general, setGeneral] = useState('');
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFields({});
    setGeneral('');
    if (password !== confirm) {
      setFields({ confirm: 'The two passwords do not match.' });
      return;
    }
    setBusy(true);
    const result = await authApi.signup({
      email: email.trim(),
      password,
      organisation_name: organisation.trim(),
      display_name: displayName.trim() || undefined,
    });
    if (result.authenticated) {
      await refresh();
      return;
    }
    setBusy(false);
    if (hasPendingFlow(result, 'verify_email')) return setPending(true);
    if (result.status === 403) {
      return setGeneral('Sign-ups are closed right now. Ask your administrator for an invitation.');
    }
    const split = splitErrors(result.errors);
    setFields(split.fields);
    setGeneral(split.general || (Object.keys(split.fields).length ? '' : 'Could not create the account. Please try again.'));
  };

  if (pending) {
    return (
      <AuthCard title="Check your inbox" subtitle="Your account is almost ready.">
        <CheckInbox
          email={email.trim()}
          password={password}
          onSignedIn={refresh}
          onBack={() => {
            setPending(false);
            setPassword('');
            setConfirm('');
          }}
        />
      </AuthCard>
    );
  }

  return (
    <AuthCard
      title="Create your account"
      subtitle="Set up your organisation and start monitoring your domains."
      footer={<>Already have an account? <Link href="/login">Sign in</Link></>}
    >
      <form className="auth-form" onSubmit={submit} noValidate>
        {general && <Alert kind="error">{general}</Alert>}
        <TextField label="Organisation name" value={organisation} onChange={(e) => setOrganisation(e.target.value)} error={fields.organisation_name} autoComplete="organization" minLength={2} maxLength={200} autoFocus required />
        <TextField label="Your name (optional)" value={displayName} onChange={(e) => setDisplayName(e.target.value)} error={fields.display_name} autoComplete="name" maxLength={200} />
        <TextField label="Work email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} error={fields.email} autoComplete="email" required />
        <PasswordField label="Password" value={password} onChange={(e) => setPassword(e.target.value)} error={fields.password} hint="At least 12 characters. Avoid common passwords." autoComplete="new-password" minLength={12} required />
        <PasswordField label="Confirm password" value={confirm} onChange={(e) => setConfirm(e.target.value)} error={fields.confirm} autoComplete="new-password" required />
        <SubmitButton busy={busy} busyLabel="Creating account…">Create account</SubmitButton>
      </form>
      <SocialButtons />
    </AuthCard>
  );
}