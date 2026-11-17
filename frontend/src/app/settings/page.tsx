'use client';
import { LogOut, ShieldCheck, UserRound } from 'lucide-react';
import { useRouter } from 'next/navigation';
import { useApp } from '@/components/app-provider';
import { SecuritySettings } from '@/components/security-settings';
import { PageHeader, StatusBadge } from '@/components/ui';

export default function SettingsPage() {
  const { me, selectedTenant, signOut } = useApp();
  const router = useRouter();
  const membership = me?.memberships.find((m) => m.tenant_id === selectedTenant);
  const handleSignOut = async () => {
    await signOut();
    router.replace('/login');
  };
  return (
    <div className="page-wrap">
      <PageHeader
        eyebrow="PREFERENCES"
        title="Settings"
        description="Manage your account, security and current organisation access."
        action={<button className="button subtle" onClick={() => void handleSignOut()}><LogOut size={15} /> Sign out</button>}
      />
      <div className="two-column">
        <section className="panel">
          <div className="panel-heading"><h2><UserRound size={18} /> Account</h2></div>
          <div className="metadata-list">
            <div><span>Name</span><strong>{me?.display_name || '—'}</strong></div>
            <div><span>Email</span><strong>{me?.email ?? '—'}</strong></div>
            <div><span>MFA</span><strong>{me?.mfa_enabled ? 'Enabled' : 'Not enabled'}</strong></div>
          </div>
        </section>
        <section className="panel">
          <div className="panel-heading"><h2><ShieldCheck size={18} /> Organisation access</h2></div>
          <div className="metadata-list">
            <div><span>Organisation</span><strong>{membership?.tenant_name ?? '—'}</strong></div>
            <div><span>Your role</span>{membership ? <StatusBadge status={membership.role} /> : '—'}</div>
            <div><span>Memberships</span><strong>{me?.memberships.length ?? 0}</strong></div>
          </div>
          <p className="muted-copy">User invitations and organisation management are not exposed by the current backend API.</p>
        </section>
      </div>
      <SecuritySettings />
    </div>
  );
}