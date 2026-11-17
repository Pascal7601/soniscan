'use client';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { Activity, ChevronDown, CircleHelp, FileText, Globe2, LayoutDashboard, LoaderCircle, LogOut, Menu, ScanLine, ShieldAlert, Settings, ShieldCheck } from 'lucide-react';
import { useEffect, useState } from 'react';
import { safeNext } from '@/lib/api/auth';
import { useApp } from './app-provider';

const nav = [
  { href: '/', label: 'Overview', icon: LayoutDashboard },
  { href: '/domains', label: 'Domains', icon: Globe2 },
  { href: '/scans', label: 'Scans', icon: ScanLine },
  { href: '/findings', label: 'Findings', icon: ShieldAlert },
  { href: '/reports', label: 'Reports', icon: FileText },
];

// Screens a signed-in user has no reason to see: they are sent on to the app.
const AUTH_ONLY = ['/login', '/signup', '/forgot-password'];
// Screens reachable without a session. (Email-confirm and reset links also work when signed in.)
const PUBLIC = [...AUTH_ONLY, '/verify-email', '/reset-password'];
const matches = (path: string, list: string[]) => list.some((p) => path === p || path.startsWith(`${p}/`));

function FullPage({ label, children }: { label?: string; children?: React.ReactNode }) {
  return (
    <div className="auth-page">
      <div className="auth-fullpage">
        <LoaderCircle className="spin" size={24} />
        {label && <span>{label}</span>}
        {children}
      </div>
    </div>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const router = useRouter();
  const [mobileOpen, setMobileOpen] = useState(false);
  const { me, authStatus, selectedTenant, selectTenant, loading, error, refresh, signOut } = useApp();

  const publicRoute = matches(path, PUBLIC);
  const authOnlyRoute = matches(path, AUTH_ONLY);

  useEffect(() => {
    if (authStatus === 'anonymous' && !publicRoute) {
      const here = path + window.location.search;
      router.replace(here === '/' ? '/login' : `/login?next=${encodeURIComponent(here)}`);
    }
    if (authStatus === 'authenticated' && authOnlyRoute) {
      router.replace(safeNext(new URLSearchParams(window.location.search).get('next')));
    }
  }, [authStatus, publicRoute, authOnlyRoute, path, router]);

  // ---- screens that do not use the sidebar layout -------------------------------------------
  if (authStatus === 'authenticated' && authOnlyRoute) return <FullPage label="Signing you in…" />;
  if (publicRoute) return <div className="auth-page">{children}</div>;
  if (authStatus === 'loading') return <FullPage label="Loading your workspace…" />;
  if (authStatus === 'error') {
    return (
      <FullPage>
        <strong>API connection issue</strong>
        <span>{error ?? 'Unable to connect to the API.'}</span>
        <button className="button primary" onClick={() => void refresh()}>Retry</button>
      </FullPage>
    );
  }
  if (authStatus === 'anonymous') return <FullPage label="Redirecting to sign in…" />;

  const currentMembership = me?.memberships.find((m) => m.tenant_id === selectedTenant);
  const handleSignOut = async () => {
    setMobileOpen(false);
    await signOut();
    router.replace('/login');
  };

  return <div className="app-shell">
    <aside className={`sidebar ${mobileOpen ? 'sidebar-open' : ''}`}>
      <Link href="/" className="brand"><span className="brand-mark"><ShieldCheck size={20}/></span><span><strong>soni</strong><small>SECURITY POSTURE</small></span></Link>
      <div className="workspace-select"><label>WORKSPACE</label><select aria-label="Select organisation" value={selectedTenant ?? ''} onChange={e => selectTenant(e.target.value)} disabled={!me || me.memberships.length < 2}>{me?.memberships.map(m => <option key={m.tenant_id} value={m.tenant_id}>{m.tenant_name}</option>)}</select><small>{currentMembership?.role ?? (loading ? 'Loading workspace…' : 'Choose a workspace')}</small><ChevronDown className="workspace-chevron" size={14}/></div>
      <div className="nav-label">WORKSPACE</div><nav className="side-nav">{nav.map(item => { const Icon = item.icon; const active = item.href === '/' ? path === '/' : path.startsWith(item.href); return <Link key={item.href} href={item.href} onClick={() => setMobileOpen(false)} className={active ? 'nav-item active' : 'nav-item'}><Icon size={18}/><span>{item.label}</span></Link>; })}</nav>
      <div className="sidebar-bottom"><div className="sidebar-rule"/><div className="nav-label">PREFERENCES</div><Link href="/settings" className={`nav-item ${path.startsWith('/settings') ? 'active' : ''}`}><Settings size={18}/><span>Settings</span></Link><a href="mailto:support@soramaplabs.com" className="nav-item"><CircleHelp size={18}/><span>Help &amp; support</span></a>
        <div className="profile-row"><div className="avatar">{(me?.display_name || me?.email || 'S').slice(0,1).toUpperCase()}</div><div className="profile-meta"><strong>{me?.display_name || 'Soni workspace'}</strong><small>{me?.email ?? 'Not signed in'}</small></div><button className="icon-button signout-button" title="Sign out" aria-label="Sign out" onClick={() => void handleSignOut()}><LogOut size={17}/></button></div></div>
    </aside>
    <main className="main-area"><header className="topbar"><button className="icon-button mobile-menu" onClick={() => setMobileOpen(!mobileOpen)} aria-label="Toggle menu"><Menu size={20}/></button><div className="breadcrumbs"><span>Workspace</span><span className="crumb-slash">/</span><strong>{nav.find(n => n.href === path || (n.href !== '/' && path.startsWith(n.href)))?.label ?? 'Settings'}</strong></div><div className="topbar-right"><span className="connection-dot"/><span>Workspace data</span><button className="icon-button" title="Refresh data" onClick={() => void refresh()}><Activity size={17}/></button></div></header>
      {error && <div className="global-error"><strong>API connection issue</strong><span>{error}</span><button onClick={() => void refresh()}>Retry</button></div>}
      {!loading && me && me.memberships.length > 1 && !selectedTenant && <div className="notice warning">Select an organisation to load its security data.</div>}
      {!loading && me && me.memberships.length === 0 && <div className="notice warning">Your account is not a member of an organisation yet.</div>}
      {children}
    </main>
  </div>;
}