'use client';
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { ApiError, api, setTenantId } from '@/lib/api/client';
import { authApi, type AuthUser } from '@/lib/api/auth';
import type { Domain, Me } from '@/lib/api/types';

export type AuthStatus = 'loading' | 'authenticated' | 'anonymous' | 'error';

type AppContextValue = {
  authStatus: AuthStatus;
  authUser: AuthUser | null; // from the auth session (has_usable_password, ...)
  me: Me | null;
  domains: Domain[];
  selectedDomain: Domain | null;
  selectedTenant: string | null;
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  signOut: () => Promise<void>;
  selectTenant: (id: string) => void;
  selectDomain: (id: string) => void;
};
const AppContext = createContext<AppContextValue | null>(null);

// DRF answers an expired session with 403 "Authentication credentials were not provided."
// A 403 for another reason (not a member of that organisation) must not log the user out.
function isAuthError(e: unknown): boolean {
  if (!(e instanceof ApiError)) return false;
  return e.status === 401 || (e.status === 403 && /credentials|authenticat/i.test(e.message));
}

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [authStatus, setAuthStatus] = useState<AuthStatus>('loading');
  const [authUser, setAuthUser] = useState<AuthUser | null>(null);
  const [me, setMe] = useState<Me | null>(null);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [selectedTenant, setSelectedTenant] = useState<string | null>(null);
  const [selectedDomainId, setSelectedDomainId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // The latest tenant choice, readable inside refresh() without making refresh() change identity.
  const tenantRef = useRef<string | null>(null);

  const clearSession = useCallback(() => {
    tenantRef.current = null;
    setTenantId(null);
    setAuthUser(null);
    setMe(null);
    setDomains([]);
    setSelectedTenant(null);
    setSelectedDomainId(null);
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      await api.csrf();
      const session = await authApi.session();
      if (session.status === 0 || session.status >= 500) {
        throw new Error(session.errors[0]?.message ?? 'Unable to connect to the API.');
      }
      if (!session.authenticated) {
        clearSession();
        setAuthStatus('anonymous');
        return;
      }
      setAuthUser(session.user);

      const profile = await api.me();
      setMe(profile);
      const tenant =
        tenantRef.current && profile.memberships.some((m) => m.tenant_id === tenantRef.current)
          ? tenantRef.current
          : profile.memberships.length === 1
            ? profile.memberships[0].tenant_id
            : null;
      tenantRef.current = tenant;
      setSelectedTenant(tenant);
      setTenantId(tenant);
      setAuthStatus('authenticated');

      if (tenant) {
        const list = await api.domains();
        setDomains(list);
        setSelectedDomainId((current) =>
          current && list.some((d) => d.id === current) ? current : (list[0]?.id ?? null),
        );
      } else {
        setDomains([]);
        setSelectedDomainId(null);
      }
    } catch (e) {
      if (isAuthError(e)) {
        // The session ended (expired, logged out in another tab): back to the sign-in screen.
        clearSession();
        setAuthStatus('anonymous');
      } else {
        setError(e instanceof Error ? e.message : 'Unable to connect to the API.');
        setAuthStatus((current) => (current === 'loading' ? 'error' : current));
      }
    } finally {
      setLoading(false);
    }
  }, [clearSession]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const signOut = useCallback(async () => {
    await authApi.logout(); // 401 "unauthenticated" is the expected answer
    clearSession();
    setError(null);
    setAuthStatus('anonymous');
  }, [clearSession]);

  const selectTenant = useCallback((id: string) => {
    tenantRef.current = id;
    setSelectedTenant(id);
    setTenantId(id);
    setDomains([]);
    setSelectedDomainId(null);
    void (async () => {
      try {
        const list = await api.domains();
        setDomains(list);
        setSelectedDomainId(list[0]?.id ?? null);
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Could not load domains.');
      }
    })();
  }, []);

  const value = useMemo(
    () => ({
      authStatus,
      authUser,
      me,
      domains,
      selectedDomain: domains.find((d) => d.id === selectedDomainId) ?? null,
      selectedTenant,
      loading,
      error,
      refresh,
      signOut,
      selectTenant,
      selectDomain: setSelectedDomainId,
    }),
    [authStatus, authUser, me, domains, selectedDomainId, selectedTenant, loading, error, refresh, signOut, selectTenant],
  );
  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp() {
  const value = useContext(AppContext);
  if (!value) throw new Error('useApp must be used within AppProvider');
  return value;
}