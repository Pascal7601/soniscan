'use client';
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { api, setTenantId } from '@/lib/api/client';
import type { Domain, Me } from '@/lib/api/types';

type AppContextValue = { me: Me | null; domains: Domain[]; selectedDomain: Domain | null; selectedTenant: string | null; loading: boolean; error: string | null; refresh: () => Promise<void>; selectTenant: (id: string) => void; selectDomain: (id: string) => void };
const AppContext = createContext<AppContextValue | null>(null);
export function AppProvider({ children }: { children: React.ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [selectedTenant, setSelectedTenant] = useState<string | null>(null);
  const [selectedDomainId, setSelectedDomainId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      await api.csrf();
      const profile = await api.me();
      setMe(profile);
      const tenant = selectedTenant ?? (profile.memberships.length === 1 ? profile.memberships[0].tenant_id : null);
      setSelectedTenant(tenant); setTenantId(tenant);
      if (tenant) {
        const list = await api.domains(); setDomains(list);
        setSelectedDomainId(current => current && list.some(d => d.id === current) ? current : list[0]?.id ?? null);
      } else { setDomains([]); setSelectedDomainId(null); }
    } catch (e) { setError(e instanceof Error ? e.message : 'Unable to connect to the API.'); }
    finally { setLoading(false); }
  }, [selectedTenant]);

  useEffect(() => { void refresh(); }, [refresh]);

  const selectTenant = useCallback((id: string) => {
    setSelectedTenant(id); setTenantId(id); setDomains([]); setSelectedDomainId(null);
    void (async () => {
      try { const list = await api.domains(); setDomains(list); setSelectedDomainId(list[0]?.id ?? null); }
      catch (e) { setError(e instanceof Error ? e.message : 'Could not load domains.'); }
    })();
  }, []);

  const value = useMemo(() => ({
    me, domains, selectedDomain: domains.find(d => d.id === selectedDomainId) ?? null,
    selectedTenant, loading, error, refresh, selectTenant, selectDomain: setSelectedDomainId,
  }), [me, domains, selectedDomainId, selectedTenant, loading, error, refresh, selectTenant]);
  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}
export function useApp() { const value = useContext(AppContext); if (!value) throw new Error('useApp must be used within AppProvider'); return value; }
