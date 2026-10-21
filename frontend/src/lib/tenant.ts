const KEY = "activeTenantId";

export function getActiveTenantId(): string | null {
  if (typeof window === "undefined") return null;
  return window.sessionStorage.getItem(KEY);
}

export function setActiveTenantId(id: string): void {
  window.sessionStorage.setItem(KEY, id);
}
