import { api } from "@/lib/api/client";

export async function listDomains() {
  const { data, error } = await api.GET("/api/v1/domains/");
  if (error || !data) throw new Error("Could not load domains");
  return data;
}

export async function addDomain(fqdn: string) {
  const { data, error } = await api.POST("/api/v1/domains/", { body: { fqdn } });
  if (error || !data) throw new Error("Could not add domain");
  return data;
}
