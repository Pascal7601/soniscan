"use client";

import { useEffect, useState } from "react";
import { listDomains } from "./api";

type Domains = Awaited<ReturnType<typeof listDomains>>;

export function DomainTable() {
  const [domains, setDomains] = useState<Domains | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    listDomains().then(setDomains).catch(() => setFailed(true));
  }, []);

  if (failed) return <p role="alert">We couldn&apos;t load your domains. Please try again.</p>;
  if (!domains) return <p>Loading…</p>;
  if (domains.length === 0) return <p>No domains yet. Add one to run your first scan.</p>;

  return (
    <table>
      <thead>
        <tr><th>Domain</th><th>Status</th></tr>
      </thead>
      <tbody>
        {domains.map((d) => (
          <tr key={d.id}><td>{d.fqdn}</td><td>{d.status}</td></tr>
        ))}
      </tbody>
    </table>
  );
}
