'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';

interface PublicAgent {
  id: string;
  name: string;
  description: string;
  clientMetadata: { clientName: string | null; modelName: string | null };
  declaredVersion: string | null;
  benchmarkVersion: string;
  overall: { numerator: string; denominator: string };
  tiers: Record<'simple' | 'medium' | 'hard' | 'ultra', { numerator: string; denominator: string }>;
}

export default function PublicAgentsPage() {
  const [agents, setAgents] = useState<PublicAgent[] | null>(null);
  const [available, setAvailable] = useState(true);

  useEffect(() => {
    let active = true;
    void fetch('/api/public/agents', { cache: 'no-store', credentials: 'same-origin' })
      .then(async (response) => {
        if (!response.ok) throw new Error('public_results_unavailable');
        const body = await response.json() as { agents?: PublicAgent[] };
        if (active) setAgents(Array.isArray(body.agents) ? body.agents : []);
      })
      .catch(() => {
        if (active) {
          setAvailable(false);
          setAgents([]);
        }
      });
    return () => { active = false; };
  }, []);

  return (
    <section className="page-shell stack-lg">
      <header className="page-heading">
        <p className="eyebrow">Public benchmark results</p>
        <h1>Verified agent results</h1>
        <p>Summaries show the selected benchmark version and exact overall and tier fractions. Owner details and task evidence stay private.</p>
      </header>
      {!available ? <p className="notice notice-warning" role="status">Public results are unavailable from this network or the results service is not ready.</p> : null}
      {agents === null ? <p className="fine" role="status">Loading published results…</p> : null}
      {available && agents?.length === 0 ? <p className="empty-state">No published verified results are available for the current benchmark version.</p> : null}
      <div className="agent-list" data-testid="public-ranked-agents">
        {agents?.map((agent) => (
          <article className="agent-card stack-sm" key={agent.id} data-testid={`public-ranked-agent-${agent.id}`}>
            <div>
              <p className="eyebrow">{agent.benchmarkVersion} · overall {agent.overall.numerator}/{agent.overall.denominator}</p>
              <h2><Link href={`/public/agents/${encodeURIComponent(agent.id)}`}>{agent.name}</Link></h2>
              <p>{agent.description}</p>
            </div>
            <p className="fine">{agent.clientMetadata.clientName ?? 'Client unspecified'} · {agent.clientMetadata.modelName ?? 'Model unspecified'}
              {agent.declaredVersion ? ` · ${agent.declaredVersion}` : ''}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
