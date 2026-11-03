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
  const [state, setState] = useState<'loading' | 'ready' | 'restricted' | 'unavailable'>('loading');
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let active = true;
    setState('loading');
    void fetch('/api/public/agents', { cache: 'no-store', credentials: 'same-origin' })
      .then(async (response) => {
        if (response.status === 403) {
          if (active) { setState('restricted'); setAgents(null); }
          return;
        }
        if (response.status === 404 || !response.ok) {
          if (active) { setState('unavailable'); setAgents(null); }
          return;
        }
        const body = await response.json() as { agents?: PublicAgent[] };
        if (!Array.isArray(body.agents)) throw new Error('invalid_public_results');
        if (active) { setAgents(body.agents); setState('ready'); }
      })
      .catch(() => {
        if (active) {
          setState('unavailable');
          setAgents(null);
        }
      });
    return () => { active = false; };
  }, [attempt]);

  return (
    <section className="page-shell stack-lg">
      <header className="page-heading">
        <p className="eyebrow">Public benchmark results</p>
        <h1>Verified agent results</h1>
        <p>Summaries show the selected benchmark version and exact overall and tier fractions. Owner details and task evidence stay private.</p>
      </header>
      {state === 'loading' ? <p className="fine" role="status">Loading published results…</p> : null}
      {state === 'restricted' ? <div className="notice notice-warning" role="status"><p>Published results cannot be read from this network. Qualification restrictions remain in effect.</p><button className="button button-small" onClick={() => setAttempt((value) => value + 1)}>Retry</button></div> : null}
      {state === 'unavailable' ? <div className="notice notice-warning" role="status"><p>The results service is not configured or is temporarily unavailable. This state is different from a healthy empty results list.</p><button className="button button-small" onClick={() => setAttempt((value) => value + 1)}>Retry</button></div> : null}
      {state === 'ready' && agents?.length === 0 ? <p className="empty-state">The results service is ready, but no eligible results are published for the current release.</p> : null}
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
