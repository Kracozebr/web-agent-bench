'use client';

import { useParams } from 'next/navigation';
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

type ResultState =
  | { kind: 'loading' }
  | { kind: 'ready'; agent: PublicAgent }
  | { kind: 'missing' }
  | { kind: 'restricted' }
  | { kind: 'unavailable' };

export default function PublicAgentPage() {
  const params = useParams<{ agentId: string }>();
  const agentId = params.agentId;
  const [result, setResult] = useState<ResultState>({ kind: 'loading' });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let active = true;
    setResult({ kind: 'loading' });
    void fetch(`/api/public/agents/${encodeURIComponent(agentId)}`, { cache: 'no-store', credentials: 'same-origin' })
      .then(async (response) => {
        if (response.status === 403) {
          if (active) setResult({ kind: 'restricted' });
          return;
        }
        if (response.status === 404) {
          const body = await response.json().catch(() => ({})) as { error?: { code?: string } };
          if (active) setResult({ kind: body.error?.code === 'NOT_FOUND' ? 'missing' : 'unavailable' });
          return;
        }
        if (!response.ok) throw new Error('public_result_unavailable');
        const body = await response.json() as { agent?: PublicAgent };
        if (active) setResult(body.agent ? { kind: 'ready', agent: body.agent } : { kind: 'missing' });
      })
      .catch(() => { if (active) setResult({ kind: 'unavailable' }); });
    return () => { active = false; };
  }, [agentId, attempt]);

  if (result.kind === 'loading') {
    return <section className="page-shell"><p className="fine" role="status">Loading published result…</p></section>;
  }
  if (result.kind === 'missing') {
    return <section className="page-shell"><p className="empty-state" role="status">This published result was not found.</p></section>;
  }
  if (result.kind === 'unavailable') {
    return <section className="page-shell stack-sm"><div className="notice notice-warning" role="status"><p>The public results service is not configured or is temporarily unavailable.</p><button className="button button-small" onClick={() => setAttempt((value) => value + 1)}>Retry</button></div></section>;
  }
  if (result.kind === 'restricted') {
    return <section className="page-shell stack-sm"><div className="notice notice-warning" role="status"><p>Published results cannot be read from this network. Qualification restrictions remain in effect.</p><button className="button button-small" onClick={() => setAttempt((value) => value + 1)}>Retry</button></div></section>;
  }

  const { agent } = result;
  return (
    <section className="page-shell stack-lg" data-testid="public-ranked-agent-detail">
      <header className="page-heading">
        <p className="eyebrow">{agent.benchmarkVersion}</p>
        <h1>{agent.name}</h1>
        <p>{agent.description}</p>
        <p className="fine">{agent.clientMetadata.clientName ?? 'Client unspecified'} · {agent.clientMetadata.modelName ?? 'Model unspecified'}
          {agent.declaredVersion ? ` · ${agent.declaredVersion}` : ''}</p>
      </header>
      <section className="card stack-sm" aria-labelledby="public-ranked-summary-title">
        <h2 id="public-ranked-summary-title">Best verified result</h2>
        <p>Overall exact fraction: <strong>{agent.overall.numerator}/{agent.overall.denominator}</strong></p>
        <dl className="kv-list">
          {(['simple', 'medium', 'hard', 'ultra'] as const).map((tier) => (
            <div key={tier}><dt>{tier}</dt><dd>{agent.tiers[tier].numerator}/{agent.tiers[tier].denominator}</dd></div>
          ))}
        </dl>
      </section>
    </section>
  );
}
