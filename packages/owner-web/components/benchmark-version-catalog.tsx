'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { formatPublicUsdc, parsePublicBenchmarkHistory, type PublicBenchmarkHistory } from '@/lib/public-benchmark-history';

type CatalogState = { kind: 'loading' } | { kind: 'unavailable' } | { kind: 'ready'; history: PublicBenchmarkHistory };

export function BenchmarkVersionCatalog() {
  const [state, setState] = useState<CatalogState>({ kind: 'loading' });

  useEffect(() => {
    let active = true;
    void fetch('/api/public/benchmarks', { cache: 'no-store', credentials: 'same-origin' })
      .then(async (response) => {
        if (!response.ok) throw new Error('benchmark_history_unavailable');
        const history = parsePublicBenchmarkHistory(await response.json());
        if (!history) throw new Error('invalid_benchmark_history');
        if (active) setState({ kind: 'ready', history });
      })
      .catch(() => { if (active) setState({ kind: 'unavailable' }); });
    return () => { active = false; };
  }, []);

  if (state.kind === 'loading') return <p className="fine" role="status">Loading validated benchmark versions…</p>;
  if (state.kind === 'unavailable') {
    return <p className="notice notice-warning" role="status">The validated version catalogue is unavailable. No benchmark version or price is shown until the release history can be verified.</p>;
  }

  const { history } = state;
  return (
    <div className="stack-lg" aria-label="Benchmark versions">
      {history.catalogStatus === 'history_only' ? <p className="notice notice-warning">There is no active benchmark version. Completed versions remain available for reference.</p> : null}
      <div className="content-grid benchmark-version-grid">
        {history.versions.map((version) => (
          <Link className="card span-6 benchmark-version-card" href={`/benchmark/${encodeURIComponent(version.slug)}`} key={version.slug}>
            <span className="pill">{version.status === 'current' ? 'Current version' : 'Completed version'}</span>
            <h2>{version.displayName}</h2>
            <p className="fine">A versioned rubric with pinned task weights and prices.</p>
            <dl className="benchmark-version-prices">
              <div><dt>Ranked · 12 tasks · weight 26</dt><dd>{formatPublicUsdc(version.ranked.priceUnits, version.ranked.precision)}</dd></div>
              <div><dt>Training · S1, M1, H1 · weight 6</dt><dd>{formatPublicUsdc(version.training.priceUnits, version.training.precision)}</dd></div>
            </dl>
            <span className="benchmark-version-action">View version description →</span>
          </Link>
        ))}
      </div>
      {history.versions.length === 1 && history.catalogStatus === 'active'
        ? <p className="fine">Completed versions will appear here after they are retired.</p>
        : null}
    </div>
  );
}
